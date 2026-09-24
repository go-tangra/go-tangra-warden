package httpapi

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-warden/v4/internal/transfer"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../tests/testdata/bitwarden/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTransferRoutes(t *testing.T) {
	st := newStory(t)
	st.s.RegisterTransfer(TransferDeps{Transfer: transfer.New(st.ms, st.d.Folders, st.d.Secrets, st.d.Authz, st.aw), Vault: st.vt, MaxBytes: 16 << 20})
	_, target := st.call(st.alice, "POST", "/api/warden/v1/folders", `{"name":"Vault"}`)
	targetID := target["id"].(string)
	sample := fixture(t, "sample")
	// Validate writes nothing and reports counts; bob cannot write into alice's folder.
	code, rep := st.call(st.alice, "POST", "/api/warden/v1/transfer/bitwarden/validate?folder_id="+targetID, sample)
	if code != 200 || rep["items"] != float64(20) || rep["folders"] != float64(4) || rep["skipped"] != float64(2) {
		t.Fatalf("validate: %d %v", code, rep)
	}
	if code, out := st.call(st.alice, "GET", "/api/warden/v1/secrets?folder_id="+targetID, ""); code != 200 || len(out["items"].([]any)) != 0 {
		t.Fatalf("validate wrote: %d %v", code, out)
	}
	if code, _ := st.call(st.bob, "POST", "/api/warden/v1/transfer/bitwarden/validate?folder_id="+targetID, sample); code != 403 {
		t.Fatal("bob validate")
	}
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/transfer/bitwarden/validate", `{"encrypted":true,"items":[]}`); code != 400 || out["reason"] != "validation_failed" {
		t.Fatalf("encrypted: %d %v", code, out)
	}
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/transfer/bitwarden/validate", `{"encrypted":false,"items":[`); code != 400 || out["reason"] != "malformed_body" {
		t.Fatalf("malformed: %d %v", code, out)
	}
	// Above the limit → 413 (the edge cap on this route is the per-route 16 MiB; the handler checks Content-Length first).
	huge := `{"encrypted":false,"items":[],"pad":"` + strings.Repeat("x", 16<<20) + `"}`
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/transfer/bitwarden/validate", huge); code != 413 || out["reason"] != "body_too_large" {
		t.Fatalf("huge: %d %v", code, out)
	}
	// Import requires a strategy; imports with rename; a second import skips.
	if code, _ := st.call(st.alice, "POST", "/api/warden/v1/transfer/bitwarden/import?folder_id="+targetID, sample); code != 400 {
		t.Fatal("strategy required")
	}
	code, rep = st.call(st.alice, "POST", "/api/warden/v1/transfer/bitwarden/import?folder_id="+targetID+"&duplicates=rename", sample)
	if code != 200 || rep["created"] != float64(20) {
		t.Fatalf("import: %d %v", code, rep)
	}
	code, rep = st.call(st.alice, "POST", "/api/warden/v1/transfer/bitwarden/import?folder_id="+targetID+"&duplicates=skip", sample)
	if code != 200 || rep["skipped"] != float64(22) {
		t.Fatalf("skip: %d %v", code, rep)
	}
	// Export carries passwords and is audited as a bulk disclosure with the count; bob gets an empty document.
	w := do(st.s, "POST", "/api/warden/v1/transfer/bitwarden/export?folder_id="+targetID, "", auth(st.alice))
	if w.Code != 200 || w.Header().Get("Content-Disposition") != "attachment" || !strings.Contains(w.Body.String(), "WARDEN-MARKER-PW-bw-0001") {
		t.Fatalf("export: %d %s", w.Code, w.Header())
	}
	var doc transfer.Document
	_ = json.Unmarshal(w.Body.Bytes(), &doc)
	if len(doc.Items) != 20 {
		t.Fatalf("export items %d", len(doc.Items))
	}
	st.aw.Flush()
	ev := st.ms.AuditEvents(tA, "transfer_exported")
	if len(ev) != 1 || !strings.Contains(string(ev[0].Details), `"count":20`) {
		t.Fatalf("export audit %+v", ev)
	}
	if code, _ := st.call(st.bob, "POST", "/api/warden/v1/transfer/bitwarden/export?folder_id="+targetID, ""); code != 403 {
		t.Fatal("bob export")
	}
	// Backup with material, then import it into another tenant's session (other) and read a secret back.
	w = do(st.s, "POST", "/api/warden/v1/backup/export?include_material=true", "", auth(st.alice))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "WARDEN-MARKER-PW-bw-0001") {
		t.Fatalf("backup: %d", w.Code)
	}
	backup := w.Body.String()
	w = do(st.s, "POST", "/api/warden/v1/backup/export", "", auth(st.alice))
	if w.Code != 200 || strings.Contains(w.Body.String(), "WARDEN-MARKER") {
		t.Fatalf("plain backup leaks: %d", w.Code)
	}
	code, brep := st.call(st.other, "POST", "/api/warden/v1/backup/import", backup)
	if code != 200 || brep["secrets"].(map[string]any)["created"] != float64(20) || brep["folders"].(map[string]any)["created"] != float64(5) { // Vault + Imported + 3 teams
		t.Fatalf("backup import: %d %v", code, brep)
	}
	code, list := st.call(st.other, "GET", "/api/warden/v1/secrets/search?q=Service", "")
	if code != 200 || len(list["items"].([]any)) == 0 {
		t.Fatalf("imported secrets: %d %v", code, list)
	}
	if code, out := st.call(st.other, "POST", "/api/warden/v1/backup/import", `{"module":"warden","schema_version":9}`); code != 400 || out["reason"] != "validation_failed" {
		t.Fatalf("bad schema: %d %v", code, out)
	}
	if code, _ := st.call(st.other, "POST", "/api/warden/v1/backup/import", `{`); code != 400 {
		t.Fatal("malformed backup")
	}
	st.aw.Flush()
	if n := len(st.ms.AuditEvents(tA, "backup_exported")); n != 2 {
		t.Fatalf("backup audit %d", n)
	}
	if n := len(st.ms.AuditEvents(tB, "backup_imported")); n != 1 {
		t.Fatalf("backup import audit %d", n)
	}
	// Vault down → 503 on export.
	st.vt.Down = true
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/backup/export?include_material=true", ""); code != 503 || out["reason"] != "vault_unavailable" {
		t.Fatalf("vault down: %d %v", code, out)
	}
	st.vt.Down = false
	for _, r := range st.ms.Audit {
		if strings.Contains(string(r.Details), "MARKER") {
			t.Fatal("audit leak")
		}
	}
}
