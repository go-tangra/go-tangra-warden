//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestBitwarden validates and imports the 5,000-item fixture through the
// gateway within the budget (SC-006), then exports and re-validates.
func TestBitwarden(t *testing.T) {
	e := StartPlatform(t)
	owner, tid := e.CreateTenant("acme", "owner@acme.test")
	huge, err := os.ReadFile("../testdata/bitwarden/huge.json")
	if err != nil {
		t.Skip("run `go run ./tests/testdata/bitwarden -out tests/testdata/bitwarden` first: " + err.Error())
	}
	code, out := owner.JSON(http.MethodPost, "/api/warden/v1/folders", map[string]any{"name": "Migrated"})
	if code != 201 {
		t.Fatalf("folder → %d %v", code, out)
	}
	target := out["id"].(string)
	started := time.Now()
	resp := owner.Raw(http.MethodPost, "/api/warden/v1/transfer/bitwarden/validate?folder_id="+target, huge, "application/json")
	var rep map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&rep)
	resp.Body.Close()
	if resp.StatusCode != 200 || rep["items"] != float64(5000) || rep["folders"] != float64(51) {
		t.Fatalf("validate → %d %v", resp.StatusCode, rep)
	}
	if d := time.Since(started); d > 10*time.Second {
		t.Fatalf("validate took %s (budget 10 s)", d)
	}
	started = time.Now()
	resp = owner.Raw(http.MethodPost, "/api/warden/v1/transfer/bitwarden/import?folder_id="+target+"&duplicates=rename", huge, "application/json")
	rep = map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&rep)
	resp.Body.Close()
	if resp.StatusCode != 200 || rep["created"] != float64(5000) || rep["failed"] != float64(0) {
		t.Fatalf("import → %d %v", resp.StatusCode, rep)
	}
	if d := time.Since(started); d > 60*time.Second {
		t.Fatalf("import took %s (budget 60 s)", d)
	}
	t.Logf("import of 5000 items took %s", time.Since(started))
	// Export the subtree and re-validate the result elsewhere: no problems.
	resp = owner.Raw(http.MethodPost, "/api/warden/v1/transfer/bitwarden/export?folder_id="+target, nil, "")
	exported, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(exported), "WARDEN-MARKER-PW-bw-0042") {
		t.Fatalf("export → %d", resp.StatusCode)
	}
	code, out = owner.JSON(http.MethodPost, "/api/warden/v1/folders", map[string]any{"name": "Again"})
	again := out["id"].(string)
	resp = owner.Raw(http.MethodPost, "/api/warden/v1/transfer/bitwarden/validate?folder_id="+again, exported, "application/json")
	rep = map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&rep)
	resp.Body.Close()
	if resp.StatusCode != 200 || rep["items"] != float64(5000) || len(rep["problems"].([]any)) != 0 {
		t.Fatalf("re-validate → %d %v", resp.StatusCode, rep)
	}
	if e.AuditCount(tid, "transfer_imported", "ok") != 1 || e.AuditCount(tid, "transfer_exported", "ok") != 1 {
		t.Fatal("transfer audit")
	}
	e.ScanForMaterial(t, []string{"WARDEN-MARKER-PW-"})
}

// TestBackup exports a tenant with material and imports it into an empty
// tenant; folders, secrets, versions and grants come back (SC-007).
func TestBackup(t *testing.T) {
	e := StartPlatform(t)
	owner, tid := e.CreateTenant("acme", "owner@acme.test")
	code, out := owner.JSON(http.MethodPost, "/api/warden/v1/folders", map[string]any{"name": "Infra"})
	infra := out["id"].(string)
	code, out = owner.JSON(http.MethodPost, "/api/warden/v1/secrets", map[string]any{"folder_id": infra, "name": "db", "username": "root", "password": "WARDEN-MARKER-PW-backup-1", "totp": "JBSWY3DPEHPK3PXP"})
	if code != 201 {
		t.Fatalf("secret → %d %v", code, out)
	}
	sid := out["id"].(string)
	if code, _ := owner.JSON(http.MethodPut, "/api/warden/v1/secrets/"+sid+"/password", map[string]any{"password": "WARDEN-MARKER-PW-backup-2", "comment": "rotated"}); code != 200 {
		t.Fatal("rotate")
	}
	if code, _ := owner.JSON(http.MethodPost, "/api/warden/v1/grants", map[string]any{"resource_type": "folder", "resource_id": infra, "subject_type": "role", "subject_id": "member", "relation": "viewer"}); code != 201 {
		t.Fatal("grant")
	}
	resp := owner.Raw(http.MethodPost, "/api/warden/v1/backup/export?include_material=true", nil, "")
	backup, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(backup), "WARDEN-MARKER-PW-backup-1") || !strings.Contains(string(backup), "JBSWY3DPEHPK3PXP") {
		t.Fatalf("backup → %d", resp.StatusCode)
	}
	resp = owner.Raw(http.MethodPost, "/api/warden/v1/backup/export", nil, "")
	plain, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(plain), "WARDEN-MARKER") || strings.Contains(string(plain), "JBSWY3DP") {
		t.Fatal("plain backup carries material")
	}
	if e.AuditCount(tid, "backup_exported", "ok") != 2 {
		t.Fatal("backup audit")
	}
	// Into an empty tenant.
	beta, btid := e.CreateTenant("beta", "owner@beta.test")
	resp = beta.Raw(http.MethodPost, "/api/warden/v1/backup/import", backup, "application/json")
	var rep map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&rep)
	resp.Body.Close()
	if resp.StatusCode != 200 || rep["secrets"].(map[string]any)["created"] != float64(1) || rep["versions"].(map[string]any)["created"] != float64(2) || rep["folders"].(map[string]any)["created"] != float64(1) {
		t.Fatalf("import → %d %v", resp.StatusCode, rep)
	}
	code, list := beta.JSON(http.MethodGet, "/api/warden/v1/secrets/search?q=db", nil)
	items := list["items"].([]any)
	if code != 200 || len(items) != 1 {
		t.Fatalf("imported secret → %d %v", code, list)
	}
	got := items[0].(map[string]any)
	if got["folder_path"] != "/Infra" || got["current_version"] != float64(2) || got["has_totp"] != true {
		t.Fatalf("%v", got)
	}
	nid := got["id"].(string)
	if code, out := beta.JSON(http.MethodGet, "/api/warden/v1/secrets/"+nid+"/password", nil); code != 200 || out["password"] != "WARDEN-MARKER-PW-backup-2" {
		t.Fatalf("material → %d %v", code, out)
	}
	if code, out := beta.JSON(http.MethodGet, "/api/warden/v1/secrets/"+nid+"/password?version=1", nil); code != 200 || out["password"] != "WARDEN-MARKER-PW-backup-1" {
		t.Fatalf("material v1 → %d %v", code, out)
	}
	if code, out := beta.JSON(http.MethodGet, "/api/warden/v1/secrets/"+nid+"/totp", nil); code != 200 || len(out["code"].(string)) != 6 {
		t.Fatalf("totp → %d %v", code, out)
	}
	code, grants := beta.JSON(http.MethodGet, "/api/warden/v1/grants?resource_type=secret&resource_id="+nid, nil)
	roleGrant := false
	for _, g := range grants["items"].([]any) {
		if g.(map[string]any)["subject_type"] == "role" && g.(map[string]any)["subject_id"] == "member" {
			roleGrant = true
		}
	}
	if code != 200 || !roleGrant {
		t.Fatalf("grants → %d %v", code, grants)
	}
	if e.AuditCount(btid, "backup_imported", "ok") != 1 {
		t.Fatal("import audit")
	}
	e.ScanForMaterial(t, []string{"WARDEN-MARKER-PW-", "JBSWY3DPEHPK3PXP"})
}
