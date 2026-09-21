package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-freya/freya/services/warden/internal/audit"
	"github.com/go-freya/freya/services/warden/internal/authz"
	"github.com/go-freya/freya/services/warden/internal/folders"
	"github.com/go-freya/freya/services/warden/internal/memstore"
	"github.com/go-freya/freya/services/warden/internal/secrets"
	"github.com/go-freya/freya/services/warden/internal/vault"
)

const (
	tA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	tB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
	uA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"
	uB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c88"
	pw = "WARDEN-MARKER-PW-http"
)

type story struct {
	s     *Server
	d     StoryDeps
	sg    signer
	ms    *memstore.Store
	vt    *vault.Fake
	aw    *audit.Writer
	alice string
	bob   string
	other string
}

func newStory(t *testing.T) *story {
	t.Helper()
	s, sg := newTestServer(t)
	ms := memstore.New()
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	az := authz.New(ms, aw)
	vt := vault.NewFake()
	sec := secrets.New(ms, vt, az, aw)
	fo := folders.New(ms, az, aw, sec)
	deps := StoryDeps{Folders: fo, Secrets: sec, Authz: az}
	s.RegisterFolders(deps)
	s.RegisterSecrets(deps)
	s.RegisterGrants(deps)
	return &story{s: s, d: deps, sg: sg, ms: ms, vt: vt, aw: aw, alice: sg.mint(uA, tA, []string{"member"}), bob: sg.mint(uB, tA, []string{"ops"}), other: sg.mint(uB, tB, nil)}
}

func (st *story) call(tok, method, path, body string) (int, map[string]any) {
	w := do(st.s, method, path, body, auth(tok))
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (st *story) raw(tok, method, path, body string) string {
	return do(st.s, method, path, body, auth(tok)).Body.String()
}

func TestFolderRoutes(t *testing.T) {
	st := newStory(t)
	// Schema refusals and creation.
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/folders", `{"name":"a/b"}`); code != 400 || out["reason"] != "validation_failed" {
		t.Fatalf("%d %v", code, out)
	}
	code, infra := st.call(st.alice, "POST", "/api/warden/v1/folders", `{"name":"Infra"}`)
	if code != 201 || infra["path"] != "/Infra" || infra["permissions"].(map[string]any)["delete"] != true {
		t.Fatalf("%d %v", code, infra)
	}
	infraID := infra["id"].(string)
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/folders", `{"name":"infra"}`); code != 409 || out["reason"] != "conflict" {
		t.Fatalf("sibling: %d %v", code, out)
	}
	// Permission and tenant boundaries.
	if code, out := st.call(st.bob, "POST", "/api/warden/v1/folders", `{"parent_id":"`+infraID+`","name":"X"}`); code != 403 || out["reason"] != "forbidden" {
		t.Fatalf("bob: %d %v", code, out)
	}
	if code, out := st.call(st.other, "GET", "/api/warden/v1/folders/"+infraID, ""); code != 404 || out["reason"] != "not_found" {
		t.Fatalf("other: %d %v", code, out)
	}
	if code, _ := st.call("", "GET", "/api/warden/v1/folders", ""); code != 401 {
		t.Fatal("anonymous")
	}
	code, db := st.call(st.alice, "POST", "/api/warden/v1/folders", `{"parent_id":"`+infraID+`","name":"Databases"}`)
	if code != 201 {
		t.Fatalf("%d %v", code, db)
	}
	dbID := db["id"].(string)
	// Listing, get, tree.
	if code, out := st.call(st.alice, "GET", "/api/warden/v1/folders?parent_id="+infraID, ""); code != 200 || len(out["items"].([]any)) != 1 {
		t.Fatalf("children: %d %v", code, out)
	}
	if code, out := st.call(st.alice, "GET", "/api/warden/v1/folders", ""); code != 200 || len(out["items"].([]any)) != 1 {
		t.Fatalf("roots: %d %v", code, out)
	}
	if code, out := st.call(st.alice, "GET", "/api/warden/v1/folders/tree", ""); code != 200 || len(out["items"].([]any)) != 1 {
		t.Fatalf("tree: %d %v", code, out)
	}
	if code, out := st.call(st.alice, "GET", "/api/warden/v1/folders/"+dbID, ""); code != 200 || out["path"] != "/Infra/Databases" {
		t.Fatalf("get: %d %v", code, out)
	}
	// Rename, move (cycle 409), delete (not empty 409, recursive 204).
	if code, out := st.call(st.alice, "PUT", "/api/warden/v1/folders/"+infraID, `{"name":"Platform"}`); code != 200 || out["path"] != "/Platform" {
		t.Fatalf("rename: %d %v", code, out)
	}
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/folders/"+infraID+"/move", `{"parent_id":"`+dbID+`"}`); code != 409 {
		t.Fatalf("cycle: %d %v", code, out)
	}
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/folders/"+dbID+"/move", `{"parent_id":null}`); code != 200 || out["path"] != "/Databases" {
		t.Fatalf("move: %d %v", code, out)
	}
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/folders/"+dbID+"/move", `{"parent_id":"`+infraID+`"}`); code != 200 {
		t.Fatalf("move back: %d %v", code, out)
	}
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/folders/"+infraID+"/remove", ""); code != 409 {
		t.Fatalf("not empty: %d %v", code, out)
	}
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/folders/"+infraID+"/remove", `{"recursive":true}`); code != 204 {
		t.Fatalf("recursive: %d %v", code, out)
	}
	if code, _ := st.call(st.alice, "GET", "/api/warden/v1/folders/"+dbID, ""); code != 404 {
		t.Fatal("subtree survived")
	}
	// Malformed bodies.
	for _, c := range []struct{ m, p, b string }{{"POST", "/api/warden/v1/folders", `{"name":`}, {"PUT", "/api/warden/v1/folders/" + infraID, `{"name":`}, {"POST", "/api/warden/v1/folders/" + infraID + "/move", `{`}, {"POST", "/api/warden/v1/folders/" + infraID + "/remove", `{`}} {
		if code, _ := st.call(st.alice, c.m, c.p, c.b); code != 400 {
			t.Fatalf("%s %s: %d", c.m, c.p, code)
		}
	}
}

func TestSecretRoutes(t *testing.T) {
	st := newStory(t)
	_, infra := st.call(st.alice, "POST", "/api/warden/v1/folders", `{"name":"Infra"}`)
	infraID := infra["id"].(string)
	create := `{"folder_id":"` + infraID + `","name":"prod-db","username":"root","host_url":"https://db.example.org","password":"` + pw + `","totp":"JBSWY3DPEHPK3PXP","metadata":{"env":"prod"}}`
	// Schema refusals.
	for _, body := range []string{`{"name":"x"}`, `{"name":"","password":"p"}`, `{"name":"x","password":"p","extra":1}`, `{"name":"x","password":"` + strings.Repeat("p", 5000) + `"}`} {
		if code, out := st.call(st.alice, "POST", "/api/warden/v1/secrets", body); code != 400 {
			t.Fatalf("%s: %d %v", body, code, out)
		}
	}
	if code, out := st.call(st.bob, "POST", "/api/warden/v1/secrets", create); code != 403 {
		t.Fatalf("bob create: %d %v", code, out)
	}
	code, sec := st.call(st.alice, "POST", "/api/warden/v1/secrets", create)
	if code != 201 || sec["current_version"] != float64(1) || sec["has_totp"] != true || sec["folder_path"] != "/Infra" {
		t.Fatalf("%d %v", code, sec)
	}
	id := sec["id"].(string)
	// No material in any secret representation.
	for _, p := range []string{"/api/warden/v1/secrets/" + id, "/api/warden/v1/secrets?folder_id=" + infraID, "/api/warden/v1/secrets/search?q=prod", "/api/warden/v1/secrets/" + id + "/versions"} {
		body := st.raw(st.alice, "GET", p, "")
		if strings.Contains(body, "MARKER") || strings.Contains(body, "JBSWY3DP") || strings.Contains(body, `"password"`) || strings.Contains(body, `"totp"`) {
			t.Fatalf("%s leaks: %s", p, body)
		}
	}
	// Reveal is audited with the version; a specific version too.
	if code, out := st.call(st.alice, "GET", "/api/warden/v1/secrets/"+id+"/password", ""); code != 200 || out["password"] != pw || out["version"] != float64(1) {
		t.Fatalf("reveal: %d %v", code, out)
	}
	if code, _ := st.call(st.bob, "GET", "/api/warden/v1/secrets/"+id+"/password", ""); code != 403 {
		t.Fatal("bob reveal")
	}
	if code, _ := st.call(st.other, "GET", "/api/warden/v1/secrets/"+id+"/password", ""); code != 404 {
		t.Fatal("other reveal")
	}
	if code, _ := st.call(st.alice, "GET", "/api/warden/v1/secrets/"+id+"/password?version=0", ""); code != 400 {
		t.Fatal("version minimum")
	}
	st.aw.Flush()
	if n := len(st.ms.AuditEvents(tA, "secret_password_read")); n != 1 {
		t.Fatalf("reveal audit %d", n)
	}
	// Password change, versions, restore.
	if code, out := st.call(st.alice, "PUT", "/api/warden/v1/secrets/"+id+"/password", `{"password":"`+pw+`-2","comment":"rotated"}`); code != 200 || out["version"] != float64(2) {
		t.Fatalf("update pw: %d %v", code, out)
	}
	if code, out := st.call(st.alice, "GET", "/api/warden/v1/secrets/"+id+"/versions", ""); code != 200 || len(out["items"].([]any)) != 2 {
		t.Fatalf("versions: %d %v", code, out)
	}
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/secrets/"+id+"/versions/1/restore", `{"comment":"back"}`); code != 200 || out["version"] != float64(3) {
		t.Fatalf("restore: %d %v", code, out)
	}
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/secrets/"+id+"/versions/1/restore", ""); code != 200 || out["version"] != float64(4) {
		t.Fatalf("restore without body: %d %v", code, out)
	}
	if code, _ := st.call(st.alice, "POST", "/api/warden/v1/secrets/"+id+"/versions/99/restore", ""); code != 404 {
		t.Fatal("restore unknown")
	}
	if code, out := st.call(st.alice, "GET", "/api/warden/v1/secrets/"+id+"/password?version=2", ""); code != 200 || out["password"] != pw+"-2" {
		t.Fatalf("reveal v2: %d %v", code, out)
	}
	// Metadata update, move, search and paging.
	if code, out := st.call(st.alice, "PUT", "/api/warden/v1/secrets/"+id, `{"description":"primary"}`); code != 200 || out["description"] != "primary" || out["current_version"] != float64(4) {
		t.Fatalf("update: %d %v", code, out)
	}
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/secrets/"+id+"/move", `{"folder_id":null}`); code != 200 || out["folder_id"] != nil {
		t.Fatalf("move: %d %v", code, out)
	}
	for i := 0; i < 3; i++ {
		if code, _ := st.call(st.alice, "POST", "/api/warden/v1/secrets", `{"name":"root-`+string(rune('a'+i))+`","password":"p"}`); code != 201 {
			t.Fatal("seed")
		}
	}
	code, page := st.call(st.alice, "GET", "/api/warden/v1/secrets?root=true&limit=2", "")
	if code != 200 || len(page["items"].([]any)) != 2 || page["next"] == nil {
		t.Fatalf("page1: %d %v", code, page)
	}
	code, page2 := st.call(st.alice, "GET", "/api/warden/v1/secrets?limit=2&cursor="+page["next"].(string), "")
	if code != 200 || len(page2["items"].([]any)) != 2 || page2["next"] != nil {
		t.Fatalf("page2: %d %v", code, page2)
	}
	if code, out := st.call(st.alice, "GET", "/api/warden/v1/secrets/search?q=root", ""); code != 200 || len(out["items"].([]any)) != 4 { // three root-* names and the username "root"
		t.Fatalf("search: %d %v", code, out)
	}
	if code, _ := st.call(st.alice, "GET", "/api/warden/v1/secrets/search", ""); code != 400 {
		t.Fatal("search requires q")
	}
	if code, out := st.call(st.bob, "GET", "/api/warden/v1/secrets/search?q=root", ""); code != 200 || len(out["items"].([]any)) != 0 {
		t.Fatalf("bob search: %d %v", code, out)
	}
	// TOTP code, set, remove.
	if code, out := st.call(st.alice, "GET", "/api/warden/v1/secrets/"+id+"/totp", ""); code != 200 || len(out["code"].(string)) != 6 {
		t.Fatalf("totp: %d %v", code, out)
	}
	if code, _ := st.call(st.alice, "DELETE", "/api/warden/v1/secrets/"+id+"/totp", ""); code != 204 {
		t.Fatal("remove totp")
	}
	if code, _ := st.call(st.alice, "GET", "/api/warden/v1/secrets/"+id+"/totp", ""); code != 404 {
		t.Fatal("no totp")
	}
	if code, _ := st.call(st.alice, "PUT", "/api/warden/v1/secrets/"+id+"/totp", `{"totp":"not-a-valid-seed!!"}`); code != 400 {
		t.Fatal("bad seed")
	}
	if code, _ := st.call(st.alice, "PUT", "/api/warden/v1/secrets/"+id+"/totp", `{"totp":"JBSWY3DPEHPK3PXP"}`); code != 204 {
		t.Fatal("set totp")
	}
	// Vault down → 503 vault_unavailable; delete needs owner; delete destroys.
	st.vt.Down = true
	if code, out := st.call(st.alice, "GET", "/api/warden/v1/secrets/"+id+"/password", ""); code != 503 || out["reason"] != "vault_unavailable" {
		t.Fatalf("vault down: %d %v", code, out)
	}
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/secrets", `{"name":"x","password":"p"}`); code != 503 || out["reason"] != "vault_unavailable" {
		t.Fatalf("create down: %d %v", code, out)
	}
	st.vt.Down = false
	if code, _ := st.call(st.bob, "POST", "/api/warden/v1/secrets/"+id+"/remove", ""); code != 403 {
		t.Fatal("bob delete")
	}
	if code, _ := st.call(st.alice, "POST", "/api/warden/v1/secrets/"+id+"/remove", ""); code != 204 {
		t.Fatal("delete")
	}
	if code, _ := st.call(st.alice, "GET", "/api/warden/v1/secrets/"+id, ""); code != 404 {
		t.Fatal("deleted visible")
	}
	// Malformed bodies on every JSON route.
	for _, c := range []struct{ m, p string }{{"POST", "/api/warden/v1/secrets"}, {"PUT", "/api/warden/v1/secrets/" + id}, {"POST", "/api/warden/v1/secrets/" + id + "/move"},
		{"PUT", "/api/warden/v1/secrets/" + id + "/password"}, {"POST", "/api/warden/v1/secrets/" + id + "/versions/1/restore"}, {"PUT", "/api/warden/v1/secrets/" + id + "/totp"}} {
		if code, _ := st.call(st.alice, c.m, c.p, `{`); code != 400 {
			t.Fatalf("%s %s: %d", c.m, c.p, code)
		}
	}
	// Audit details never carry material.
	st.aw.Flush()
	for _, r := range st.ms.Audit {
		if strings.Contains(string(r.Details), "MARKER") || strings.Contains(string(r.Details), "JBSWY3DP") {
			t.Fatalf("audit leak: %s", r.Details)
		}
	}
}
