//go:build integration

package integration

import (
	"net/http"
	"testing"
	"time"
)

// TestAccess covers the relation × permission matrix over three folder
// levels, role grants held through an auth group, tenant grants, expiry,
// revocation on the next request, audit of every grant and refusal, and
// cross-tenant invisibility (SC-003, SC-004, SC-009).
func TestAccess(t *testing.T) {
	e := StartPlatform(t)
	owner, tid := e.CreateTenant("acme", "owner@acme.test")
	viewerU := e.Invite(owner, "viewer@acme.test", "member")
	editorU := e.Invite(owner, "editor@acme.test", "member")
	sharerU := e.Invite(owner, "sharer@acme.test", "member")
	nobody := e.Invite(owner, "nobody@acme.test", "member")

	mk := func(parent *string, name string) string {
		body := map[string]any{"name": name}
		if parent != nil {
			body["parent_id"] = *parent
		}
		code, out := owner.JSON(http.MethodPost, "/api/warden/v1/folders", body)
		if code != 201 {
			t.Fatalf("folder %s → %d %v", name, code, out)
		}
		return out["id"].(string)
	}
	infra := mk(nil, "Infra")
	databases := mk(&infra, "Databases")
	prod := mk(&databases, "Prod")
	code, sec := owner.JSON(http.MethodPost, "/api/warden/v1/secrets", map[string]any{"folder_id": prod, "name": "db", "password": "WARDEN-MARKER-PW-access"})
	if code != 201 {
		t.Fatalf("secret → %d %v", code, sec)
	}
	secretID := sec["id"].(string)

	grant := func(s *Session, rtype, rid, stype, sid, rel string, exp *time.Time) (int, map[string]any) {
		body := map[string]any{"resource_type": rtype, "resource_id": rid, "subject_type": stype, "subject_id": sid, "relation": rel}
		if exp != nil {
			body["expires_at"] = exp.UTC().Format(time.RFC3339)
		}
		return s.JSON(http.MethodPost, "/api/warden/v1/grants", body)
	}
	// Viewer on Infra (three levels above the secret), editor on the secret, sharer on Databases.
	for _, g := range []struct {
		u                 *Session
		rtype, rid, stype string
		rel               string
	}{{viewerU, "folder", infra, "user", "viewer"}, {editorU, "secret", secretID, "user", "editor"}, {sharerU, "folder", databases, "user", "sharer"}} {
		if code, out := grant(owner, g.rtype, g.rid, g.stype, g.u.UserID, g.rel, nil); code != 201 {
			t.Fatalf("grant %s → %d %v", g.rel, code, out)
		}
	}
	matrix := []struct {
		name  string
		s     *Session
		read  int
		write int
		del   int
		share int
	}{
		{"owner", owner, 200, 200, 200, 201},
		{"viewer", viewerU, 200, 403, 403, 403},
		{"editor", editorU, 200, 200, 403, 403},
		{"sharer", sharerU, 200, 403, 403, 201},
		{"nobody", nobody, 403, 403, 403, 403},
	}
	for _, m := range matrix {
		t.Run(m.name, func(t *testing.T) {
			if code, _ := m.s.JSON(http.MethodGet, "/api/warden/v1/secrets/"+secretID+"/password", nil); code != m.read {
				t.Fatalf("read → %d want %d", code, m.read)
			}
			if code, _ := m.s.JSON(http.MethodPut, "/api/warden/v1/secrets/"+secretID, map[string]any{"description": m.name}); code != m.write {
				t.Fatalf("write → %d want %d", code, m.write)
			}
			// Share: grant viewer to a bystander user id on the secret (sharer-bound relation).
			if code, _ := grant(m.s, "secret", secretID, "user", "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c00", "viewer", nil); code != m.share {
				t.Fatalf("share → %d want %d", code, m.share)
			}
			if m.del == 403 {
				if code, _ := m.s.JSON(http.MethodPost, "/api/warden/v1/secrets/"+secretID+"/remove", nil); code != 403 {
					t.Fatalf("delete → %d want 403", code)
				}
			}
			// Effective permissions explain the outcome.
			code, eff := m.s.JSON(http.MethodGet, "/api/warden/v1/access/effective?resource_type=secret&resource_id="+secretID, nil)
			if code != 200 {
				t.Fatalf("effective → %d %v", code, eff)
			}
			p := eff["permissions"].(map[string]any)
			if (p["read"] == true) != (m.read == 200) || (p["write"] == true) != (m.write == 200) {
				t.Fatalf("effective mismatch %v", p)
			}
		})
	}
	// A tenant grant (viewer) lets every member read, nobody included.
	if code, out := grant(owner, "secret", secretID, "tenant", "", "viewer", nil); code != 201 {
		t.Fatalf("tenant grant → %d %v", code, out)
	}
	if code, _ := nobody.JSON(http.MethodGet, "/api/warden/v1/secrets/"+secretID, nil); code != 200 {
		t.Fatal("tenant grant not honoured")
	}
	// Remove the tenant grant: the next request is refused (SC-004).
	code, list := owner.JSON(http.MethodGet, "/api/warden/v1/grants?resource_type=secret&resource_id="+secretID, nil)
	if code != 200 {
		t.Fatalf("list → %d %v", code, list)
	}
	for _, it := range list["items"].([]any) {
		g := it.(map[string]any)
		if g["subject_type"] == "tenant" {
			if code, _ := owner.JSON(http.MethodPost, "/api/warden/v1/grants/"+g["id"].(string)+"/revoke", nil); code != 204 {
				t.Fatal("revoke tenant grant")
			}
		}
	}
	if code, _ := nobody.JSON(http.MethodGet, "/api/warden/v1/secrets/"+secretID, nil); code != 403 {
		t.Fatal("revocation not enforced on the next request")
	}
	// A role grant held through an auth group: ops group → role "ops"; member "grouped" joins the group.
	code, role := owner.JSON(http.MethodPost, "/api/v1/admin/roles", map[string]any{"slug": "ops", "display_name": "Ops", "permissions": []string{"secrets:read"}})
	if code != 201 {
		t.Fatalf("role → %d %v", code, role)
	}
	code, group := owner.JSON(http.MethodPost, "/api/v1/admin/groups", map[string]any{"name": "Ops team", "description": ""})
	if code != 201 {
		t.Fatalf("group → %d %v", code, group)
	}
	if code, out := owner.JSON(http.MethodPut, "/api/v1/admin/groups/"+group["id"].(string)+"/roles", map[string]any{"role_ids": []string{role["id"].(string)}}); code != 200 {
		t.Fatalf("group roles → %d %v", code, out)
	}
	grouped := e.Invite(owner, "grouped@acme.test", "member")
	if code, out := owner.JSON(http.MethodPost, "/api/v1/admin/groups/"+group["id"].(string)+"/members", map[string]any{"user_ids": []string{grouped.UserID}}); code/100 != 2 {
		t.Fatalf("membership → %d %v", code, out)
	}
	exp := time.Now().Add(3 * time.Second)
	if code, out := grant(owner, "folder", infra, "role", "ops", "viewer", &exp); code != 201 {
		t.Fatalf("role grant → %d %v", code, out)
	}
	// The token must carry the new effective role: sign in again.
	if code, _ := grouped.SignIn(); code != 200 {
		t.Fatal("re-sign-in")
	}
	grouped.WaitAuthorized("/api/warden/v1/secrets/" + secretID)
	if code, _ := grouped.JSON(http.MethodPut, "/api/warden/v1/secrets/"+secretID, map[string]any{"description": "x"}); code != 403 {
		t.Fatal("viewer through group writes")
	}
	// Expiry: after the grant lapses the member is refused.
	time.Sleep(time.Until(exp) + 500*time.Millisecond)
	if code, _ := grouped.JSON(http.MethodGet, "/api/warden/v1/secrets/"+secretID, nil); code != 403 {
		t.Fatal("expired grant honoured")
	}
	// Cross-tenant: another tenant's owner sees nothing (404), never 403.
	beta, _ := e.CreateTenant("beta", "owner@beta.test")
	if code, out := beta.JSON(http.MethodGet, "/api/warden/v1/secrets/"+secretID, nil); code != 404 || out["reason"] != "not_found" {
		t.Fatalf("cross-tenant → %d %v", code, out)
	}
	if code, _ := grant(beta, "secret", secretID, "tenant", "", "viewer", nil); code != 404 {
		t.Fatal("cross-tenant grant")
	}
	// Every grant and refusal is audited (SC-009).
	if e.AuditCount(tid, "grant_created", "ok") < 5 || e.AuditCount(tid, "grant_revoked", "ok") < 1 || e.AuditCount(tid, "access_refused", "refused") < 10 {
		t.Fatalf("audit: created %d revoked %d refused %d", e.AuditCount(tid, "grant_created", "ok"), e.AuditCount(tid, "grant_revoked", "ok"), e.AuditCount(tid, "access_refused", "refused"))
	}
}
