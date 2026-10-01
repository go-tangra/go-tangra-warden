//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
)

// TestLists covers the list contract on the real database through the
// gateway (go-tangra specs/032-server-side-tables, T119): folder secrets
// visible through folder-inherited and direct grants (role and user,
// unexpired) with exact totals computed in SQL, hidden and deleted secrets
// never counted or returned, search paged by relevance and name, shares
// paged, the audit default 7-day window and 422 refusals.
func TestLists(t *testing.T) {
	e := StartPlatform(t)
	owner, tid := e.CreateTenant("lists", "owner@lists.test")
	viewer := e.Invite(owner, "viewer@lists.test", "member")
	other, _ := e.CreateTenant("elsewhere", "owner@elsewhere.test")

	mkFolder := func(parent, name string) string {
		body := map[string]any{"name": name}
		if parent != "" {
			body["parent_id"] = parent
		}
		code, out := owner.JSON(http.MethodPost, "/api/warden/v1/folders", body)
		if code != 201 {
			t.Fatalf("folder %s → %d %v", name, code, out)
		}
		return out["id"].(string)
	}
	mkSecret := func(folder, name, username string) string {
		body := map[string]any{"name": name, "username": username, "password": "WARDEN-MARKER-PW-lists"}
		if folder != "" {
			body["folder_id"] = folder
		}
		code, out := owner.JSON(http.MethodPost, "/api/warden/v1/secrets", body)
		if code != 201 {
			t.Fatalf("secret %s → %d %v", name, code, out)
		}
		return out["id"].(string)
	}
	grant := func(rtype, rid, stype, sid, rel string, exp *time.Time) {
		body := map[string]any{"resource_type": rtype, "resource_id": rid, "subject_type": stype, "subject_id": sid, "relation": rel}
		if exp != nil {
			body["expires_at"] = exp.UTC().Format(time.RFC3339)
		}
		if code, out := owner.JSON(http.MethodPost, "/api/warden/v1/grants", body); code != 201 && code != 200 {
			t.Fatalf("grant %v → %d %v", body, code, out)
		}
	}
	infra := mkFolder("", "Infra")
	dbs := mkFolder(infra, "Databases")
	private := mkFolder("", "Private")
	var root, priv []string
	for i := 0; i < 8; i++ {
		root = append(root, mkSecret("", fmt.Sprintf("r-%02d", i), ""))
	}
	for i := 0; i < 4; i++ {
		mkSecret(infra, fmt.Sprintf("i-%d", i), "")
	}
	for i := 0; i < 30; i++ {
		mkSecret(dbs, fmt.Sprintf("d-%02d", i), "")
	}
	for i := 0; i < 2; i++ {
		priv = append(priv, mkSecret(private, fmt.Sprintf("p-%d", i), ""))
	}
	mkSecret("", "alpha", "r-user") // matches "r-" by username only
	// The viewer: direct grants on r-01 (viewer) and r-03 (editor), a grant
	// on r-05 that expires, the role "member" on Infra (inherited by
	// Databases) and a direct grant on p-1 in a folder they cannot read.
	grant("secret", root[1], "user", viewer.UserID, "viewer", nil)
	grant("secret", root[3], "user", viewer.UserID, "editor", nil)
	soon := time.Now().Add(3 * time.Second)
	grant("secret", root[5], "user", viewer.UserID, "owner", &soon)
	grant("folder", infra, "role", "member", "viewer", nil)
	grant("secret", priv[1], "user", viewer.UserID, "viewer", nil)
	// r-07 is deleted: never counted again.
	if code, _ := owner.JSON(http.MethodPost, "/api/warden/v1/secrets/"+root[7]+"/remove", nil); code != 204 {
		t.Fatal("delete r-07")
	}
	time.Sleep(time.Until(soon) + time.Second)

	page := func(s *Session, path string, total, pg, size int, sortBy, order string) []string {
		t.Helper()
		code, out := s.JSON(http.MethodGet, path, nil)
		if code != 200 || out["total"] != float64(total) || out["page"] != float64(pg) || out["page_size"] != float64(size) || out["sort"] != sortBy || out["order"] != order {
			t.Fatalf("%s %s → %d %v", s.Email, path, code, out)
		}
		var names []string
		for _, it := range out["items"].([]any) {
			m := it.(map[string]any)
			if _, ok := m["password"]; ok {
				t.Fatalf("%s: material in a list row", path)
			}
			names = append(names, m["name"].(string))
		}
		return names
	}
	t.Run("root and folders", func(t *testing.T) {
		if got := page(owner, "/api/warden/v1/secrets?root=true", 8, 1, 25, "name", "asc"); strings.Join(got, ",") != "alpha,r-00,r-01,r-02,r-03,r-04,r-05,r-06" {
			t.Fatalf("owner root %v", got)
		}
		// Root: only unexpired direct grants, in SQL (count and page agree).
		if got := page(viewer, "/api/warden/v1/secrets", 2, 1, 25, "name", "asc"); strings.Join(got, ",") != "r-01,r-03" {
			t.Fatalf("viewer root %v", got)
		}
		if got := page(viewer, "/api/warden/v1/secrets?page=2&page_size=1", 2, 2, 1, "name", "asc"); strings.Join(got, ",") != "r-03" {
			t.Fatalf("viewer root page 2 %v", got)
		}
		page(viewer, "/api/warden/v1/secrets?page=50&page_size=1", 2, 2, 1, "name", "asc")
		// Folder-inherited role grant: every secret of Infra and Databases,
		// each exactly once over the pages.
		page(viewer, "/api/warden/v1/secrets?folder_id="+infra, 4, 1, 25, "name", "asc")
		seen := map[string]bool{}
		for p := 1; p <= 3; p++ {
			for _, n := range page(viewer, fmt.Sprintf("/api/warden/v1/secrets?folder_id=%s&page=%d&page_size=12&sort=created_at", dbs, p), 30, p, 12, "created_at", "desc") {
				if seen[n] {
					t.Fatalf("%s twice", n)
				}
				seen[n] = true
			}
		}
		if len(seen) != 30 {
			t.Fatalf("seen %d", len(seen))
		}
		got := page(viewer, "/api/warden/v1/secrets?folder_id="+dbs+"&sort=name&order=desc&page_size=3", 30, 1, 3, "name", "desc")
		if strings.Join(got, ",") != "d-29,d-28,d-27" {
			t.Fatalf("desc %v", got)
		}
		if code, _ := viewer.JSON(http.MethodGet, "/api/warden/v1/secrets?folder_id="+private, nil); code != 403 {
			t.Fatal("viewer private folder")
		}
		if code, _ := other.JSON(http.MethodGet, "/api/warden/v1/secrets?folder_id="+infra, nil); code != 404 {
			t.Fatal("other tenant folder")
		}
		page(other, "/api/warden/v1/secrets", 0, 1, 25, "name", "asc")
		// Legacy cursor/limit: old shape plus the same total.
		code, out := viewer.JSON(http.MethodGet, "/api/warden/v1/secrets?folder_id="+dbs+"&limit=20", nil)
		if code != 200 || len(out["items"].([]any)) != 20 || out["next"] == nil || out["total"] != float64(30) || out["page"] != nil {
			t.Fatalf("legacy → %d %v", code, out)
		}
	})
	t.Run("folder counts and refused moves", func(t *testing.T) {
		// The tree carries each folder's live secret count, for the owner and
		// for the viewer reading through the role grant on Infra alike.
		counts := func(s *Session) map[string]float64 {
			t.Helper()
			code, out := s.JSON(http.MethodGet, "/api/warden/v1/folders/tree", nil)
			if code != 200 {
				t.Fatalf("%s tree → %d %v", s.Email, code, out)
			}
			got := map[string]float64{}
			var walk func([]any)
			walk = func(nodes []any) {
				for _, n := range nodes {
					m := n.(map[string]any)
					f := m["folder"].(map[string]any)
					got[f["id"].(string)] = f["secret_count"].(float64)
					walk(m["children"].([]any))
				}
			}
			walk(out["items"].([]any))
			return got
		}
		if c := counts(owner); c[infra] != 4 || c[dbs] != 30 || c[private] != 2 || len(c) != 3 {
			t.Fatalf("owner counts %v", c)
		}
		if c := counts(viewer); c[infra] != 4 || c[dbs] != 30 || len(c) != 2 {
			t.Fatalf("viewer counts %v", c)
		}
		// Moves to a missing folder, another tenant's folder or one the caller
		// cannot read are 404 (never revealed); a read-only one is 403. The
		// secret stays where it was.
		_, foreign := other.JSON(http.MethodPost, "/api/warden/v1/folders", map[string]any{"name": "Foreign"})
		for _, c := range []struct {
			s      *Session
			target string
			want   int
		}{{owner, "0190f7c2-6a3e-7c1a-9b2e-000000000000", 404}, {owner, foreign["id"].(string), 404}, {viewer, private, 404}, {viewer, infra, 403}} {
			code, out := c.s.JSON(http.MethodPost, "/api/warden/v1/secrets/"+root[3]+"/move", map[string]any{"folder_id": c.target})
			if code != c.want {
				t.Fatalf("%s move to %s → %d %v", c.s.Email, c.target, code, out)
			}
		}
		if code, out := owner.JSON(http.MethodPost, "/api/warden/v1/folders/"+dbs+"/move", map[string]any{"parent_id": foreign["id"]}); code != 404 {
			t.Fatalf("folder move to foreign → %d %v", code, out)
		}
		if code, out := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/"+root[3], nil); code != 200 || out["folder_id"] != nil {
			t.Fatalf("refused moves changed the secret → %d %v", code, out)
		}
		page(owner, "/api/warden/v1/secrets?root=true", 8, 1, 25, "name", "asc")
	})
	t.Run("search", func(t *testing.T) {
		got := page(owner, "/api/warden/v1/secrets/search?q=r-", 8, 1, 25, "relevance", "desc")
		if got[0] != "r-00" || got[len(got)-1] != "alpha" {
			t.Fatalf("relevance %v", got)
		}
		if got := page(owner, "/api/warden/v1/secrets/search?q=r-&sort=name&page_size=2", 8, 1, 2, "name", "asc"); got[0] != "alpha" {
			t.Fatalf("by name %v", got)
		}
		page(owner, "/api/warden/v1/secrets/search?q=r-&sort=updated_at", 8, 1, 25, "updated_at", "desc")
		if got := page(viewer, "/api/warden/v1/secrets/search?q=r-", 2, 1, 25, "relevance", "desc"); strings.Join(got, ",") != "r-01,r-03" {
			t.Fatalf("viewer search %v", got)
		}
		if got := page(viewer, "/api/warden/v1/secrets/search?q=p-", 1, 1, 25, "relevance", "desc"); strings.Join(got, ",") != "p-1" {
			t.Fatalf("viewer private search %v", got)
		}
		page(viewer, "/api/warden/v1/secrets/search?q=databases&page_size=10&page=3", 30, 3, 10, "relevance", "desc")
		page(other, "/api/warden/v1/secrets/search?q=r-", 0, 1, 25, "relevance", "desc")
		code, out := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/search?q=d-&limit=10", nil)
		if code != 200 || len(out["items"].([]any)) != 10 || out["next"] == nil || out["total"] != float64(30) {
			t.Fatalf("legacy search → %d %v", code, out)
		}
	})
	t.Run("shares", func(t *testing.T) {
		for i, v := range []int{3600, 600, 7200} {
			if code, out := owner.JSON(http.MethodPost, "/api/warden/v1/secrets/"+root[0]+"/shares", map[string]any{"recipient_email": fmt.Sprintf("r%d@outside.test", i), "validity_seconds": v}); code != 201 {
				t.Fatalf("share → %d %v", code, out)
			}
		}
		code, out := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/"+root[0]+"/shares?page_size=2", nil)
		if code != 200 || out["total"] != float64(3) || len(out["items"].([]any)) != 2 || out["sort"] != "created_at" || out["order"] != "desc" ||
			out["items"].([]any)[0].(map[string]any)["recipient_email"] != "r2@outside.test" {
			t.Fatalf("shares → %d %v", code, out)
		}
		code, out = owner.JSON(http.MethodGet, "/api/warden/v1/secrets/"+root[0]+"/shares?sort=expires_at", nil)
		if code != 200 || out["items"].([]any)[0].(map[string]any)["recipient_email"] != "r1@outside.test" {
			t.Fatalf("shares by expiry → %d %v", code, out)
		}
		if code, _ := viewer.JSON(http.MethodGet, "/api/warden/v1/secrets/"+root[1]+"/shares", nil); code != 403 {
			t.Fatal("viewer shares")
		}
	})
	t.Run("audit window", func(t *testing.T) {
		old := time.Now().Add(-10 * 24 * time.Hour)
		e.Warden.Audit.Flush()
		if err := e.Warden.Store.Tx(context.Background(), store.Scope{TenantID: tid}, func(tx pgx.Tx) error {
			return store.InsertAuditRows(context.Background(), tx, []store.AuditRow{{TS: old, TenantID: tid, EventType: "secret_read", ActorKind: "user", ActorID: owner.UserID, Outcome: "ok"}})
		}); err != nil {
			t.Fatal(err)
		}
		all := e.AuditCount(tid, "", "")
		code, out := owner.JSON(http.MethodGet, "/api/warden/v1/audit?page_size=5", nil)
		if code != 200 || out["total"] != float64(all-1) || len(out["items"].([]any)) != 5 || out["sort"] != "ts" || out["order"] != "desc" {
			t.Fatalf("audit → %d %v (all %d)", code, out, all)
		}
		// Newest first and every event of the window exactly once.
		var ts []string
		total := int(out["total"].(float64))
		for p := 1; (p-1)*50 < total; p++ {
			_, out := owner.JSON(http.MethodGet, fmt.Sprintf("/api/warden/v1/audit?page=%d&page_size=50", p), nil)
			for _, it := range out["items"].([]any) {
				ts = append(ts, it.(map[string]any)["ts"].(string))
			}
		}
		if len(ts) != total {
			t.Fatalf("audit pages %d/%d", len(ts), total)
		}
		for i := 1; i < len(ts); i++ {
			if parseTS(t, ts[i]).After(parseTS(t, ts[i-1])) {
				t.Fatalf("audit order at %d: %s after %s", i, ts[i], ts[i-1])
			}
		}
		from := url.QueryEscape(old.Add(-time.Hour).UTC().Format(time.RFC3339))
		code, out = owner.JSON(http.MethodGet, "/api/warden/v1/audit?from="+from, nil)
		if code != 200 || out["total"] != float64(all) {
			t.Fatalf("audit 30d → %d %v (all %d)", code, out, all)
		}
	})
	t.Run("refusals", func(t *testing.T) {
		for _, c := range []struct{ path, param string }{
			{"/api/warden/v1/secrets?sort=password", "sort"}, {"/api/warden/v1/secrets?sort=username", "sort"},
			{"/api/warden/v1/secrets?page=0", "page"}, {"/api/warden/v1/secrets?page_size=500", "page_size"},
			{"/api/warden/v1/secrets?order=sideways", "order"}, {"/api/warden/v1/secrets?limit=5&page=2", "cursor"},
			{"/api/warden/v1/secrets/search?q=r&sort=totp", "sort"}, {"/api/warden/v1/secrets/" + root[0] + "/shares?sort=token_hash", "sort"},
			{"/api/warden/v1/audit?sort=details", "sort"}, {"/api/warden/v1/audit?cursor=1&page=1", "cursor"},
			{"/api/warden/v1/audit?from=1970-01-01T00:00:00Z", "from"}, {"/api/warden/v1/audit?from=1970-01-01T00:00:00Z&limit=5", "from"},
		} {
			code, out := owner.JSON(http.MethodGet, c.path, nil)
			d, _ := out["detail"].(map[string]any)
			if code != 422 || out["reason"] != "validation_failed" || d["param"] != c.param {
				t.Errorf("%s → %d %v", c.path, code, out)
			}
		}
	})
}

func parseTS(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
