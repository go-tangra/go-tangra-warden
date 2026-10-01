package httpapi

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"

	"github.com/go-tangra/go-tangra-warden/v4/internal/cache"
	"github.com/go-tangra/go-tangra-warden/v4/internal/generator"
	"github.com/go-tangra/go-tangra-warden/v4/internal/share"
	"github.com/go-tangra/go-tangra-warden/v4/internal/stats"
	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
	"github.com/go-tangra/go-tangra-warden/v4/internal/vault"
)

// List contract (go-tangra specs/032-server-side-tables) on the warden
// tables: exact totals under folder-inherited and direct grants, hidden
// secrets never counted or returned, search by relevance/name, shares, the
// audit window, the legacy cursor shape and 422 refusals naming the
// parameter only.

func (st *story) mustCreate(t *testing.T, tok, path, body string) string {
	t.Helper()
	code, out := st.call(tok, "POST", path, body)
	if code != 201 {
		t.Fatalf("%s %s: %d %v", path, body, code, out)
	}
	return out["id"].(string)
}

func (st *story) grant(t *testing.T, typ, id, subjType, subj, rel string) {
	t.Helper()
	body := fmt.Sprintf(`{"resource_type":%q,"resource_id":%q,"subject_type":%q,"subject_id":%q,"relation":%q}`, typ, id, subjType, subj, rel)
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/grants", body); code != 200 && code != 201 {
		t.Fatalf("grant %s: %d %v", body, code, out)
	}
}

func names(out map[string]any) []string {
	var n []string
	for _, it := range out["items"].([]any) {
		n = append(n, it.(map[string]any)["name"].(string))
	}
	return n
}

func expectPage(t *testing.T, what string, code int, out map[string]any, total, page, size int, sort, order string) {
	t.Helper()
	if code != 200 || out["total"] != float64(total) || out["page"] != float64(page) || out["page_size"] != float64(size) || out["sort"] != sort || out["order"] != order {
		t.Fatalf("%s: %d %v", what, code, out)
	}
}

type vaultFixture struct {
	root, infra, dbs, private []string // secret ids
	infraID, dbsID, privID    string
}

// seedVault: alice owns 7 root secrets, Infra (4) > Databases (3) and
// Private (2). Bob holds direct viewer grants on r-01 and r-03, an expired
// one on r-05, the role "ops" viewer on Infra (inherited by Databases) and a
// direct grant on p-1 inside Private, whose folder he cannot read.
func seedVault(t *testing.T, st *story) vaultFixture {
	t.Helper()
	var fx vaultFixture
	fx.infraID = st.mustCreate(t, st.alice, "/api/warden/v1/folders", `{"name":"Infra"}`)
	fx.dbsID = st.mustCreate(t, st.alice, "/api/warden/v1/folders", `{"parent_id":"`+fx.infraID+`","name":"Databases"}`)
	fx.privID = st.mustCreate(t, st.alice, "/api/warden/v1/folders", `{"name":"Private"}`)
	for i := 0; i < 7; i++ {
		fx.root = append(fx.root, st.mustCreate(t, st.alice, "/api/warden/v1/secrets", fmt.Sprintf(`{"name":"r-%02d","password":"%s"}`, i, pw)))
	}
	for i := 0; i < 4; i++ {
		fx.infra = append(fx.infra, st.mustCreate(t, st.alice, "/api/warden/v1/secrets", fmt.Sprintf(`{"folder_id":%q,"name":"i-%d","password":"%s"}`, fx.infraID, i, pw)))
	}
	for i := 0; i < 3; i++ {
		fx.dbs = append(fx.dbs, st.mustCreate(t, st.alice, "/api/warden/v1/secrets", fmt.Sprintf(`{"folder_id":%q,"name":"d-%d","password":"%s"}`, fx.dbsID, i, pw)))
	}
	for i := 0; i < 2; i++ {
		fx.private = append(fx.private, st.mustCreate(t, st.alice, "/api/warden/v1/secrets", fmt.Sprintf(`{"folder_id":%q,"name":"p-%d","password":"%s"}`, fx.privID, i, pw)))
	}
	st.grant(t, "secret", fx.root[1], "user", uB, "viewer")
	st.grant(t, "secret", fx.root[3], "user", uB, "editor")
	st.grant(t, "folder", fx.infraID, "role", "ops", "viewer")
	st.grant(t, "secret", fx.private[1], "user", uB, "viewer")
	past := time.Now().Add(-time.Minute)
	if _, err := st.ms.UpsertGrant(context.Background(), store.Grant{ID: store.NewID(), TenantID: tA, ResourceType: "secret", ResourceID: fx.root[5], SubjectType: "user", SubjectID: uB, Relation: "owner", ExpiresAt: &past}); err != nil {
		t.Fatal(err)
	}
	return fx
}

func TestSecretListsVisibilityAndTotals(t *testing.T) {
	st := newStory(t)
	fx := seedVault(t, st)

	// Alice: every root secret, name order by default.
	code, out := st.call(st.alice, "GET", "/api/warden/v1/secrets", "")
	expectPage(t, "alice root", code, out, 7, 1, 25, "name", "asc")
	if got := strings.Join(names(out), ","); got != "r-00,r-01,r-02,r-03,r-04,r-05,r-06" {
		t.Fatalf("alice root order %s", got)
	}
	// Bob at the root: only the two direct grants (the expired one and the
	// secrets inside folders are neither counted nor returned).
	code, out = st.call(st.bob, "GET", "/api/warden/v1/secrets", "")
	expectPage(t, "bob root", code, out, 2, 1, 25, "name", "asc")
	if got := strings.Join(names(out), ","); got != "r-01,r-03" {
		t.Fatalf("bob root %s", got)
	}
	perm := func(out map[string]any, i int) map[string]any {
		return out["items"].([]any)[i].(map[string]any)["permissions"].(map[string]any)
	}
	if p := perm(out, 1); p["read"] != true || p["write"] != true || p["delete"] != false {
		t.Fatalf("bob r-03 permissions %v", p)
	}
	// Paging the visible set: page 2 of size 1 is r-03; beyond the end clamps.
	code, out = st.call(st.bob, "GET", "/api/warden/v1/secrets?page=2&page_size=1", "")
	expectPage(t, "bob page 2", code, out, 2, 2, 1, "name", "asc")
	if got := strings.Join(names(out), ","); got != "r-03" {
		t.Fatalf("bob page 2 %s", got)
	}
	code, out = st.call(st.bob, "GET", "/api/warden/v1/secrets?page=99&page_size=1&sort=name&order=desc", "")
	expectPage(t, "bob clamp", code, out, 2, 2, 1, "name", "desc")
	if got := strings.Join(names(out), ","); got != "r-01" {
		t.Fatalf("bob clamp %s", got)
	}
	// Folder-inherited grants: Infra and its subfolder Databases, every secret.
	code, out = st.call(st.bob, "GET", "/api/warden/v1/secrets?folder_id="+fx.infraID, "")
	expectPage(t, "bob infra", code, out, 4, 1, 25, "name", "asc")
	code, out = st.call(st.bob, "GET", "/api/warden/v1/secrets?folder_id="+fx.dbsID+"&page_size=2", "")
	expectPage(t, "bob databases", code, out, 3, 1, 2, "name", "asc")
	if p := perm(out, 0); p["read"] != true || p["write"] != false {
		t.Fatalf("bob inherited permissions %v", p)
	}
	// A folder bob cannot read stays refused although he holds a grant on a
	// secret inside it.
	if code, out := st.call(st.bob, "GET", "/api/warden/v1/secrets?folder_id="+fx.privID, ""); code != 403 || out["reason"] != "forbidden" {
		t.Fatalf("bob private: %d %v", code, out)
	}
	// Another tenant sees nothing (and nothing is counted).
	code, out = st.call(st.other, "GET", "/api/warden/v1/secrets", "")
	expectPage(t, "other tenant", code, out, 0, 1, 25, "name", "asc")
	if code, _ := st.call(st.other, "GET", "/api/warden/v1/secrets?folder_id="+fx.infraID, ""); code != 404 {
		t.Fatal("other tenant folder")
	}
	// Sort fields: created_at defaults to newest first.
	code, out = st.call(st.alice, "GET", "/api/warden/v1/secrets?sort=created_at&page_size=3", "")
	expectPage(t, "created_at", code, out, 7, 1, 3, "created_at", "desc")
	code, out = st.call(st.alice, "GET", "/api/warden/v1/secrets?sort=updated_at&order=asc&folder_id="+fx.infraID, "")
	expectPage(t, "updated_at", code, out, 4, 1, 25, "updated_at", "asc")
	// Every record exactly once over all pages.
	seen := map[string]bool{}
	for p := 1; p <= 4; p++ {
		_, out := st.call(st.alice, "GET", fmt.Sprintf("/api/warden/v1/secrets?page=%d&page_size=2&sort=created_at", p), "")
		for _, n := range names(out) {
			if seen[n] {
				t.Fatalf("%s twice", n)
			}
			seen[n] = true
		}
	}
	if len(seen) != 7 {
		t.Fatalf("seen %v", seen)
	}
}

func TestSecretSearchPaged(t *testing.T) {
	st := newStory(t)
	fx := seedVault(t, st)
	_ = st.mustCreate(t, st.alice, "/api/warden/v1/secrets", `{"name":"alpha","username":"r-user","password":"`+pw+`"}`)

	// Relevance: name matches first (name order), then other matches.
	code, out := st.call(st.alice, "GET", "/api/warden/v1/secrets/search?q=r-", "")
	expectPage(t, "alice relevance", code, out, 8, 1, 25, "relevance", "desc")
	if n := names(out); n[0] != "r-00" || n[7] != "alpha" {
		t.Fatalf("relevance order %v", n)
	}
	code, out = st.call(st.alice, "GET", "/api/warden/v1/secrets/search?q=r-&sort=name&page_size=3", "")
	expectPage(t, "alice by name", code, out, 8, 1, 3, "name", "asc")
	if n := names(out); n[0] != "alpha" {
		t.Fatalf("name order %v", n)
	}
	code, out = st.call(st.alice, "GET", "/api/warden/v1/secrets/search?q=r-&sort=updated_at", "")
	expectPage(t, "alice by updated", code, out, 8, 1, 25, "updated_at", "desc")
	// Bob: direct root grants only (not the expired one, not alpha).
	code, out = st.call(st.bob, "GET", "/api/warden/v1/secrets/search?q=r-", "")
	expectPage(t, "bob search", code, out, 2, 1, 25, "relevance", "desc")
	// Inside an unreadable folder only the directly granted secret; folder
	// paths match through inheritance.
	code, out = st.call(st.bob, "GET", "/api/warden/v1/secrets/search?q=p-", "")
	expectPage(t, "bob private search", code, out, 1, 1, 25, "relevance", "desc")
	if out["items"].([]any)[0].(map[string]any)["id"] != fx.private[1] {
		t.Fatalf("bob private search %v", out)
	}
	code, out = st.call(st.bob, "GET", "/api/warden/v1/secrets/search?q=databases", "")
	expectPage(t, "bob path search", code, out, 3, 1, 25, "relevance", "desc")
	code, out = st.call(st.other, "GET", "/api/warden/v1/secrets/search?q=r-", "")
	expectPage(t, "other search", code, out, 0, 1, 25, "relevance", "desc")
	// Legacy search: old shape plus total.
	code, out = st.call(st.alice, "GET", "/api/warden/v1/secrets/search?q=r-&limit=5", "")
	if code != 200 || len(out["items"].([]any)) != 5 || out["next"] == nil || out["total"] != float64(8) || out["page"] != nil {
		t.Fatalf("legacy search: %d %v", code, out)
	}
	if code, out := st.call(st.alice, "GET", "/api/warden/v1/secrets/search?q=%20", ""); code != 400 || out["reason"] != "validation_failed" {
		t.Fatalf("blank q: %d %v", code, out)
	}
}

func TestSecretListLegacyShape(t *testing.T) {
	st := newStory(t)
	seedVault(t, st)
	// The total counts what the caller may read (bob: two direct grants).
	code, out := st.call(st.bob, "GET", "/api/warden/v1/secrets?limit=1", "")
	if code != 200 || len(out["items"].([]any)) != 1 || out["total"] != float64(2) || out["page"] != nil {
		t.Fatalf("legacy bob: %d %v", code, out)
	}
	code, out = st.call(st.alice, "GET", "/api/warden/v1/secrets?limit=4", "")
	if code != 200 || len(out["items"].([]any)) != 4 || out["next"] == nil || out["total"] != float64(7) || out["page"] != nil {
		t.Fatalf("legacy page 1: %d %v", code, out)
	}
	code, out = st.call(st.alice, "GET", "/api/warden/v1/secrets?limit=4&cursor="+url.QueryEscape(out["next"].(string)), "")
	if code != 200 || len(out["items"].([]any)) != 3 || out["next"] != nil || out["total"] != float64(7) {
		t.Fatalf("legacy page 2: %d %v", code, out)
	}
	if code, _ := st.call(st.bob, "GET", "/api/warden/v1/secrets?cursor=@@", ""); code != 400 {
		t.Fatal("legacy bad cursor")
	}
}

// TestListParamRefusals: invalid list parameters are 422 validation_failed
// naming the parameter, never echoing the value; no field can sort by
// material (password, seed) or other non-listed columns.
func TestListParamRefusals(t *testing.T) {
	st := newStory(t)
	seedVault(t, st)
	mb := &mailbox{}
	shares := share.New(st.ms, st.vt, st.d.Authz, st.aw, mb, share.Config{PublicOrigin: "https://platform.example.org"})
	st.s.RegisterShares(ShareDeps{Shares: shares, Cache: cache.New(cache.NewMemory()), OpenLimit: 3})
	st.s.RegisterOps(OpsDeps{Generator: generator.New(), Stats: stats.New(st.ms), Audit: st.ms, Version: "test",
		Health: func(context.Context) (string, vault.Health) { return "ok", vault.HealthOK }})
	sid := st.mustCreate(t, st.alice, "/api/warden/v1/secrets", `{"name":"s","password":"`+pw+`"}`)
	bases := []string{"/api/warden/v1/secrets?", "/api/warden/v1/secrets/search?q=r&", "/api/warden/v1/secrets/" + sid + "/shares?", "/api/warden/v1/audit?"}
	cases := []struct{ query, param string }{
		{"page=0", "page"}, {"page=-1", "page"}, {"page=abc", "page"}, {"page=99999999999", "page"},
		{"page_size=0", "page_size"}, {"page_size=201", "page_size"}, {"page_size=x", "page_size"},
		{"sort=password", "sort"}, {"sort=totp", "sort"}, {"sort=seed", "sort"}, {"sort=material", "sort"}, {"sort=vault_path", "sort"},
		{"sort=metadata", "sort"}, {"sort=s.name", "sort"}, {"sort=name%3BDROP", "sort"}, {"order=up", "order"},
		{"cursor=x&page=1", "cursor"}, {"limit=2&sort=name", "cursor"},
	}
	for _, base := range bases {
		for _, c := range cases {
			path := base + c.query
			if (strings.Contains(base, "/audit") || strings.Contains(base, "/shares")) && strings.HasPrefix(c.query, "limit=") {
				continue // no legacy limit there: the unknown sort is refused first (covered above)
			}
			w := do(st.s, "GET", path, "", auth(st.alice))
			body := w.Body.String()
			if w.Code != 422 || !strings.Contains(body, `"reason":"validation_failed"`) || !strings.Contains(body, `"param":"`+c.param+`"`) {
				t.Errorf("%s: %d %s", path, w.Code, body)
			}
			if v := strings.SplitN(c.query, "=", 2)[1]; len(v) > 2 && strings.Contains(body, v) {
				t.Errorf("%s: value echoed in %s", path, body)
			}
		}
	}
	// Sort fields of other lists are refused where they do not belong.
	for _, path := range []string{"/api/warden/v1/secrets?sort=relevance", "/api/warden/v1/secrets?sort=username", "/api/warden/v1/secrets/search?q=r&sort=created_at", "/api/warden/v1/audit?sort=name"} {
		if w := do(st.s, "GET", path, "", auth(st.alice)); w.Code != 422 || !strings.Contains(w.Body.String(), `"param":"sort"`) {
			t.Errorf("%s: %d %s", path, w.Code, w.Body)
		}
	}
	// The Specs never name material or the vault reference.
	for name, spec := range map[string]map[string]string{"secrets": exprs(store.SecretList.Fields), "search": exprs(store.SecretSearchList.Fields), "shares": exprs(store.ShareList.Fields), "audit": exprs(store.AuditList.Fields)} {
		for field, expr := range spec {
			for _, bad := range []string{"password", "totp", "seed", "vault", "material", "token", "metadata", "details"} {
				if strings.Contains(field, bad) || strings.Contains(expr, bad) {
					t.Errorf("%s: field %s (%s) names %s", name, field, expr, bad)
				}
			}
		}
	}
}

func exprs(fields map[string]listquery.Field) map[string]string {
	out := map[string]string{}
	for k, f := range fields {
		out[k] = f.Expr
	}
	return out
}

func TestSharesPaged(t *testing.T) {
	st := newStory(t)
	mb := &mailbox{}
	shares := share.New(st.ms, st.vt, st.d.Authz, st.aw, mb, share.Config{PublicOrigin: "https://platform.example.org"})
	st.s.RegisterShares(ShareDeps{Shares: shares, Cache: cache.New(cache.NewMemory()), OpenLimit: 3})
	sid := st.mustCreate(t, st.alice, "/api/warden/v1/secrets", `{"name":"db","password":"`+pw+`"}`)
	for i, v := range []int{3600, 600, 7200} {
		if code, out := st.call(st.alice, "POST", "/api/warden/v1/secrets/"+sid+"/shares", fmt.Sprintf(`{"recipient_email":"r%d@x.test","validity_seconds":%d}`, i, v)); code != 201 {
			t.Fatalf("share: %d %v", code, out)
		}
		time.Sleep(2 * time.Millisecond)
	}
	code, out := st.call(st.alice, "GET", "/api/warden/v1/secrets/"+sid+"/shares?page_size=2", "")
	expectPage(t, "shares", code, out, 3, 1, 2, "created_at", "desc")
	if out["items"].([]any)[0].(map[string]any)["recipient_email"] != "r2@x.test" {
		t.Fatalf("newest first %v", out)
	}
	code, out = st.call(st.alice, "GET", "/api/warden/v1/secrets/"+sid+"/shares?sort=expires_at", "")
	expectPage(t, "shares by expiry", code, out, 3, 1, 25, "expires_at", "asc")
	if out["items"].([]any)[0].(map[string]any)["recipient_email"] != "r1@x.test" {
		t.Fatalf("soonest first %v", out)
	}
	// Share on the secret is required; other tenants see not_found.
	st.grant(t, "secret", sid, "user", uB, "viewer")
	if code, _ := st.call(st.bob, "GET", "/api/warden/v1/secrets/"+sid+"/shares", ""); code != 403 {
		t.Fatal("bob shares")
	}
	if code, _ := st.call(st.other, "GET", "/api/warden/v1/secrets/"+sid+"/shares", ""); code != 404 {
		t.Fatal("other shares")
	}
	// A sharer sees only the shares they created.
	st.grant(t, "secret", sid, "user", uB, "sharer")
	code, out = st.call(st.bob, "GET", "/api/warden/v1/secrets/"+sid+"/shares", "")
	expectPage(t, "bob shares", code, out, 0, 1, 25, "created_at", "desc")
	st.ms.FailOn("PageSharesOfSecret", errTest)
	if code, _ := st.call(st.alice, "GET", "/api/warden/v1/secrets/"+sid+"/shares", ""); code != 503 {
		t.Fatal("shares db")
	}
}

func TestAuditPagedWindow(t *testing.T) {
	st := newStory(t)
	st.s.RegisterOps(OpsDeps{Generator: generator.New(), Stats: stats.New(st.ms), Audit: st.ms, Version: "test",
		Health: func(context.Context) (string, vault.Health) { return "ok", vault.HealthOK }})
	now := time.Now()
	var rows []store.AuditRow
	for i := 0; i < 5; i++ {
		rows = append(rows, store.AuditRow{TS: now.Add(-time.Duration(i) * time.Hour), TenantID: tA, EventType: "secret_read", ActorKind: "user", ActorID: uA, Outcome: "ok"})
	}
	ts := now.Add(-2 * time.Hour) // equal timestamps: the tie-breaker keeps them apart
	rows = append(rows, store.AuditRow{TS: ts, TenantID: tA, EventType: "secret_created", ActorKind: "user", ActorID: uA, Outcome: "ok"},
		store.AuditRow{TS: now.Add(-10 * 24 * time.Hour), TenantID: tA, EventType: "secret_read", ActorKind: "user", ActorID: uA, Outcome: "ok"},
		store.AuditRow{TS: now, TenantID: tB, EventType: "secret_read", ActorKind: "user", ActorID: uB, Outcome: "ok"})
	if err := st.ms.InsertAuditRows(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	st.aw.Flush()
	base := len(st.ms.AuditEvents(tA, "")) - 7 // events the story itself emitted (none expected)
	// Default: the last 7 days only, newest first, exact total.
	code, out := st.call(st.alice, "GET", "/api/warden/v1/audit?page_size=2", "")
	expectPage(t, "audit", code, out, 6+base, 1, 2, "ts", "desc")
	seen := 0
	for p := 1; p <= 3; p++ {
		_, out := st.call(st.alice, "GET", fmt.Sprintf("/api/warden/v1/audit?page=%d&page_size=2&event_type=secret_read", p), "")
		seen += len(out["items"].([]any))
	}
	if seen != 5 {
		t.Fatalf("seen %d", seen)
	}
	// An explicit from widens the window.
	from := url.QueryEscape(now.Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339))
	code, out = st.call(st.alice, "GET", "/api/warden/v1/audit?from="+from, "")
	expectPage(t, "audit 30d", code, out, 7+base, 1, 50, "ts", "desc")
	// Legacy cursor path: old shape (every event) plus the total of the
	// bounded default window, never an unbounded count.
	code, out = st.call(st.alice, "GET", "/api/warden/v1/audit?cursor=", "")
	if code != 200 || out["total"] != float64(6+base) || len(out["items"].([]any)) != 7+base || out["page"] != nil {
		t.Fatalf("legacy audit: %d %v", code, out)
	}
	if code, out := st.call(st.alice, "GET", "/api/warden/v1/audit?event_type=nope", ""); code != 400 || out["reason"] != "validation_failed" {
		t.Fatalf("bad type: %d %v", code, out)
	}
	// A window wider than 90 days is 422 {param: from} on both paths without
	// echoing the value; exactly 90 days passes (security review F-2).
	rfc := func(t time.Time) string { return url.QueryEscape(t.UTC().Format(time.RFC3339)) }
	end := now.Add(time.Hour)
	wide := "from=" + rfc(end.Add(-91*24*time.Hour)) + "&to=" + rfc(end)
	for _, q := range []string{wide, wide + "&page=1", wide + "&cursor=", "from=1970-01-01T00:00:00Z", "from=1970-01-01T00:00:00Z&limit=5"} {
		code, out := st.call(st.alice, "GET", "/api/warden/v1/audit?"+q, "")
		d, _ := out["detail"].(map[string]any)
		if code != 422 || out["reason"] != "validation_failed" || d["param"] != "from" || strings.Contains(fmt.Sprint(out), "1970") {
			t.Fatalf("span %s: %d %v", q, code, out)
		}
	}
	ok := "from=" + rfc(end.Add(-90*24*time.Hour)) + "&to=" + rfc(end)
	for _, q := range []string{ok, ok + "&cursor="} {
		if code, out := st.call(st.alice, "GET", "/api/warden/v1/audit?"+q, ""); code != 200 {
			t.Fatalf("90 days %s: %d %v", q, code, out)
		}
	}
}
