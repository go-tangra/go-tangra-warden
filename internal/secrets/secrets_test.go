package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-warden/v4/internal/audit"
	"github.com/go-tangra/go-tangra-warden/v4/internal/authz"
	"github.com/go-tangra/go-tangra-warden/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
	"github.com/go-tangra/go-tangra-warden/v4/internal/vault"
)

const (
	tA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	tB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
	uA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"
	uB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c88"
	pw = "WARDEN-MARKER-PW-0001"
)

var (
	alice = authz.Subjects{TenantID: tA, UserID: uA, Roles: []string{"member"}}
	bob   = authz.Subjects{TenantID: tA, UserID: uB, Roles: []string{"ops"}}
	other = authz.Subjects{TenantID: tB, UserID: uB}
)

type fx struct {
	ms    *memstore.Store
	vt    *vault.Fake
	az    *authz.Authz
	aw    *audit.Writer
	svc   *Service
	infra string
	now   time.Time
}

func newFx(t *testing.T) *fx {
	t.Helper()
	ms := memstore.New()
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	az := authz.New(ms, aw)
	vt := vault.NewFake()
	f := &fx{ms: ms, vt: vt, az: az, aw: aw, svc: New(ms, vt, az, aw), now: time.Unix(1_700_000_000, 0)}
	f.svc.SetClock(func() time.Time { return f.now })
	ms.Now = func() time.Time { return f.now }
	az.SetClock(func() time.Time { return f.now })
	f.infra = store.NewID()
	if err := ms.InsertFolder(context.Background(), store.Folder{ID: f.infra, TenantID: tA, Name: "Infra", Path: "/Infra"}); err != nil {
		t.Fatal(err)
	}
	if err := az.GrantOwner(context.Background(), tA, authz.Folder, f.infra, uA); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fx) events(t string) []store.AuditRow { f.aw.Flush(); return f.ms.AuditEvents(tA, t) }

func (f *fx) ok(t string) []store.AuditRow {
	var out []store.AuditRow
	for _, r := range f.events(t) {
		if r.Outcome == "ok" {
			out = append(out, r)
		}
	}
	return out
}

// failNth fails the n-th GetSecret call (authz locates first, the service loads second).
type failNth struct {
	*memstore.Store
	n, calls int
}

func (w *failNth) GetSecret(ctx context.Context, tid, id string) (store.Secret, error) {
	w.calls++
	if w.calls == w.n {
		return store.Secret{}, errors.New("db")
	}
	return w.Store.GetSecret(ctx, tid, id)
}

func (f *fx) create(t *testing.T, name string, folder *string) View {
	t.Helper()
	v, err := f.svc.Create(context.Background(), alice, Input{FolderID: folder, Name: name, Username: "root", HostURL: "https://db.example.org", Description: "d", Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func noMarkers(t *testing.T, f *fx) {
	t.Helper()
	f.aw.Flush()
	for _, r := range f.ms.Audit {
		if strings.Contains(string(r.Details), "WARDEN-MARKER") {
			t.Fatalf("material in audit: %s", r.Details)
		}
	}
	for _, s := range f.ms.Secrets {
		if strings.Contains(s.Name+s.Username+s.HostURL+s.Description+string(s.Metadata), "WARDEN-MARKER") {
			t.Fatal("material in metadata")
		}
	}
	for _, vs := range f.ms.Versions {
		for _, v := range vs {
			if strings.Contains(v.Comment+v.Checksum+v.Source, "WARDEN-MARKER") {
				t.Fatal("material in versions")
			}
		}
	}
}

func TestCreateGetUpdate(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	// Validation.
	for name, in := range map[string]Input{
		"no name":  {Password: pw},
		"long":     {Name: strings.Repeat("x", 201), Password: pw},
		"control":  {Name: "a\x00b", Password: pw},
		"no pw":    {Name: "x"},
		"long pw":  {Name: "x", Password: strings.Repeat("p", 4097)},
		"user":     {Name: "x", Password: pw, Username: strings.Repeat("u", 201)},
		"host":     {Name: "x", Password: pw, HostURL: strings.Repeat("h", 2049)},
		"desc":     {Name: "x", Password: pw, Description: strings.Repeat("d", 2001)},
		"meta":     {Name: "x", Password: pw, Metadata: json.RawMessage(`[1]`)},
		"meta big": {Name: "x", Password: pw, Metadata: json.RawMessage(`{"k":"` + strings.Repeat("v", 17000) + `"}`)},
		"totp":     {Name: "x", Password: pw, TOTP: "nope"},
	} {
		if _, err := f.svc.Create(ctx, alice, in); !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrInvalidTOTP) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Permission on the folder; foreign tenant; root allowed.
	if _, err := f.svc.Create(ctx, bob, Input{FolderID: &f.infra, Name: "x", Password: pw}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bob: %v", err)
	}
	if _, err := f.svc.Create(ctx, other, Input{FolderID: &f.infra, Name: "x", Password: pw}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other: %v", err)
	}
	v, err := f.svc.Create(ctx, alice, Input{FolderID: &f.infra, Name: "prod-db", Username: "root", Metadata: json.RawMessage(`{"env":"prod"}`), Password: pw, TOTP: "JBSWY3DPEHPK3PXP"})
	if err != nil || v.CurrentVersion != 1 || !v.HasTOTP || v.FolderPath != "/Infra" || !v.Permissions.Delete || string(v.Metadata) != `{"env":"prod"}` || v.CreatedBy != uA {
		t.Fatalf("%+v %v", v, err)
	}
	if len(f.ms.Versions[v.ID]) != 1 || f.ms.Versions[v.ID][0].Checksum != Checksum(pw) || f.ms.Versions[v.ID][0].Source != "create" {
		t.Fatalf("%+v", f.ms.Versions[v.ID])
	}
	root := f.create(t, "loose", nil)
	if root.FolderID != nil || string(root.Metadata) != "{}" {
		t.Fatalf("%+v", root)
	}
	// Get: read required, audited; the view never carries material.
	g, err := f.svc.Get(ctx, alice, v.ID)
	if err != nil || g.ID != v.ID {
		t.Fatal(err)
	}
	if _, err := f.svc.Get(ctx, bob, v.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("bob get")
	}
	if _, err := f.svc.Get(ctx, other, v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("other get")
	}
	js, _ := json.Marshal(g)
	if strings.Contains(string(js), "MARKER") || strings.Contains(string(js), "JBSWY3DP") || strings.Contains(string(js), "password") {
		t.Fatalf("material in view: %s", js)
	}
	// Update metadata only; no new version; audited with field names.
	name := "prod-db-2"
	u, err := f.svc.Update(ctx, alice, v.ID, Patch{Name: &name, Metadata: json.RawMessage(`{"env":"staging"}`)})
	if err != nil || u.Name != name || u.CurrentVersion != 1 || u.UpdatedBy != uA {
		t.Fatalf("%+v %v", u, err)
	}
	bad := strings.Repeat("x", 300)
	if _, err := f.svc.Update(ctx, alice, v.ID, Patch{Name: &bad}); !errors.Is(err, ErrInvalid) {
		t.Fatal("update validation")
	}
	empty := ""
	if _, err := f.svc.Update(ctx, alice, v.ID, Patch{Username: &empty, HostURL: &empty, Description: &empty}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Update(ctx, bob, v.ID, Patch{Name: &name}); !errors.Is(err, ErrForbidden) {
		t.Fatal("bob update")
	}
	ev := f.events("secret_updated")
	if len(ev) != 2 || !strings.Contains(string(ev[0].Details), `"name"`) {
		t.Fatalf("%+v", ev)
	}
	if len(f.events("secret_created")) != 2 || len(f.events("secret_totp_set")) != 1 || len(f.events("secret_read")) < 1 {
		t.Fatal("audit counts")
	}
	noMarkers(t, f)
}

func TestVaultFailuresOnCreate(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	// Vault down: nothing is left behind, vault_unavailable audited.
	f.vt.Down = true
	if _, err := f.svc.Create(ctx, alice, Input{Name: "x", Password: pw}); !errors.Is(err, ErrVaultUnavailable) {
		t.Fatalf("%v", err)
	}
	if len(f.ms.Secrets) != 0 || len(f.ms.Grants) != 1 {
		t.Fatalf("rows left: %d secrets", len(f.ms.Secrets))
	}
	if len(f.events("vault_unavailable")) != 1 {
		t.Fatal("audit")
	}
	f.vt.Down = false
	// TOTP write failing after the password committed.
	f.vt.FailAfter = f.vt.Writes() + 2
	if _, err := f.svc.Create(ctx, alice, Input{Name: "x", Password: pw, TOTP: "JBSWY3DPEHPK3PXP"}); !errors.Is(err, ErrVaultUnavailable) {
		t.Fatalf("%v", err)
	}
	f.vt.FailAfter = 0
	// Database failures at each phase.
	f.ms.FailOn("InsertSecret", errors.New("db"))
	if _, err := f.svc.Create(ctx, alice, Input{Name: "x", Password: pw}); err == nil {
		t.Fatal("insert")
	}
	f.ms.FailOn("InsertSecret", nil)
	f.ms.FailOn("InsertVersion", errors.New("db"))
	if _, err := f.svc.Create(ctx, alice, Input{Name: "x", Password: pw}); err == nil {
		t.Fatal("version")
	}
	f.ms.FailOn("InsertVersion", nil)
	// That row is stuck at version 0 for Reconcile; keep going.
	f.ms.FailOn("SetSecretTOTP", errors.New("db"))
	if _, err := f.svc.Create(ctx, alice, Input{Name: "x", Password: pw, TOTP: "JBSWY3DPEHPK3PXP"}); err == nil {
		t.Fatal("set totp")
	}
	f.ms.FailOn("SetSecretTOTP", nil)
	// A bad tenant id cannot build a vault path.
	if _, err := f.svc.Create(ctx, authz.Subjects{TenantID: "not-a-uuid", UserID: uA}, Input{Name: "x", Password: pw}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("path: %v", err)
	}
	noMarkers(t, f)
}

func TestListAndSearch(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	var ids []string
	for _, n := range []string{"Charlie", "alpha", "Bravo"} {
		ids = append(ids, f.create(t, n, &f.infra).ID)
	}
	loose := f.create(t, "loose-db", nil)
	// Alice lists the folder (inherited read) paged 2 + 1.
	p1, err := f.svc.List(ctx, alice, &f.infra, "", 2)
	if err != nil || len(p1.Items) != 2 || p1.Items[0].Name != "alpha" || p1.Next == "" {
		t.Fatalf("%+v %v", p1, err)
	}
	p2, err := f.svc.List(ctx, alice, &f.infra, p1.Next, 2)
	if err != nil || len(p2.Items) != 1 || p2.Items[0].Name != "Charlie" || p2.Next != "" {
		t.Fatalf("%+v %v", p2, err)
	}
	if _, err := f.svc.List(ctx, alice, &f.infra, "!!!", 2); !errors.Is(err, ErrInvalid) {
		t.Fatal("bad cursor")
	}
	if _, err := f.svc.List(ctx, alice, &f.infra, "YQ", 2); !errors.Is(err, ErrInvalid) {
		t.Fatal("cursor without separator")
	}
	if _, err := f.svc.List(ctx, bob, &f.infra, "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatal("bob list")
	}
	// Root: each secret is checked; bob sees nothing, alice her own; default limit.
	r, err := f.svc.List(ctx, alice, nil, "", 1000)
	if err != nil || len(r.Items) != 1 || r.Items[0].ID != loose.ID {
		t.Fatalf("%+v %v", r, err)
	}
	if r, _ := f.svc.List(ctx, bob, nil, "", 10); len(r.Items) != 0 {
		t.Fatal("bob root")
	}
	// Bob gets viewer on one folder secret and one root secret: root listing filters, folder listing needs read on the folder.
	must(t, f.az.GrantOwner(ctx, tA, authz.Secret, loose.ID, uB))
	if _, err := f.ms.UpsertGrant(ctx, store.Grant{ID: store.NewID(), TenantID: tA, ResourceType: "secret", ResourceID: ids[1], SubjectType: "user", SubjectID: uB, Relation: "viewer"}); err != nil {
		t.Fatal(err)
	}
	if r, _ := f.svc.List(ctx, bob, nil, "", 10); len(r.Items) != 1 {
		t.Fatal("bob root after grant")
	}
	// Paging skips unreadable rows: bob viewer on the folder makes all readable; take limit 1 twice.
	if _, err := f.ms.UpsertGrant(ctx, store.Grant{ID: store.NewID(), TenantID: tA, ResourceType: "folder", ResourceID: f.infra, SubjectType: "role", SubjectID: "ops", Relation: "viewer"}); err != nil {
		t.Fatal(err)
	}
	b1, _ := f.svc.List(ctx, bob, &f.infra, "", 1)
	b2, _ := f.svc.List(ctx, bob, &f.infra, b1.Next, 5)
	if len(b1.Items) != 1 || len(b2.Items) != 2 || b2.Next != "" || b2.Items[0].Permissions.Write {
		t.Fatalf("%+v %+v", b1, b2)
	}
	// Search: name, username, host, folder path; readable scope only (creator-owner
	// grants put alice's own root secret in scope); no material.
	s, err := f.svc.Search(ctx, alice, "loose", "", 10)
	if err != nil || len(s.Items) != 1 || s.Items[0].ID != loose.ID {
		t.Fatalf("%+v %v", s, err)
	}
	carol := authz.Subjects{TenantID: tA, UserID: "carol"}
	if s, _ := f.svc.Search(ctx, carol, "loose", "", 10); len(s.Items) != 0 {
		t.Fatal("out of scope secret found")
	}
	s, _ = f.svc.Search(ctx, alice, "infra", "", 2)
	if len(s.Items) != 2 || s.Next != "2" {
		t.Fatalf("%+v", s)
	}
	s, _ = f.svc.Search(ctx, alice, "infra", s.Next, 2)
	if len(s.Items) != 1 || s.Next != "" {
		t.Fatalf("%+v", s)
	}
	if s, _ := f.svc.Search(ctx, alice, "infra", "99", 2); len(s.Items) != 0 {
		t.Fatal("offset past end")
	}
	if s, _ := f.svc.Search(ctx, alice, "example.org", "", 1000); len(s.Items) != 4 {
		t.Fatalf("host match %d", len(s.Items))
	}
	if s, _ := f.svc.Search(ctx, alice, pw, "", 10); len(s.Items) != 0 {
		t.Fatal("material searchable")
	}
	if s, _ := f.svc.Search(ctx, bob, "example", "", 10); len(s.Items) != 4 {
		t.Fatalf("bob scope %d", len(s.Items))
	}
	for _, bad := range []string{"", strings.Repeat("q", 201)} {
		if _, err := f.svc.Search(ctx, alice, bad, "", 10); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q", bad)
		}
	}
	for _, c := range []string{"x", "1234567890"} {
		if _, err := f.svc.Search(ctx, alice, "a", c, 10); !errors.Is(err, ErrInvalid) {
			t.Errorf("cursor %q", c)
		}
	}
	// Store failures.
	f.ms.FailOn("SecretsInFolder", errors.New("db"))
	if _, err := f.svc.List(ctx, alice, &f.infra, "", 2); err == nil {
		t.Fatal("list db")
	}
	f.ms.FailOn("SecretsInFolder", nil)
	f.ms.FailOn("GrantsForSubjects", errors.New("db"))
	if _, err := f.svc.List(ctx, alice, nil, "", 2); err == nil {
		t.Fatal("list perms db")
	}
	f.ms.FailOn("GrantsForSubjects", nil)
	for _, op := range []string{"GrantsForSubjects", "FolderSubtree", "SearchSecrets", "GrantsOnResources"} {
		f.ms.FailOn(op, errors.New("db"))
		if _, err := f.svc.Search(ctx, alice, "a", "", 2); err == nil {
			t.Fatalf("search %s", op)
		}
		f.ms.FailOn(op, nil)
	}
	// The second grants query (direct secret permissions) failing after the scope was computed.
	second := &grantsForSubjectsNth{Store: f.ms, n: 2}
	svcS := New(second, f.vt, authz.New(second, nil), nil)
	if _, err := svcS.Search(ctx, alice, "a", "", 2); err == nil {
		t.Fatal("search direct grants db")
	}
	noMarkers(t, f)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRevealVersionsRestore(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	v := f.create(t, "db", &f.infra)
	m, err := f.svc.Reveal(ctx, alice, v.ID, 0)
	if err != nil || m.Password != pw || m.Version != 1 {
		t.Fatalf("%+v %v", m, err)
	}
	if _, err := f.svc.Reveal(ctx, bob, v.ID, 0); !errors.Is(err, ErrForbidden) {
		t.Fatal("bob reveal")
	}
	if _, err := f.svc.Reveal(ctx, alice, v.ID, 9); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown version")
	}
	// Two password changes with comments.
	n, err := f.svc.UpdatePassword(ctx, alice, v.ID, pw+"-2", "rotated")
	if err != nil || n != 2 {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := f.svc.UpdatePassword(ctx, alice, v.ID, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty password")
	}
	if _, err := f.svc.UpdatePassword(ctx, alice, v.ID, "x", strings.Repeat("c", 501)); !errors.Is(err, ErrInvalid) {
		t.Fatal("long comment")
	}
	if _, err := f.svc.UpdatePassword(ctx, bob, v.ID, "x", ""); !errors.Is(err, ErrForbidden) {
		t.Fatal("bob update pw")
	}
	n, _ = f.svc.UpdatePassword(ctx, alice, v.ID, pw+"-3", "rotated again")
	if n != 3 {
		t.Fatal(n)
	}
	vs, err := f.svc.Versions(ctx, alice, v.ID)
	if err != nil || len(vs) != 3 || vs[0].Version != 3 || !vs[0].Current || vs[2].Current || vs[1].Comment != "rotated" || vs[0].CreatedBy != uA {
		t.Fatalf("%+v %v", vs, err)
	}
	js, _ := json.Marshal(vs)
	if strings.Contains(string(js), "MARKER") {
		t.Fatal("material in versions")
	}
	if _, err := f.svc.Versions(ctx, bob, v.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("bob versions")
	}
	// Specific version reveal is audited as a version read.
	m, err = f.svc.Reveal(ctx, alice, v.ID, 1)
	if err != nil || m.Password != pw || m.Version != 1 {
		t.Fatalf("%+v %v", m, err)
	}
	if len(f.events("secret_version_read")) != 1 || len(f.events("secret_password_read")) != 1 {
		t.Fatal("reveal audit")
	}
	// Restore v1 → v4 with the old material and source restore:1.
	nv, err := f.svc.Restore(ctx, alice, v.ID, 1, "back to v1")
	if err != nil || nv != 4 {
		t.Fatalf("%d %v", nv, err)
	}
	m, _ = f.svc.Reveal(ctx, alice, v.ID, 0)
	if m.Password != pw || m.Version != 4 {
		t.Fatalf("%+v", m)
	}
	vs, _ = f.svc.Versions(ctx, alice, v.ID)
	if vs[0].Source != "restore:1" || vs[0].Checksum != Checksum(pw) {
		t.Fatalf("%+v", vs[0])
	}
	for _, bad := range []struct {
		ver int
		c   string
	}{{0, ""}, {1, strings.Repeat("c", 501)}} {
		if _, err := f.svc.Restore(ctx, alice, v.ID, bad.ver, bad.c); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v", bad)
		}
	}
	if _, err := f.svc.Restore(ctx, alice, v.ID, 99, ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("restore unknown")
	}
	if _, err := f.svc.Restore(ctx, bob, v.ID, 1, ""); !errors.Is(err, ErrForbidden) {
		t.Fatal("bob restore")
	}
	// Vault failures on each material path.
	f.vt.Down = true
	if _, err := f.svc.Reveal(ctx, alice, v.ID, 0); !errors.Is(err, ErrVaultUnavailable) {
		t.Fatal("reveal down")
	}
	if _, err := f.svc.UpdatePassword(ctx, alice, v.ID, "x", ""); !errors.Is(err, ErrVaultUnavailable) {
		t.Fatal("update down")
	}
	if _, err := f.svc.Restore(ctx, alice, v.ID, 1, ""); !errors.Is(err, ErrVaultUnavailable) {
		t.Fatal("restore down")
	}
	f.vt.Down = false
	f.vt.FailAfter = f.vt.Writes() + 1
	if _, err := f.svc.Restore(ctx, alice, v.ID, 1, ""); !errors.Is(err, ErrVaultUnavailable) {
		t.Fatal("restore put down")
	}
	f.vt.FailAfter = 0
	// Database failures.
	f.ms.FailOn("GetSecret", errors.New("db"))
	for name, fn := range map[string]func() error{
		"reveal":   func() error { _, err := f.svc.Reveal(ctx, alice, v.ID, 0); return err },
		"versions": func() error { _, err := f.svc.Versions(ctx, alice, v.ID); return err },
		"update":   func() error { _, err := f.svc.Update(ctx, alice, v.ID, Patch{}); return err },
	} {
		if err := fn(); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	f.ms.FailOn("GetSecret", nil)
	f.ms.FailOn("VersionsOf", errors.New("db"))
	if _, err := f.svc.Versions(ctx, alice, v.ID); err == nil {
		t.Fatal("versions db")
	}
	f.ms.FailOn("VersionsOf", nil)
	f.ms.FailOn("InsertVersion", errors.New("db"))
	if _, err := f.svc.UpdatePassword(ctx, alice, v.ID, "x", ""); err == nil {
		t.Fatal("commit db")
	}
	if _, err := f.svc.Restore(ctx, alice, v.ID, 1, ""); err == nil {
		t.Fatal("restore commit db")
	}
	f.ms.FailOn("InsertVersion", nil)
	f.ms.FailOn("UpdateSecret", errors.New("db"))
	if _, err := f.svc.Update(ctx, alice, v.ID, Patch{}); err == nil {
		t.Fatal("update db")
	}
	f.ms.FailOn("UpdateSecret", nil)
	f.ms.FailOn("GetVersion", errors.New("db"))
	if _, err := f.svc.Reveal(ctx, alice, v.ID, 1); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("get version db")
	}
	f.ms.FailOn("GetVersion", nil)
	noMarkers(t, f)
}

func TestMoveDeleteTOTP(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	archive := store.NewID()
	must(t, f.ms.InsertFolder(ctx, store.Folder{ID: archive, TenantID: tA, Name: "Archive", Path: "/Archive"}))
	v := f.create(t, "db", &f.infra)
	// Move needs write on the secret and the target.
	if _, err := f.svc.Move(ctx, alice, v.ID, &archive); !errors.Is(err, ErrForbidden) {
		t.Fatal("move target")
	}
	must(t, f.az.GrantOwner(ctx, tA, authz.Folder, archive, uA))
	m, err := f.svc.Move(ctx, alice, v.ID, &archive)
	if err != nil || m.FolderPath != "/Archive" {
		t.Fatalf("%+v %v", m, err)
	}
	m, err = f.svc.Move(ctx, alice, v.ID, nil)
	if err != nil || m.FolderID != nil || m.FolderPath != "" {
		t.Fatalf("%+v %v", m, err)
	}
	if _, err := f.svc.Move(ctx, bob, v.ID, nil); !errors.Is(err, ErrForbidden) {
		t.Fatal("bob move")
	}
	// TOTP: set (validated), code, remove; seed never in the view.
	if err := f.svc.SetTOTP(ctx, alice, v.ID, "nope"); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatal("bad seed")
	}
	if err := f.svc.SetTOTP(ctx, bob, v.ID, "JBSWY3DPEHPK3PXP"); !errors.Is(err, ErrForbidden) {
		t.Fatal("bob totp")
	}
	if _, err := f.svc.TOTPCode(ctx, alice, v.ID); !errors.Is(err, ErrNoTOTP) {
		t.Fatalf("no seed: %v", err)
	}
	must(t, f.svc.SetTOTP(ctx, alice, v.ID, "JBSWY3DPEHPK3PXP"))
	c, err := f.svc.TOTPCode(ctx, alice, v.ID)
	if err != nil || len(c.Code) != 6 || c.Period != 30 {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := f.svc.TOTPCode(ctx, bob, v.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("bob code")
	}
	g, _ := f.svc.Get(ctx, alice, v.ID)
	if !g.HasTOTP {
		t.Fatal("has_totp")
	}
	if err := f.svc.RemoveTOTP(ctx, bob, v.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("bob remove")
	}
	must(t, f.svc.RemoveTOTP(ctx, alice, v.ID))
	if g, _ := f.svc.Get(ctx, alice, v.ID); g.HasTOTP {
		t.Fatal("has_totp after remove")
	}
	// A corrupted stored seed cannot generate a code.
	must(t, f.vt.PutTOTP(ctx, tA, v.ID, "garbage"))
	must(t, f.ms.SetSecretTOTP(ctx, tA, v.ID, true, nil))
	if _, err := f.svc.TOTPCode(ctx, alice, v.ID); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("garbage seed: %v", err)
	}
	// Vault failures.
	f.vt.Down = true
	if err := f.svc.SetTOTP(ctx, alice, v.ID, "JBSWY3DPEHPK3PXP"); !errors.Is(err, ErrVaultUnavailable) {
		t.Fatal("set down")
	}
	if _, err := f.svc.TOTPCode(ctx, alice, v.ID); !errors.Is(err, ErrVaultUnavailable) {
		t.Fatal("code down")
	}
	if err := f.svc.RemoveTOTP(ctx, alice, v.ID); !errors.Is(err, ErrVaultUnavailable) {
		t.Fatal("remove down")
	}
	// Delete while the vault is down: hidden, pending; the row stays for Reconcile.
	if err := f.svc.Delete(ctx, alice, v.ID); !errors.Is(err, ErrVaultUnavailable) {
		t.Fatalf("delete down: %v", err)
	}
	if _, err := f.svc.Get(ctx, alice, v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted secret visible")
	}
	f.vt.Down = false
	rep, err := f.svc.Reconcile(ctx)
	if err != nil || rep.Deleted != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if _, ok := f.ms.Secrets[v.ID]; ok {
		t.Fatal("row survived reconcile")
	}
	// Normal delete destroys material and rows; delete needs owner; twice is not found.
	w := f.create(t, "w", nil)
	if err := f.svc.Delete(ctx, bob, w.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("bob delete")
	}
	must(t, f.svc.Delete(ctx, alice, w.ID))
	if err := f.svc.Delete(ctx, alice, w.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if _, err := f.vt.GetPassword(ctx, tA, w.ID, 0); !errors.Is(err, vault.ErrNotFound) {
		t.Fatal("material survived")
	}
	// DeleteMany (folder deletion) and its error.
	a, b := f.create(t, "a", &f.infra), f.create(t, "b", &f.infra)
	f.ms.FailOn("HardDeleteSecret", errors.New("db"))
	if err := f.svc.DeleteMany(ctx, alice, []string{a.ID}); err == nil {
		t.Fatal("hard delete db")
	}
	f.ms.FailOn("HardDeleteSecret", nil)
	must(t, f.svc.DeleteMany(ctx, alice, []string{b.ID})) // a is hidden and settled by Reconcile
	if err := f.svc.DeleteMany(ctx, alice, []string{"missing"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("delete many missing")
	}
	// Database failures on move/totp.
	x := f.create(t, "x", nil)
	f.ms.FailOn("MoveSecret", errors.New("db"))
	if _, err := f.svc.Move(ctx, alice, x.ID, nil); err == nil {
		t.Fatal("move db")
	}
	f.ms.FailOn("MoveSecret", nil)
	f.ms.FailOn("GetSecret", errors.New("db"))
	if _, err := f.svc.Move(ctx, alice, x.ID, nil); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("move get db")
	}
	if err := f.svc.SetTOTP(ctx, alice, x.ID, "JBSWY3DPEHPK3PXP"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("set totp get db")
	}
	if _, err := f.svc.TOTPCode(ctx, alice, x.ID); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("code get db")
	}
	f.ms.FailOn("GetSecret", nil)
	f.ms.FailOn("SetSecretTOTP", errors.New("db"))
	if err := f.svc.SetTOTP(ctx, alice, x.ID, "JBSWY3DPEHPK3PXP"); err == nil {
		t.Fatal("set totp db")
	}
	if err := f.svc.RemoveTOTP(ctx, alice, x.ID); err == nil {
		t.Fatal("remove totp db")
	}
	f.ms.FailOn("SetSecretTOTP", nil)
	if len(f.ok("secret_moved")) != 2 || len(f.ok("secret_deleted")) < 3 || len(f.ok("secret_totp_read")) != 1 || len(f.ok("secret_totp_removed")) != 1 {
		t.Fatal("audit")
	}
	noMarkers(t, f)
}

func TestReconcile(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	// An interrupted create: row at version 0 with vault material → repaired.
	f.ms.FailOn("InsertVersion", errors.New("db"))
	_, _ = f.svc.Create(ctx, alice, Input{Name: "stuck", Password: pw})
	f.ms.FailOn("InsertVersion", nil)
	// An orphan row: version 0, no material.
	orphan := store.NewID()
	must(t, f.ms.InsertSecret(ctx, store.Secret{ID: orphan, TenantID: tA, Name: "orphan", VaultPath: "p"}))
	// A fresh row inside the grace period is left alone.
	fresh := store.NewID()
	f.now = f.now.Add(ReconcileGrace + time.Minute)
	must(t, f.ms.InsertSecret(ctx, store.Secret{ID: fresh, TenantID: tA, Name: "fresh", VaultPath: "p"}))
	rep, err := f.svc.Reconcile(ctx)
	if err != nil || rep.Repaired != 1 || rep.Orphans != 1 || rep.Deleted != 0 || rep.Failed != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	var stuck store.Secret
	for _, s := range f.ms.Secrets {
		if s.Name == "stuck" {
			stuck = s
		}
	}
	if stuck.CurrentVersion != 1 || len(f.ms.Versions[stuck.ID]) != 1 || f.ms.Versions[stuck.ID][0].Source != "reconcile" {
		t.Fatalf("%+v", stuck)
	}
	if _, ok := f.ms.Secrets[orphan]; ok {
		t.Fatal("orphan kept")
	}
	if _, ok := f.ms.Secrets[fresh]; !ok {
		t.Fatal("fresh row removed")
	}
	// Failures are counted, not fatal: vault down, then database errors per branch.
	f.now = f.now.Add(ReconcileGrace + time.Minute)
	must(t, f.ms.SoftDeleteSecret(ctx, tA, stuck.ID))
	f.vt.Down = true
	rep, _ = f.svc.Reconcile(ctx)
	if rep.Failed != 2 { // hidden row (delete) + fresh row (versions)
		t.Fatalf("%+v", rep)
	}
	f.vt.Down = false
	f.ms.FailOn("HardDeleteSecret", errors.New("db"))
	rep, _ = f.svc.Reconcile(ctx)
	if rep.Failed != 2 {
		t.Fatalf("%+v", rep)
	}
	f.ms.FailOn("HardDeleteSecret", nil)
	// Repair branch failures: version insert and current version update.
	repair := store.NewID()
	must(t, f.ms.InsertSecret(ctx, store.Secret{ID: repair, TenantID: tA, Name: "repair", VaultPath: "p"}))
	_, _ = f.vt.PutPassword(ctx, tA, repair, pw)
	f.now = f.now.Add(ReconcileGrace + time.Minute)
	f.ms.FailOn("InsertVersion", errors.New("db"))
	if rep, _ = f.svc.Reconcile(ctx); rep.Failed != 1 || rep.Deleted != 1 || rep.Orphans != 1 {
		t.Fatalf("%+v", rep)
	}
	f.ms.FailOn("InsertVersion", nil)
	f.ms.FailOn("SetSecretVersion", errors.New("db"))
	if rep, _ = f.svc.Reconcile(ctx); rep.Failed != 1 {
		t.Fatalf("%+v", rep)
	}
	f.ms.FailOn("SetSecretVersion", nil)
	rep, _ = f.svc.Reconcile(ctx)
	if rep.Repaired != 1 || rep.Deleted != 0 {
		t.Fatalf("%+v", rep)
	}
	f.ms.FailOn("PendingSecrets", errors.New("db"))
	if _, err := f.svc.Reconcile(ctx); err == nil {
		t.Fatal("pending db")
	}
	f.ms.FailOn("PendingSecrets", nil)
	// The runner stops with the context and reports errors.
	rctx, cancel := context.WithCancel(ctx)
	errs := make(chan error, 1)
	f.ms.FailOn("PendingSecrets", errors.New("db"))
	go f.svc.RunReconciler(rctx, 5*time.Millisecond, func(err error) {
		select {
		case errs <- err:
		default:
		}
	})
	select {
	case <-errs:
	case <-time.After(2 * time.Second):
		t.Fatal("runner never reported")
	}
	cancel()
	f.ms.FailOn("PendingSecrets", nil)
	// The vault's own version listing failing.
	// Unsettled rows with no audit writer are silent.
	quiet := New(f.ms, f.vt, f.az, nil)
	if _, err := quiet.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	noMarkers(t, f)
}

func TestSecondLoadFailures(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	v := f.create(t, "db", &f.infra)
	must(t, f.svc.SetTOTP(ctx, alice, v.ID, "JBSWY3DPEHPK3PXP"))
	for name, fn := range map[string]func(svc *Service) error{
		"get":      func(svc *Service) error { _, err := svc.Get(ctx, alice, v.ID); return err },
		"update":   func(svc *Service) error { _, err := svc.Update(ctx, alice, v.ID, Patch{}); return err },
		"reveal":   func(svc *Service) error { _, err := svc.Reveal(ctx, alice, v.ID, 0); return err },
		"versions": func(svc *Service) error { _, err := svc.Versions(ctx, alice, v.ID); return err },
		"move":     func(svc *Service) error { _, err := svc.Move(ctx, alice, v.ID, nil); return err },
		"settotp":  func(svc *Service) error { return svc.SetTOTP(ctx, alice, v.ID, "JBSWY3DPEHPK3PXP") },
		"code":     func(svc *Service) error { _, err := svc.TOTPCode(ctx, alice, v.ID); return err },
	} {
		w := &failNth{Store: f.ms, n: 2}
		svc := New(w, f.vt, authz.New(w, nil), nil)
		if err := fn(svc); err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrForbidden) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An empty folder lists nothing; duplicate folder grants are folded in the search scope.
	empty := store.NewID()
	must(t, f.ms.InsertFolder(ctx, store.Folder{ID: empty, TenantID: tA, Name: "Empty", Path: "/Empty"}))
	must(t, f.az.GrantOwner(ctx, tA, authz.Folder, empty, uA))
	if p, err := f.svc.List(ctx, alice, &empty, "", 10); err != nil || len(p.Items) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := f.ms.UpsertGrant(ctx, store.Grant{ID: store.NewID(), TenantID: tA, ResourceType: "folder", ResourceID: f.infra, SubjectType: "role", SubjectID: "member", Relation: "viewer"}); err != nil {
		t.Fatal(err)
	}
	if p, _ := f.svc.Search(ctx, alice, "db", "", 10); len(p.Items) != 1 {
		t.Fatalf("%+v", p)
	}
	// A view of a bare row still carries an object for metadata.
	if vv := view(store.Secret{}, authz.Permissions{}); string(vv.Metadata) != "{}" {
		t.Fatal("metadata default")
	}
	// A tenant id that cannot form a vault path maps to invalid input on material access.
	weird := authz.Subjects{TenantID: "weird", UserID: uA}
	sid := store.NewID()
	must(t, f.ms.InsertSecret(ctx, store.Secret{ID: sid, TenantID: "weird", Name: "w", VaultPath: "p", CurrentVersion: 1}))
	must(t, f.az.GrantOwner(ctx, "weird", authz.Secret, sid, uA))
	if _, err := f.svc.Reveal(ctx, weird, sid, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad path: %v", err)
	}
}

func TestReadableAndMaterial(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	if err := (Input{Name: "ok"}).Validate(); err != nil {
		t.Fatal(err)
	}
	// CreateChecked skips the folder check (the importer verified it) and still returns the view.
	v, err := f.svc.CreateChecked(ctx, bob, Input{FolderID: &f.infra, Name: "checked", Password: pw, TOTP: "JBSWY3DPEHPK3PXP"})
	if err != nil || v.FolderPath != "/Infra" || !v.HasTOTP {
		t.Fatalf("%+v %v", v, err)
	}
	a := f.create(t, "a", &f.infra)
	root := f.create(t, "loose", nil)
	// Readable within a folder needs read on it; the subtree is listed with the folder's permissions.
	rows, err := f.svc.Readable(ctx, alice, &f.infra, 0)
	if err != nil || len(rows) != 2 || !rows[0].Permissions.Write {
		t.Fatalf("%d %v", len(rows), err)
	}
	if rows, _ := f.svc.Readable(ctx, alice, &f.infra, 1); len(rows) != 1 {
		t.Fatal("limit")
	}
	if _, err := f.svc.Readable(ctx, bob, &f.infra, 0); !errors.Is(err, ErrForbidden) {
		t.Fatal("bob folder")
	}
	// Scope listing: folder grants expanded plus direct secret grants, deduplicated, capped.
	all, err := f.svc.Readable(ctx, alice, nil, 0)
	if err != nil || len(all) != 3 {
		t.Fatalf("%d %v", len(all), err)
	}
	must(t, f.az.GrantOwner(ctx, tA, authz.Secret, a.ID, uA)) // direct grant on a folder secret: not listed twice
	if all, _ := f.svc.Readable(ctx, alice, nil, 0); len(all) != 3 {
		t.Fatal("duplicate")
	}
	if all, _ := f.svc.Readable(ctx, alice, nil, 2); len(all) != 2 {
		t.Fatal("cap")
	}
	if all, _ := f.svc.Readable(ctx, bob, nil, 0); len(all) != 1 || all[0].ID != v.ID {
		t.Fatalf("bob scope %+v", all)
	}
	carol := authz.Subjects{TenantID: tA, UserID: "carol"}
	if all, err := f.svc.Readable(ctx, carol, nil, 0); err != nil || all == nil || len(all) != 0 {
		t.Fatalf("empty scope %v %v", all, err)
	}
	// Material for exports: password and seed; refused without read; vault errors surface.
	var checked View
	for _, it := range all {
		if it.ID == v.ID {
			checked = it
		}
	}
	pwd, seed, err := f.svc.MaterialOf(ctx, alice, checked)
	if err != nil || pwd != pw || seed == "" {
		t.Fatalf("%q %q %v", pwd, seed, err)
	}
	if _, _, err := f.svc.MaterialOf(ctx, alice, View{ID: root.ID}); !errors.Is(err, ErrForbidden) {
		t.Fatal("no read")
	}
	if p, s, err := f.svc.MaterialOf(ctx, alice, View{ID: root.ID, Permissions: authz.Of(authz.Owner)}); err != nil || p != "" || s != "" {
		t.Fatalf("version 0: %q %q %v", p, s, err)
	}
	must(t, f.vt.DeleteTOTP(ctx, tA, v.ID))
	if _, seed, err := f.svc.MaterialOf(ctx, alice, checked); err != nil || seed != "" {
		t.Fatalf("missing seed: %q %v", seed, err)
	}
	f.vt.Down = true
	if _, _, err := f.svc.MaterialOf(ctx, alice, checked); !errors.Is(err, ErrVaultUnavailable) {
		t.Fatal("vault down password")
	}
	f.vt.Down = false
	stub := &totpDown{Fake: f.vt}
	svc2 := New(f.ms, stub, f.az, nil)
	if _, _, err := svc2.MaterialOf(ctx, alice, checked); !errors.Is(err, ErrVaultUnavailable) {
		t.Fatal("vault down seed")
	}
	// Store failures on every Readable path.
	for _, op := range []string{"FolderSubtree", "SecretsInFolders"} {
		f.ms.FailOn(op, errors.New("db"))
		if _, err := f.svc.Readable(ctx, alice, &f.infra, 0); err == nil {
			t.Fatalf("%s folder", op)
		}
		if _, err := f.svc.Readable(ctx, alice, nil, 0); err == nil {
			t.Fatalf("%s scope", op)
		}
		f.ms.FailOn(op, nil)
	}
	for _, op := range []string{"GrantsForSubjects", "SecretsByIDs", "GrantsOnResources"} {
		f.ms.FailOn(op, errors.New("db"))
		if _, err := f.svc.Readable(ctx, alice, nil, 0); err == nil {
			t.Fatalf("%s scope", op)
		}
		f.ms.FailOn(op, nil)
	}
	// The folder of a directly granted secret failing to evaluate (bob holds only a secret grant).
	f.ms.FailOn("GrantsOnResources", errors.New("db"))
	if _, err := f.svc.Readable(ctx, bob, nil, 0); err == nil {
		t.Fatal("direct grant folder error")
	}
	f.ms.FailOn("GrantsOnResources", nil)
	// The second grants query (direct secret permissions) failing after the scope was computed.
	second := &grantsForSubjectsNth{Store: f.ms, n: 2}
	svc4 := New(second, f.vt, authz.New(second, nil), nil)
	if _, err := svc4.Readable(ctx, alice, nil, 0); err == nil {
		t.Fatal("direct grants db")
	}
	// Read-back failing after a successful create.
	w := &failNth{Store: f.ms, n: 1}
	svc3 := New(w, f.vt, authz.New(w, nil), nil)
	if _, err := svc3.CreateChecked(ctx, alice, Input{Name: "rb", Password: pw}); err == nil {
		t.Fatal("read-back error")
	}
	if _, err := f.svc.UpdatePasswordFrom(ctx, alice, a.ID, "x", "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty source")
	}
}

// totpDown fails only the seed read.
type totpDown struct{ *vault.Fake }

func (t *totpDown) GetTOTP(context.Context, string, string) (string, error) {
	return "", vault.ErrUnavailable
}

// grantsForSubjectsNth fails the n-th GrantsForSubjects call.
type grantsForSubjectsNth struct {
	*memstore.Store
	n, calls int
}

func (g *grantsForSubjectsNth) GrantsForSubjects(ctx context.Context, tid, uid string, roles []string, now time.Time) ([]store.Grant, error) {
	g.calls++
	if g.calls == g.n {
		return nil, errors.New("db")
	}
	return g.Store.GrantsForSubjects(ctx, tid, uid, roles, now)
}
