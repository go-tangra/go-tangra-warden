package authz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra-warden/v4/internal/audit"
	"github.com/go-tangra/go-tangra-warden/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
)

const (
	tA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	tB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
	uA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"
	uB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c88"
)

// tree: root folder "Infra" > "Databases" > "Prod"; secret "db" in Prod, secret "loose" at root.
type fixture struct {
	ms                     *memstore.Store
	az                     *Authz
	aw                     *audit.Writer
	infra, databases, prod string
	db, loose              string
	now                    time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ms := memstore.New()
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	az := New(ms, aw)
	f := &fixture{ms: ms, az: az, aw: aw, now: time.Unix(1_700_000_000, 0)}
	az.SetClock(func() time.Time { return f.now })
	ms.Now = func() time.Time { return f.now }
	ctx := context.Background()
	f.infra, f.databases, f.prod, f.db, f.loose = store.NewID(), store.NewID(), store.NewID(), store.NewID(), store.NewID()
	must(t, ms.InsertFolder(ctx, store.Folder{ID: f.infra, TenantID: tA, Name: "Infra", Path: "/Infra"}))
	must(t, ms.InsertFolder(ctx, store.Folder{ID: f.databases, TenantID: tA, ParentID: &f.infra, Name: "Databases", Path: "/Infra/Databases", Ancestors: []string{f.infra}}))
	must(t, ms.InsertFolder(ctx, store.Folder{ID: f.prod, TenantID: tA, ParentID: &f.databases, Name: "Prod", Path: "/Infra/Databases/Prod", Ancestors: []string{f.infra, f.databases}}))
	must(t, ms.InsertSecret(ctx, store.Secret{ID: f.db, TenantID: tA, FolderID: &f.prod, Name: "db", VaultPath: "p"}))
	must(t, ms.InsertSecret(ctx, store.Secret{ID: f.loose, TenantID: tA, Name: "loose", VaultPath: "p"}))
	return f
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) grant(t *testing.T, rtype, rid, stype, sid, rel string, exp *time.Time) store.Grant {
	t.Helper()
	g, err := f.ms.UpsertGrant(context.Background(), store.Grant{ID: store.NewID(), TenantID: tA, ResourceType: rtype, ResourceID: rid, SubjectType: stype, SubjectID: sid, Relation: rel, ExpiresAt: exp})
	must(t, err)
	return g
}

func (f *fixture) refusals() int {
	f.aw.Flush()
	return len(f.ms.AuditEvents(tA, "access_refused"))
}

func TestRelationsAndSubjects(t *testing.T) {
	for rel, want := range map[string]Permissions{
		Owner: {true, true, true, true}, Editor: {true, true, false, false}, Viewer: {true, false, false, false}, Sharer: {true, false, false, true}, "x": {},
	} {
		if Of(rel) != want {
			t.Errorf("%s: %+v", rel, Of(rel))
		}
	}
	p := Of(Owner)
	for _, perm := range []string{Read, Write, Delete, Share} {
		if !p.Has(perm) || !ValidPermission(perm) {
			t.Errorf("%s", perm)
		}
	}
	if p.Has("admin") || ValidPermission("admin") || ValidRelation("root") || ValidResourceType("thing") || ValidSubjectType("group") || !ValidSubjectType(SubjectTenant) {
		t.Fatal("validators")
	}
	s := SubjectsOf(authclient.Identity{UserID: uA, TenantID: tA, Roles: []string{"member", "ops"}})
	if s.UserID != uA || s.TenantID != tA || len(s.Roles) != 2 {
		t.Fatalf("%+v", s)
	}
	if matches(store.Grant{SubjectType: "group"}, s, time.Now()) {
		t.Fatal("unknown subject type matched")
	}
}

func TestCheckLattice(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	alice := Subjects{TenantID: tA, UserID: uA, Roles: []string{"member"}}
	// Nothing granted: refused and audited; unknown inputs refused; cross-tenant not found.
	d, err := f.az.Check(ctx, alice, Secret, f.db, Read)
	if err != nil || d.Allowed || d.Relation != "" {
		t.Fatalf("%+v %v", d, err)
	}
	if f.refusals() != 1 {
		t.Fatal("refusal not audited")
	}
	if _, err := f.az.Check(ctx, alice, Secret, f.db, "admin"); !errors.Is(err, ErrInput) {
		t.Fatal("bad permission")
	}
	if _, err := f.az.Check(ctx, alice, "thing", f.db, Read); !errors.Is(err, ErrInput) {
		t.Fatal("bad resource type")
	}
	bob := Subjects{TenantID: tB, UserID: uB}
	if _, err := f.az.Check(ctx, bob, Secret, f.db, Read); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant secret: %v", err)
	}
	if _, err := f.az.Check(ctx, bob, Folder, f.prod, Read); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant folder: %v", err)
	}
	if _, err := f.az.Require(ctx, bob, Folder, f.prod, Read); !errors.Is(err, ErrNotFound) {
		t.Fatal("require propagates not found")
	}
	// Viewer on the root folder is inherited three levels down to the secret.
	f.grant(t, Folder, f.infra, SubjectUser, uA, Viewer, nil)
	d, err = f.az.Check(ctx, alice, Secret, f.db, Read)
	if err != nil || !d.Allowed || d.Relation != Viewer || len(d.Sources) != 1 || !d.Sources[0].Inherited {
		t.Fatalf("%+v %v", d, err)
	}
	if d, _ := f.az.Check(ctx, alice, Secret, f.db, Write); d.Allowed {
		t.Fatal("viewer may write")
	}
	if _, err := f.az.Require(ctx, alice, Secret, f.db, Write); !errors.Is(err, ErrForbidden) {
		t.Fatal("require forbidden")
	}
	// Editor through a role on the middle folder: union of permissions, strongest relation reported.
	f.grant(t, Folder, f.databases, SubjectRole, "member", Editor, nil)
	d, _ = f.az.Check(ctx, alice, Secret, f.db, Write)
	if !d.Allowed || d.Relation != Editor || d.Permissions != (Permissions{Read: true, Write: true}) || len(d.Sources) != 2 || d.Sources[0].Relation != Editor {
		t.Fatalf("%+v", d)
	}
	// Sharer on the secret itself adds share; delete needs owner.
	f.grant(t, Secret, f.db, SubjectTenant, "", Sharer, nil)
	d, _ = f.az.Check(ctx, alice, Secret, f.db, Share)
	if !d.Allowed || d.Relation != Editor || !d.Permissions.Share || d.Permissions.Delete {
		t.Fatalf("%+v", d)
	}
	if d, _ := f.az.Check(ctx, alice, Secret, f.db, Delete); d.Allowed {
		t.Fatal("delete without owner")
	}
	// Expired grants are ignored at the boundary; a future expiry counts.
	past := f.now
	future := f.now.Add(time.Second)
	f.grant(t, Secret, f.loose, SubjectUser, uA, Owner, &past)
	if d, _ := f.az.Check(ctx, alice, Secret, f.loose, Read); d.Allowed {
		t.Fatal("expired grant honoured")
	}
	f.grant(t, Secret, f.loose, SubjectUser, uA, Owner, &future)
	if d, _ := f.az.Check(ctx, alice, Secret, f.loose, Delete); !d.Allowed || d.Relation != Owner {
		t.Fatal("future expiry refused")
	}
	f.now = f.now.Add(2 * time.Second)
	if d, _ := f.az.Check(ctx, alice, Secret, f.loose, Read); d.Allowed {
		t.Fatal("grant outlived its expiry")
	}
	// Another user with a role that is not theirs sees nothing.
	carol := Subjects{TenantID: tA, UserID: uB, Roles: []string{"auditor"}}
	if d, _ := f.az.Check(ctx, carol, Folder, f.databases, Read); d.Allowed {
		t.Fatal("role mismatch allowed")
	}
	// PermissionsOn decorates without auditing.
	before := f.refusals()
	p, err := f.az.PermissionsOn(ctx, alice, Folder, f.prod)
	if err != nil || !p.Write || p.Delete {
		t.Fatalf("%+v %v", p, err)
	}
	if f.refusals() != before {
		t.Fatal("PermissionsOn audited")
	}
	if _, err := f.az.PermissionsOn(ctx, bob, Folder, f.prod); !errors.Is(err, ErrNotFound) {
		t.Fatal("PermissionsOn cross-tenant")
	}
	// Creator-owner helper.
	must(t, f.az.GrantOwner(ctx, tA, Folder, f.prod, uB))
	if d, _ := f.az.Check(ctx, carol, Folder, f.prod, Delete); !d.Allowed || d.Relation != Owner || d.Sources[0].Inherited {
		t.Fatalf("%+v", d)
	}
	// A secret whose folder vanished is not found; store failures surface.
	orphan := store.NewID()
	gone := store.NewID()
	must(t, f.ms.InsertFolder(ctx, store.Folder{ID: gone, TenantID: tA, Name: "Gone", Path: "/Gone"}))
	must(t, f.ms.InsertSecret(ctx, store.Secret{ID: orphan, TenantID: tA, FolderID: &gone, Name: "orphan", VaultPath: "p"}))
	delete(f.ms.Folders, gone)
	if _, err := f.az.Check(ctx, alice, Secret, orphan, Read); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orphan: %v", err)
	}
	f.ms.FailOn("GrantsOnResources", errors.New("db down"))
	if _, err := f.az.Check(ctx, alice, Secret, f.db, Read); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("store error swallowed")
	}
	if _, err := f.az.PermissionsOn(ctx, alice, Secret, f.db); err == nil {
		t.Fatal("store error swallowed in PermissionsOn")
	}
	f.ms.FailOn("GrantsOnResources", nil)
	f.ms.FailOn("GetSecret", errors.New("db down"))
	if _, err := f.az.Check(ctx, alice, Secret, f.db, Read); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("store error mapped to not found")
	}
	f.ms.FailOn("GetSecret", nil)
	f.ms.FailOn("UpsertGrant", errors.New("db down"))
	if err := f.az.GrantOwner(ctx, tA, Folder, f.prod, uB); err == nil {
		t.Fatal("GrantOwner error swallowed")
	}
	// Require passes an allowed decision through; locate refuses unknown types.
	if d, err := f.az.Require(ctx, alice, Secret, f.db, Read); err != nil || !d.Allowed {
		t.Fatalf("require ok: %+v %v", d, err)
	}
	if _, err := f.az.locate(ctx, tA, "thing", f.db); !errors.Is(err, ErrInput) {
		t.Fatal("locate type")
	}
	// No audit writer: refusals are silent.
	quiet := New(f.ms, nil)
	if d, err := quiet.Check(ctx, carol, Secret, f.loose, Read); err != nil || d.Allowed {
		t.Fatalf("%+v %v", d, err)
	}
}
