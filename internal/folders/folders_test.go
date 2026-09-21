package folders

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-freya/freya/services/warden/internal/audit"
	"github.com/go-freya/freya/services/warden/internal/authz"
	"github.com/go-freya/freya/services/warden/internal/memstore"
	"github.com/go-freya/freya/services/warden/internal/store"
)

const (
	tA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	tB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
	uA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"
	uB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c88"
)

type deleter struct {
	ms  *memstore.Store
	got []string
	err error
}

func (d *deleter) DeleteMany(ctx context.Context, s authz.Subjects, ids []string) error {
	d.got = append(d.got, ids...)
	if d.err != nil {
		return d.err
	}
	for _, id := range ids {
		_ = d.ms.HardDeleteSecret(ctx, s.TenantID, id)
	}
	return nil
}

type fx struct {
	ms  *memstore.Store
	az  *authz.Authz
	aw  *audit.Writer
	svc *Service
	del *deleter
}

func newFx(t *testing.T) *fx {
	t.Helper()
	ms := memstore.New()
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	az := authz.New(ms, aw)
	del := &deleter{ms: ms}
	return &fx{ms: ms, az: az, aw: aw, svc: New(ms, az, aw, del), del: del}
}

func (f *fx) events(t string) int { f.aw.Flush(); return len(f.ms.AuditEvents(tA, t)) }

var (
	alice = authz.Subjects{TenantID: tA, UserID: uA, Roles: []string{"member"}}
	bob   = authz.Subjects{TenantID: tA, UserID: uB, Roles: []string{"ops"}}
	other = authz.Subjects{TenantID: tB, UserID: uB}
)

func TestValidName(t *testing.T) {
	for _, ok := range []string{"Infra", "Dévelopment ops", "a"} {
		if !ValidName(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "   ", "a/b", "tab\there", strings.Repeat("x", 101), "nl\n"} {
		if ValidName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCreateAndTree(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	if _, err := f.svc.Create(ctx, alice, nil, "a/b"); !errors.Is(err, ErrInvalidName) {
		t.Fatal("name")
	}
	infra, err := f.svc.Create(ctx, alice, nil, "Infra")
	if err != nil || infra.Path != "/Infra" || !infra.Permissions.Delete || infra.CreatedBy != uA || infra.ParentID != nil {
		t.Fatalf("%+v %v", infra, err)
	}
	if _, err := f.svc.Create(ctx, alice, nil, "infra"); !errors.Is(err, ErrConflict) {
		t.Fatalf("sibling: %v", err)
	}
	// Bob cannot create under Alice's folder; a foreign tenant sees nothing.
	if _, err := f.svc.Create(ctx, bob, &infra.ID, "Databases"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bob: %v", err)
	}
	if _, err := f.svc.Create(ctx, other, &infra.ID, "Databases"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other: %v", err)
	}
	db, err := f.svc.Create(ctx, alice, &infra.ID, "Databases")
	if err != nil || db.Path != "/Infra/Databases" || *db.ParentID != infra.ID {
		t.Fatalf("%+v %v", db, err)
	}
	prod, _ := f.svc.Create(ctx, alice, &db.ID, "Prod")
	if got := f.ms.Folders[prod.ID].Ancestors; len(got) != 2 || got[0] != infra.ID || got[1] != db.ID {
		t.Fatalf("ancestors %v", got)
	}
	if f.events("folder_created") != 3 {
		t.Fatal("audit")
	}
	// Get with permissions and secret count; children; tree.
	sid := store.NewID()
	if err := f.ms.InsertSecret(ctx, store.Secret{ID: sid, TenantID: tA, FolderID: &prod.ID, Name: "s", VaultPath: "p"}); err != nil {
		t.Fatal(err)
	}
	v, err := f.svc.Get(ctx, alice, prod.ID)
	if err != nil || v.SecretCount != 1 || !v.Permissions.Write {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := f.svc.Get(ctx, bob, prod.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("bob get")
	}
	kids, err := f.svc.Children(ctx, alice, &infra.ID)
	if err != nil || len(kids) != 1 || kids[0].ID != db.ID {
		t.Fatalf("%+v %v", kids, err)
	}
	roots, err := f.svc.Children(ctx, alice, nil)
	if err != nil || len(roots) != 1 {
		t.Fatalf("%+v %v", roots, err)
	}
	if kids, _ := f.svc.Children(ctx, bob, nil); len(kids) != 0 {
		t.Fatal("bob sees roots")
	}
	if _, err := f.svc.Children(ctx, bob, &infra.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("bob children")
	}
	// Bob gets viewer on Databases: he sees Databases > Prod in his tree but not Infra.
	if _, err := f.ms.UpsertGrant(ctx, store.Grant{ID: store.NewID(), TenantID: tA, ResourceType: "folder", ResourceID: db.ID, SubjectType: "role", SubjectID: "ops", Relation: "viewer"}); err != nil {
		t.Fatal(err)
	}
	tree, err := f.svc.Tree(ctx, bob)
	if err != nil || len(tree) != 1 || tree[0].Folder.ID != db.ID || len(tree[0].Children) != 1 || tree[0].Children[0].Folder.ID != prod.ID || tree[0].Children[0].Folder.Permissions.Write {
		t.Fatalf("%+v %v", tree, err)
	}
	tree, _ = f.svc.Tree(ctx, alice)
	if len(tree) != 1 || tree[0].Folder.ID != infra.ID || len(tree[0].Children[0].Children) != 1 {
		t.Fatalf("%+v", tree)
	}
	if tree, _ := f.svc.Tree(ctx, other); len(tree) != 0 {
		t.Fatal("foreign tree")
	}
	// Children under a readable parent inherit; the direct grant on a child unions.
	kids, _ = f.svc.Children(ctx, bob, &db.ID)
	if len(kids) != 1 || !kids[0].Permissions.Read || kids[0].Permissions.Write {
		t.Fatalf("%+v", kids)
	}
	// Store failures.
	for _, op := range []string{"GetFolder", "CountFolderContents"} {
		f.ms.FailOn(op, errors.New("db"))
		if _, err := f.svc.Get(ctx, alice, prod.ID); err == nil || errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: %v", op, err)
		}
		f.ms.FailOn(op, nil)
	}
	f.ms.FailOn("FolderChildren", errors.New("db"))
	if _, err := f.svc.Children(ctx, alice, nil); err == nil {
		t.Fatal("children error")
	}
	f.ms.FailOn("FolderChildren", nil)
	f.ms.FailOn("CountFolderContents", errors.New("db"))
	if _, err := f.svc.Children(ctx, alice, nil); err == nil {
		t.Fatal("children count error")
	}
	f.ms.FailOn("CountFolderContents", nil)
	f.ms.FailOn("GrantsOnResources", errors.New("db"))
	if _, err := f.svc.Children(ctx, alice, nil); err == nil {
		t.Fatal("children perms error")
	}
	f.ms.FailOn("GrantsOnResources", nil)
	for _, op := range []string{"AllFolders", "GrantsForSubjects"} {
		f.ms.FailOn(op, errors.New("db"))
		if _, err := f.svc.Tree(ctx, alice); err == nil {
			t.Fatalf("%s", op)
		}
		f.ms.FailOn(op, nil)
	}
	f.ms.FailOn("InsertFolder", errors.New("db"))
	if _, err := f.svc.Create(ctx, alice, nil, "X"); err == nil {
		t.Fatal("insert error")
	}
	f.ms.FailOn("InsertFolder", nil)
	f.ms.FailOn("GetFolder", errors.New("db"))
	if _, err := f.svc.Create(ctx, alice, &infra.ID, "Y"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("parent load error")
	}
	f.ms.FailOn("GetFolder", nil)
	// Created folder vanishing before the read-back.
	calls := 0
	vanish := &vanishing{Store: f.ms, calls: &calls}
	svc2 := New(vanish, authz.New(vanish, nil), nil, f.del)
	if _, err := svc2.Create(ctx, alice, nil, "Z"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("vanish: %v", err)
	}
}

// vanishing makes the first GetFolder (the read-back after a root create) fail with not found.
type vanishing struct {
	*memstore.Store
	calls *int
}

func (v *vanishing) GetFolder(ctx context.Context, tid, id string) (store.Folder, error) {
	*v.calls++
	if *v.calls == 1 {
		return store.Folder{}, store.ErrNotFound
	}
	return v.Store.GetFolder(ctx, tid, id)
}

func TestRenameMoveDelete(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	infra, _ := f.svc.Create(ctx, alice, nil, "Infra")
	db, _ := f.svc.Create(ctx, alice, &infra.ID, "Databases")
	prod, _ := f.svc.Create(ctx, alice, &db.ID, "Prod")
	archive, _ := f.svc.Create(ctx, alice, nil, "Archive")
	// Rename rewrites the subtree paths; conflicts and permissions apply.
	if _, err := f.svc.Rename(ctx, alice, infra.ID, "bad/name"); !errors.Is(err, ErrInvalidName) {
		t.Fatal("rename name")
	}
	if _, err := f.svc.Rename(ctx, bob, infra.ID, "Ops"); !errors.Is(err, ErrForbidden) {
		t.Fatal("rename bob")
	}
	if _, err := f.svc.Rename(ctx, alice, infra.ID, "archive"); !errors.Is(err, ErrConflict) {
		t.Fatal("rename conflict")
	}
	v, err := f.svc.Rename(ctx, alice, infra.ID, "Infrastructure")
	if err != nil || v.Path != "/Infrastructure" {
		t.Fatalf("%+v %v", v, err)
	}
	if p, _ := f.svc.Get(ctx, alice, prod.ID); p.Path != "/Infrastructure/Databases/Prod" {
		t.Fatalf("subtree path %s", p.Path)
	}
	// Move: cycles refused, target permission required, subtree follows.
	if _, err := f.svc.Move(ctx, alice, infra.ID, &prod.ID); !errors.Is(err, ErrCycle) {
		t.Fatalf("cycle: %v", err)
	}
	if _, err := f.svc.Move(ctx, alice, infra.ID, &infra.ID); !errors.Is(err, ErrCycle) {
		t.Fatal("self cycle")
	}
	if _, err := f.svc.Move(ctx, bob, db.ID, &archive.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("move bob")
	}
	if _, err := f.ms.UpsertGrant(ctx, store.Grant{ID: store.NewID(), TenantID: tA, ResourceType: "folder", ResourceID: db.ID, SubjectType: "user", SubjectID: uB, Relation: "editor"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Move(ctx, bob, db.ID, &archive.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("move bob target")
	}
	v, err = f.svc.Move(ctx, alice, db.ID, &archive.ID)
	if err != nil || v.Path != "/Archive/Databases" {
		t.Fatalf("%+v %v", v, err)
	}
	p := f.ms.Folders[prod.ID]
	if p.Path != "/Archive/Databases/Prod" || len(p.Ancestors) != 2 || p.Ancestors[0] != archive.ID {
		t.Fatalf("%+v", p)
	}
	v, err = f.svc.Move(ctx, alice, db.ID, nil)
	if err != nil || v.Path != "/Databases" || v.ParentID != nil {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := f.svc.Move(ctx, alice, db.ID, nil); !errors.Is(err, ErrConflict) && err != nil {
		t.Fatalf("move to same place: %v", err)
	}
	if f.events("folder_moved") != 3 || f.events("folder_updated") != 1 {
		t.Fatal("audit")
	}
	// Delete: not empty unless recursive; recursive removes secrets via the deleter and grants.
	sid := store.NewID()
	_ = f.ms.InsertSecret(ctx, store.Secret{ID: sid, TenantID: tA, FolderID: &prod.ID, Name: "s", VaultPath: "p"})
	if err := f.svc.Delete(ctx, alice, db.ID, false); !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("not empty: %v", err)
	}
	if err := f.svc.Delete(ctx, bob, db.ID, true); !errors.Is(err, ErrForbidden) {
		t.Fatal("delete bob (editor)")
	}
	if err := f.svc.Delete(ctx, other, db.ID, true); !errors.Is(err, ErrNotFound) {
		t.Fatal("delete other")
	}
	f.del.err = errors.New("vault")
	if err := f.svc.Delete(ctx, alice, db.ID, true); err == nil {
		t.Fatal("secret deletion error swallowed")
	}
	f.del.err = nil
	if err := f.svc.Delete(ctx, alice, db.ID, true); err != nil || len(f.del.got) != 2 {
		t.Fatalf("%v %v", err, f.del.got)
	}
	if _, ok := f.ms.Folders[prod.ID]; ok {
		t.Fatal("subtree survived")
	}
	for _, g := range f.ms.Grants {
		if g.ResourceID == db.ID || g.ResourceID == prod.ID {
			t.Fatal("grants survived")
		}
	}
	if err := f.svc.Delete(ctx, alice, db.ID, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	// Empty folder deletes without recursive.
	if err := f.svc.Delete(ctx, alice, archive.ID, false); err != nil {
		t.Fatal(err)
	}
	if f.events("folder_deleted") != 2 {
		t.Fatal("audit delete")
	}
	// Store failures.
	x, _ := f.svc.Create(ctx, alice, nil, "X")
	y, _ := f.svc.Create(ctx, alice, &x.ID, "Y")
	for _, op := range []string{"FolderSubtree", "SecretsInFolders", "DeleteGrantsOfResource", "DeleteFolder"} {
		f.ms.FailOn(op, errors.New("db"))
		if err := f.svc.Delete(ctx, alice, y.ID, true); err == nil {
			t.Fatalf("%s", op)
		}
		f.ms.FailOn(op, nil)
	}
	f.ms.FailOn("RenameFolder", errors.New("db"))
	if _, err := f.svc.Rename(ctx, alice, y.ID, "Y2"); err == nil {
		t.Fatal("rename error")
	}
	f.ms.FailOn("RenameFolder", nil)
	f.ms.FailOn("MoveFolder", errors.New("db"))
	if _, err := f.svc.Move(ctx, alice, y.ID, nil); err == nil {
		t.Fatal("move error")
	}
	f.ms.FailOn("MoveFolder", nil)
	// Loading the folder or the target during a move failing.
	z, _ := f.svc.Create(ctx, alice, nil, "Z")
	f.ms.FailOn("GetFolder", errors.New("db"))
	if _, err := f.svc.Move(ctx, alice, y.ID, &z.ID); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("move load error")
	}
	f.ms.FailOn("GetFolder", nil)
	calls := 0
	tgt := &targetFails{Store: f.ms, calls: &calls}
	svc2 := New(tgt, authz.New(tgt, nil), nil, f.del)
	if _, err := svc2.Move(ctx, alice, y.ID, &z.ID); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("move target load error")
	}
	// Delete when the folder disappears between the check and the subtree load.
	empty := &emptySubtree{Store: f.ms}
	svc3 := New(empty, authz.New(empty, nil), nil, f.del)
	if err := svc3.Delete(ctx, alice, z.ID, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("vanished: %v", err)
	}
}

// targetFails fails the second GetFolder of a call sequence (the move target).
type targetFails struct {
	*memstore.Store
	calls *int
}

func (v *targetFails) GetFolder(ctx context.Context, tid, id string) (store.Folder, error) {
	*v.calls++
	if *v.calls == 4 { // authz(1) locate folder, service(2) load, authz(3) locate target, service(4) load target
		return store.Folder{}, errors.New("db")
	}
	return v.Store.GetFolder(ctx, tid, id)
}

type emptySubtree struct{ *memstore.Store }

func (emptySubtree) FolderSubtree(context.Context, string, string) ([]store.Folder, error) {
	return nil, nil
}
