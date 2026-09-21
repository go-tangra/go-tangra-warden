package authz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-freya/freya/services/warden/internal/memstore"
	"github.com/go-freya/freya/services/warden/internal/store"
)

func TestGrantRevokeList(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	alice := Subjects{TenantID: tA, UserID: uA, Roles: []string{"member"}}
	bob := Subjects{TenantID: tA, UserID: uB, Roles: []string{"ops"}}
	in := GrantInput{ResourceType: Folder, ResourceID: f.infra, SubjectType: SubjectRole, SubjectID: "ops", Relation: Viewer}
	// Alice holds nothing: forbidden. Shape errors are refused first.
	if _, err := f.az.Grant(ctx, alice, in); !errors.Is(err, ErrForbidden) {
		t.Fatalf("no share: %v", err)
	}
	for name, bad := range map[string]GrantInput{
		"type":        {ResourceType: "x", ResourceID: f.infra, SubjectType: SubjectUser, SubjectID: uB, Relation: Viewer},
		"subject":     {ResourceType: Folder, ResourceID: f.infra, SubjectType: "group", SubjectID: uB, Relation: Viewer},
		"relation":    {ResourceType: Folder, ResourceID: f.infra, SubjectType: SubjectUser, SubjectID: uB, Relation: "root"},
		"no id":       {ResourceType: Folder, SubjectType: SubjectUser, SubjectID: uB, Relation: Viewer},
		"tenant+id":   {ResourceType: Folder, ResourceID: f.infra, SubjectType: SubjectTenant, SubjectID: "x", Relation: Viewer},
		"user no id":  {ResourceType: Folder, ResourceID: f.infra, SubjectType: SubjectUser, Relation: Viewer},
		"long id":     {ResourceType: Folder, ResourceID: f.infra, SubjectType: SubjectRole, SubjectID: string(make([]byte, 129)), Relation: Viewer},
		"past expiry": {ResourceType: Folder, ResourceID: f.infra, SubjectType: SubjectUser, SubjectID: uB, Relation: Viewer, ExpiresAt: &f.now},
	} {
		if _, err := f.az.Grant(ctx, alice, bad); !errors.Is(err, ErrInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Alice becomes sharer on Infra: may grant viewer/sharer, not editor/owner.
	f.grant(t, Folder, f.infra, SubjectUser, uA, Sharer, nil)
	g, err := f.az.Grant(ctx, alice, in)
	if err != nil || g.Relation != Viewer || g.GrantedBy != uA || g.Inherited || g.Expired {
		t.Fatalf("%+v %v", g, err)
	}
	if _, err := f.az.Grant(ctx, alice, GrantInput{ResourceType: Folder, ResourceID: f.infra, SubjectType: SubjectUser, SubjectID: uB, Relation: Editor}); !errors.Is(err, ErrForbidden) {
		t.Fatal("relation above granter accepted")
	}
	if f.refusals() < 2 {
		t.Fatal("escalation not audited")
	}
	// Bob (ops) reads three levels down, cannot write.
	if d, _ := f.az.Check(ctx, bob, Secret, f.db, Read); !d.Allowed {
		t.Fatal("role grant not inherited")
	}
	if d, _ := f.az.Check(ctx, bob, Secret, f.db, Write); d.Allowed {
		t.Fatal("viewer writes")
	}
	// Re-grant replaces (same key, same id) with an expiry.
	exp := f.now.Add(time.Hour)
	in.ExpiresAt = &exp
	in.Relation = Sharer
	g2, err := f.az.Grant(ctx, alice, in)
	if err != nil || g2.ID != g.ID || g2.Relation != Sharer || g2.ExpiresAt == nil {
		t.Fatalf("%+v %v", g2, err)
	}
	// Listing on the deep secret shows inherited grants; needs share (bob is now sharer through ops).
	list, err := f.az.ListGrants(ctx, bob, Secret, f.db)
	if err != nil || len(list) != 2 || !list[0].Inherited {
		t.Fatalf("%+v %v", list, err)
	}
	if _, err := f.az.ListGrants(ctx, bob, "x", f.db); !errors.Is(err, ErrInput) {
		t.Fatal("list bad type")
	}
	carol := Subjects{TenantID: tA, UserID: "carol"}
	if _, err := f.az.ListGrants(ctx, carol, Secret, f.db); !errors.Is(err, ErrForbidden) {
		t.Fatal("list without share")
	}
	if _, err := f.az.ListGrants(ctx, Subjects{TenantID: tB, UserID: uB}, Secret, f.db); !errors.Is(err, ErrNotFound) {
		t.Fatal("list cross-tenant")
	}
	// Effective explains bob's permissions on the secret; carol has none but may ask.
	d, err := f.az.Effective(ctx, bob, Secret, f.db)
	if err != nil || !d.Allowed || d.Relation != Sharer || len(d.Sources) != 1 {
		t.Fatalf("%+v %v", d, err)
	}
	d, err = f.az.Effective(ctx, carol, Folder, f.prod)
	if err != nil || d.Allowed || d.Sources == nil || len(d.Sources) != 0 {
		t.Fatalf("%+v %v", d, err)
	}
	if _, err := f.az.Effective(ctx, carol, "x", f.prod); !errors.Is(err, ErrInput) {
		t.Fatal("effective bad type")
	}
	if _, err := f.az.Effective(ctx, Subjects{TenantID: tB}, Folder, f.prod); !errors.Is(err, ErrNotFound) {
		t.Fatal("effective cross-tenant")
	}
	// Expiry boundary: after an hour bob is refused, the listing flags the grant.
	f.now = exp
	if d, _ := f.az.Check(ctx, bob, Secret, f.db, Read); d.Allowed {
		t.Fatal("expired role grant honoured")
	}
	list, _ = f.az.ListGrants(ctx, alice, Folder, f.infra)
	if len(list) != 2 || !(list[0].Expired || list[1].Expired) {
		t.Fatalf("%+v", list)
	}
	// Revoke: bob cannot (no share any more), carol cannot see it, alice can; twice is not found.
	if err := f.az.Revoke(ctx, bob, g.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoke without share: %v", err)
	}
	if err := f.az.Revoke(ctx, Subjects{TenantID: tB, UserID: uB}, g.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke cross-tenant: %v", err)
	}
	must(t, f.az.Revoke(ctx, alice, g.ID))
	if err := f.az.Revoke(ctx, alice, g.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke twice: %v", err)
	}
	f.aw.Flush()
	if n := len(f.ms.AuditEvents(tA, "grant_created")); n != 2 {
		t.Fatalf("grant_created %d", n)
	}
	if n := len(f.ms.AuditEvents(tA, "grant_revoked")); n != 1 {
		t.Fatalf("grant_revoked %d", n)
	}
	// Store failures surface from every path.
	f.ms.FailOn("UpsertGrant", errors.New("db"))
	if _, err := f.az.Grant(ctx, alice, GrantInput{ResourceType: Folder, ResourceID: f.infra, SubjectType: SubjectUser, SubjectID: uB, Relation: Viewer}); err == nil || errors.Is(err, ErrForbidden) {
		t.Fatal("upsert error")
	}
	f.ms.FailOn("UpsertGrant", nil)
	own := f.grant(t, Folder, f.databases, SubjectUser, uA, Owner, nil)
	f.ms.FailOn("GetFolder", errors.New("db"))
	if _, err := f.az.Grant(ctx, alice, GrantInput{ResourceType: Folder, ResourceID: f.infra, SubjectType: SubjectUser, SubjectID: uB, Relation: Viewer}); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("locate error")
	}
	if err := f.az.Revoke(ctx, alice, own.ID); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("revoke locate error")
	}
	f.ms.FailOn("GetFolder", nil)
	f.ms.FailOn("GrantsOnResources", errors.New("db"))
	if _, err := f.az.ListGrants(ctx, alice, Folder, f.infra); err == nil {
		t.Fatal("list eval error")
	}
	if _, err := f.az.Effective(ctx, alice, Folder, f.infra); err == nil {
		t.Fatal("effective eval error")
	}
	if err := f.az.Revoke(ctx, alice, own.ID); err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrForbidden) {
		t.Fatal("revoke eval error")
	}
	f.ms.FailOn("GrantsOnResources", nil)
	// The listing query failing after a successful evaluation.
	calls := 0
	az2 := New(&failSecond{Store: f.ms, calls: &calls}, nil)
	az2.SetClock(func() time.Time { return f.now })
	if _, err := az2.ListGrants(ctx, alice, Folder, f.infra); err == nil {
		t.Fatal("list query error")
	}
	f.ms.FailOn("DeleteGrant", errors.New("db"))
	if err := f.az.Revoke(ctx, alice, own.ID); err == nil {
		t.Fatal("delete error")
	}
	f.ms.FailOn("DeleteGrant", nil)
	f.ms.FailOn("GetGrant", errors.New("db"))
	if err := f.az.Revoke(ctx, alice, own.ID); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("get grant error")
	}
	f.ms.FailOn("GetGrant", nil)
}

func TestAccessibleResources(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	alice := Subjects{TenantID: tA, UserID: uA, Roles: []string{"member"}}
	if _, _, err := f.az.AccessibleResources(ctx, alice, "x", "", 10); !errors.Is(err, ErrInput) {
		t.Fatal("bad permission")
	}
	all, next, err := f.az.AccessibleResources(ctx, alice, Read, "", 10)
	if err != nil || len(all) != 0 || next != "" {
		t.Fatalf("%v %q %v", all, next, err)
	}
	// Viewer on Infra (role) expands to 3 folders + the deep secret; owner on the loose secret directly.
	f.grant(t, Folder, f.infra, SubjectRole, "member", Viewer, nil)
	f.grant(t, Secret, f.loose, SubjectUser, uA, Owner, nil)
	// Editor directly on Prod: strongest relation wins for Prod and the secret below it.
	f.grant(t, Folder, f.prod, SubjectUser, uA, Editor, nil)
	// A write-only-irrelevant grant (viewer) elsewhere does not appear for write.
	all, next, err = f.az.AccessibleResources(ctx, alice, Read, "", 100)
	if err != nil || len(all) != 5 || next != "" {
		t.Fatalf("%d %q %v", len(all), next, err)
	}
	byID := map[string]Accessible{}
	for _, a := range all {
		byID[a.ResourceID] = a
	}
	if byID[f.infra].Relation != Viewer || byID[f.infra].Source.Inherited || byID[f.databases].Relation != Viewer || !byID[f.databases].Source.Inherited {
		t.Fatalf("%+v", byID)
	}
	if byID[f.prod].Relation != Editor || byID[f.prod].Source.Inherited || byID[f.db].Relation != Editor || !byID[f.db].Source.Inherited || byID[f.db].Path != "/Infra/Databases/Prod" {
		t.Fatalf("%+v", byID)
	}
	if byID[f.loose].Relation != Owner || byID[f.loose].Source.Inherited || byID[f.loose].ResourceType != Secret {
		t.Fatalf("%+v", byID[f.loose])
	}
	// Write: only Prod, its secret and the loose secret.
	w, _, _ := f.az.AccessibleResources(ctx, alice, Write, "", 100)
	if len(w) != 3 {
		t.Fatalf("write %d", len(w))
	}
	// Paging: 2 + 2 + 1 with opaque cursors; sorted by path then folder-before-secret then name.
	p1, c1, _ := f.az.AccessibleResources(ctx, alice, Read, "", 2)
	p2, c2, _ := f.az.AccessibleResources(ctx, alice, Read, c1, 2)
	p3, c3, _ := f.az.AccessibleResources(ctx, alice, Read, c2, 2)
	if len(p1) != 2 || len(p2) != 2 || len(p3) != 1 || c1 == "" || c2 == "" || c3 != "" {
		t.Fatalf("paging %d %d %d %q %q %q", len(p1), len(p2), len(p3), c1, c2, c3)
	}
	if p1[0].ResourceID != f.loose && p1[0].Path != "" {
		t.Fatalf("order: %+v", p1)
	}
	// Default limit for out-of-range values; unknown cursor starts over.
	d, _, _ := f.az.AccessibleResources(ctx, alice, Read, "nope", 1000)
	if len(d) != 5 {
		t.Fatalf("default limit %d", len(d))
	}
	// Store failures.
	for _, op := range []string{"GrantsForSubjects", "FolderSubtree", "SecretsInFolders", "SecretsByIDs"} {
		f.ms.FailOn(op, errors.New("db"))
		if _, _, err := f.az.AccessibleResources(ctx, alice, Read, "", 10); err == nil {
			t.Fatalf("%s error swallowed", op)
		}
		f.ms.FailOn(op, nil)
	}
	// Root secrets: equal paths sort by name, then equal names by id.
	twin, other := store.NewID(), store.NewID()
	must(t, f.ms.InsertSecret(ctx, store.Secret{ID: twin, TenantID: tA, Name: "loose", VaultPath: "p"}))
	must(t, f.ms.InsertSecret(ctx, store.Secret{ID: other, TenantID: tA, Name: "aaa", VaultPath: "p"}))
	f.grant(t, Secret, twin, SubjectUser, uA, Viewer, nil)
	f.grant(t, Secret, other, SubjectUser, uA, Viewer, nil)
	all, _, _ = f.az.AccessibleResources(ctx, alice, Read, "", 100)
	if len(all) != 7 || all[0].ResourceID != other || all[1].ResourceID > all[2].ResourceID {
		t.Fatalf("tie order %+v", all[:3])
	}
}

// failSecond fails the second GrantsOnResources call (the listing after evaluation).
type failSecond struct {
	*memstore.Store
	calls *int
}

func (f *failSecond) GrantsOnResources(ctx context.Context, tid string, ids []string) ([]store.Grant, error) {
	*f.calls++
	if *f.calls == 2 {
		return nil, errors.New("db")
	}
	return f.Store.GrantsOnResources(ctx, tid, ids)
}
