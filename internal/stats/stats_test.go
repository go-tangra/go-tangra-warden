package stats

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-freya/freya/services/warden/internal/memstore"
	"github.com/go-freya/freya/services/warden/internal/store"
)

const tA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

func TestForTenant(t *testing.T) {
	ms := memstore.New()
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	ms.Now = func() time.Time { return now }
	fid := store.NewID()
	_ = ms.InsertFolder(ctx, store.Folder{ID: fid, TenantID: tA, Name: "F", Path: "/F"})
	s1, s2 := store.NewID(), store.NewID()
	_ = ms.InsertSecret(ctx, store.Secret{ID: s1, TenantID: tA, FolderID: &fid, Name: "a", VaultPath: "p", HasTOTP: true})
	_ = ms.InsertSecret(ctx, store.Secret{ID: s2, TenantID: tA, Name: "b", VaultPath: "p"})
	_ = ms.InsertVersion(ctx, store.SecretVersion{SecretID: s1, TenantID: tA, Version: 1})
	_ = ms.InsertVersion(ctx, store.SecretVersion{SecretID: s1, TenantID: tA, Version: 2})
	_, _ = ms.UpsertGrant(ctx, store.Grant{ID: store.NewID(), TenantID: tA, ResourceType: "secret", ResourceID: s1, SubjectType: "user", SubjectID: "u", Relation: "owner"})
	_, _ = ms.UpsertGrant(ctx, store.Grant{ID: store.NewID(), TenantID: tA, ResourceType: "folder", ResourceID: fid, SubjectType: "role", SubjectID: "r", Relation: "viewer"})
	_ = ms.InsertShare(ctx, store.Share{ID: store.NewID(), TenantID: tA, SecretID: s1, TokenHash: "h", RecipientEmail: "r@x", MaxOpens: 1, ExpiresAt: now.Add(time.Hour), CreatedBy: "u"})
	_ = ms.InsertAuditRows(ctx, []store.AuditRow{{TS: now.Add(-time.Hour), TenantID: tA, EventType: "secret_read"}, {TS: now.Add(-48 * time.Hour), TenantID: tA, EventType: "secret_read"}})
	// Another tenant's rows never count.
	_ = ms.InsertSecret(ctx, store.Secret{ID: store.NewID(), TenantID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66", Name: "z", VaultPath: "p"})
	svc := New(ms)
	svc.SetClock(func() time.Time { return now })
	v, err := svc.ForTenant(ctx, tA)
	if err != nil || v.Secrets != 2 || v.SecretsWithTOTP != 1 || v.Folders != 1 || v.Versions != 2 || v.Grants["owner"] != 1 || v.Grants["viewer"] != 1 || v.Shares["active"] != 1 || v.Operations24h != 1 {
		t.Fatalf("%+v %v", v, err)
	}
	empty, err := svc.ForTenant(ctx, "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77")
	if err != nil || empty.Secrets != 0 || empty.Grants == nil || empty.Shares == nil {
		t.Fatalf("%+v %v", empty, err)
	}
	ms.FailOn("TenantStats", errors.New("db"))
	if _, err := svc.ForTenant(ctx, tA); err == nil {
		t.Fatal("db error")
	}
	nilMaps := New(nilStats{})
	if v, err := nilMaps.ForTenant(ctx, tA); err != nil || v.Grants == nil || v.Shares == nil {
		t.Fatalf("%+v %v", v, err)
	}
}

type nilStats struct{}

func (nilStats) TenantStats(context.Context, string, time.Time) (store.Stats, error) {
	return store.Stats{}, nil
}
