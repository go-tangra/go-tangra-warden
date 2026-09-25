//go:build integration

package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func startDB(t *testing.T) (adminDSN, appDSN string) {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: "timescale/timescaledb:latest-pg16", ExposedPorts: []string{"5432/tcp"},
			Env:        map[string]string{"POSTGRES_PASSWORD": "test", "POSTGRES_DB": "warden"},
			WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
		}, Started: true,
	})
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	host, _ := c.Host(ctx)
	port, _ := c.MappedPort(ctx, "5432/tcp")
	adminDSN = "postgres://postgres:test@" + host + ":" + port.Port() + "/warden?sslmode=disable"
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Exec(ctx, "CREATE ROLE warden_app LOGIN PASSWORD 'app' NOBYPASSRLS")
	_ = conn.Close(ctx)
	appDSN = "postgres://warden_app:app@" + host + ":" + port.Port() + "/warden?sslmode=disable"
	return
}

const (
	tA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	tB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
	uA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"
)

func TestMigrateSchemaAndRLS(t *testing.T) {
	adminDSN, appDSN := startDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, adminDSN); err != nil { // idempotent
		t.Fatal(err)
	}
	admin, _ := pgx.Connect(ctx, adminDSN)
	defer admin.Close(ctx)
	var n int
	_ = admin.QueryRow(ctx, "SELECT count(*) FROM timescaledb_information.hypertables WHERE hypertable_name = 'warden_audit_events'").Scan(&n)
	if n != 1 {
		t.Fatalf("hypertables %d", n)
	}
	_ = admin.QueryRow(ctx, "SELECT count(*) FROM timescaledb_information.jobs WHERE proc_name = 'policy_retention' AND hypertable_name = 'warden_audit_events'").Scan(&n)
	if n != 1 {
		t.Fatalf("retention policies %d", n)
	}
	_ = admin.QueryRow(ctx, "SELECT count(*) FROM pg_policies WHERE policyname = 'tenant_isolation'").Scan(&n)
	if n != 6 {
		t.Fatalf("policies %d", n)
	}
	_ = admin.QueryRow(ctx, "SELECT count(*) FROM pg_extension WHERE extname = 'pg_trgm'").Scan(&n)
	if n != 1 {
		t.Fatal("pg_trgm missing")
	}
	_ = admin.QueryRow(ctx, "SELECT count(*) FROM pg_indexes WHERE indexname = 'secrets_search' AND indexdef LIKE '%gin_trgm_ops%'").Scan(&n)
	if n != 1 {
		t.Fatal("trigram index missing")
	}
	// The app role may not update or delete audit rows.
	var upd, del bool
	_ = admin.QueryRow(ctx, "SELECT has_table_privilege('warden_app', 'warden_audit_events', 'UPDATE'), has_table_privilege('warden_app', 'warden_audit_events', 'DELETE')").Scan(&upd, &del)
	if upd || del {
		t.Fatal("app role may alter audit rows")
	}

	st, err := Open(ctx, appDSN, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	fA, fB, s1, s2 := NewID(), NewID(), NewID(), NewID()
	by := uA
	// Tenant A: a folder tree, a secret, versions, a grant and a share.
	if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
		if err := InsertFolder(ctx, tx, Folder{ID: fA, TenantID: tA, Name: "Infra", Path: "/Infra", CreatedBy: &by}); err != nil {
			return err
		}
		if err := InsertFolder(ctx, tx, Folder{ID: fB, TenantID: tA, ParentID: &fA, Name: "Prod", Path: "/Infra/Prod", Ancestors: []string{fA}, CreatedBy: &by}); err != nil {
			return err
		}
		if err := InsertSecret(ctx, tx, Secret{ID: s1, TenantID: tA, FolderID: &fB, Name: "DB admin", Username: "root", HostURL: "https://db.example.org", Description: "Primary", VaultPath: tA + "/secrets/" + s1, CreatedBy: &by}); err != nil {
			return err
		}
		if err := InsertSecret(ctx, tx, Secret{ID: s2, TenantID: tA, Name: "Root secret", VaultPath: tA + "/secrets/" + s2, CreatedBy: &by}); err != nil {
			return err
		}
		for v := 1; v <= 2; v++ {
			if err := InsertVersion(ctx, tx, SecretVersion{SecretID: s1, TenantID: tA, Version: v, Checksum: "c", Source: "api", CreatedBy: &by}); err != nil {
				return err
			}
		}
		if err := SetSecretVersion(ctx, tx, tA, s1, 2, &by); err != nil {
			return err
		}
		g, err := UpsertGrant(ctx, tx, Grant{ID: NewID(), TenantID: tA, ResourceType: "folder", ResourceID: fA, SubjectType: "user", SubjectID: uA, Relation: "viewer", GrantedBy: &by})
		if err != nil {
			return err
		}
		// Same key replaces the relation and keeps the id.
		g2, err := UpsertGrant(ctx, tx, Grant{ID: NewID(), TenantID: tA, ResourceType: "folder", ResourceID: fA, SubjectType: "user", SubjectID: uA, Relation: "owner", GrantedBy: &by})
		if err != nil || g2.ID != g.ID || g2.Relation != "owner" {
			return errors.New("grant upsert did not replace")
		}
		return InsertShare(ctx, tx, Share{ID: NewID(), TenantID: tA, SecretID: s1, TokenHash: "h1", RecipientEmail: "r@example.org", MaxOpens: 1, ExpiresAt: time.Now().Add(time.Hour), CreatedBy: uA})
	}); err != nil {
		t.Fatal(err)
	}
	// Case-insensitive sibling uniqueness at the root and below (each violation aborts its transaction).
	for _, f := range []Folder{{ID: NewID(), TenantID: tA, Name: "infra", Path: "/infra"}, {ID: NewID(), TenantID: tA, ParentID: &fA, Name: "PROD", Path: "/Infra/PROD", Ancestors: []string{fA}}} {
		f := f
		if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error { return InsertFolder(ctx, tx, f) }); !errors.Is(err, ErrConflict) {
			t.Fatalf("duplicate %s accepted: %v", f.Name, err)
		}
	}
	// Generated search column and folder path join.
	if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
		got, err := SearchSecrets(ctx, tx, tA, "example.org", []string{s1}, nil, false, 10)
		if err != nil || len(got) != 1 || got[0].FolderPath != "/Infra/Prod" || got[0].CurrentVersion != 2 {
			return errors.New("search by host: " + errString(err))
		}
		got, err = SearchSecrets(ctx, tx, tA, "prod", nil, []string{fB}, false, 10)
		if err != nil || len(got) != 1 {
			return errors.New("search by folder path")
		}
		got, err = SearchSecrets(ctx, tx, tA, "root", nil, nil, true, 10)
		if err != nil || len(got) != 1 || got[0].ID != s2 {
			return errors.New("root search")
		}
		page, err := SecretsInFolder(ctx, tx, tA, &fB, "", "", 10)
		if err != nil || len(page) != 1 {
			return errors.New("secrets in folder")
		}
		sub, err := FolderSubtree(ctx, tx, tA, fA)
		if err != nil || len(sub) != 2 {
			return errors.New("subtree")
		}
		vs, err := VersionsOf(ctx, tx, tA, s1)
		if err != nil || len(vs) != 2 || vs[0].Version != 2 {
			return errors.New("versions")
		}
		st, err := TenantStats(ctx, tx, tA, time.Now())
		if err != nil || st.Secrets != 2 || st.Folders != 2 || st.Versions != 2 || st.Grants["owner"] != 1 || st.Shares["active"] != 1 {
			return errors.New("stats")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Tenant B sees nothing of tenant A, cannot write into it, and the folder ids are invisible.
	if err := st.Tx(ctx, Scope{TenantID: tB}, func(tx pgx.Tx) error {
		if _, err := GetFolder(ctx, tx, tB, fA); !errors.Is(err, ErrNotFound) {
			return errors.New("cross-tenant folder visible")
		}
		if _, err := GetSecret(ctx, tx, tB, s1); !errors.Is(err, ErrNotFound) {
			return errors.New("cross-tenant secret visible")
		}
		all, err := AllFolders(ctx, tx, tB, 100)
		if err != nil || len(all) != 0 {
			return errors.New("cross-tenant listing")
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM secrets").Scan(&n); err != nil || n != 0 {
			return errors.New("rls leak on raw select")
		}
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM shares").Scan(&n); err != nil || n != 0 {
			return errors.New("rls leak on shares")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Tx(ctx, Scope{TenantID: tB}, func(tx pgx.Tx) error {
		return InsertFolder(ctx, tx, Folder{ID: NewID(), TenantID: tA, Name: "Evil", Path: "/Evil"})
	}); err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Fatalf("write into another tenant: %v", err)
	}
	// System scope reaches shares by token hash and audit rows.
	if err := st.Tx(ctx, Scope{System: true}, func(tx pgx.Tx) error {
		sh, err := ShareByTokenHash(ctx, tx, "h1")
		if err != nil || sh.TenantID != tA {
			return errors.New("share by hash: " + errString(err))
		}
		opened, err := ConsumeShareOpen(ctx, tx, sh.ID)
		if err != nil || opened.Opens != 1 || opened.State != "consumed" {
			return errors.New("consume")
		}
		if _, err := ConsumeShareOpen(ctx, tx, sh.ID); !errors.Is(err, ErrNotFound) {
			return errors.New("consumed share reopened")
		}
		return InsertAuditRows(ctx, tx, []AuditRow{
			{TS: time.Now(), TenantID: tA, EventType: "secret_created", ActorKind: "user", ActorID: uA, SubjectKind: "secret", SubjectID: s1, Outcome: "ok", Details: []byte(`{"version":1}`)},
			{TS: time.Now().Add(-time.Second), TenantID: tA, EventType: "folder_created", ActorKind: "user", ActorID: uA, SubjectKind: "folder", SubjectID: fB, Outcome: "ok"},
			{TS: time.Now().Add(-2 * time.Second), TenantID: tA, EventType: "access_refused", ActorKind: "user", ActorID: uA, SubjectKind: "secret", SubjectID: "not-a-uuid", Outcome: "refused"},
			{TS: time.Now().Add(-3 * time.Second), TenantID: tA, EventType: "share_created", ActorKind: "user", ActorID: uA, SubjectKind: "share", SubjectID: NewID(), Outcome: "ok", Details: []byte(`{"secret_id":"` + s1 + `"}`)},
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
		rows, err := QueryAudit(ctx, tx, tA, "", "", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), time.Time{}, 10)
		if err != nil || len(rows) != 4 || rows[0].EventType != "secret_created" {
			return errors.New("audit query: " + errString(err))
		}
		// Subjects resolve to the secret name / folder path / shared secret; malformed ids stay unresolved.
		if rows[0].SubjectName != "DB admin" || rows[1].SubjectName != "/Infra/Prod" || rows[2].SubjectName != "" || rows[3].SubjectName != "DB admin" {
			return errors.New("audit subject names: " + rows[0].SubjectName + " " + rows[1].SubjectName + " " + rows[2].SubjectName + " " + rows[3].SubjectName)
		}
		// Rename and move keep the subtree consistent; delete is restricted while secrets exist.
		if err := RenameFolder(ctx, tx, tA, fA, "Infrastructure", uA); err != nil {
			return err
		}
		f, err := GetFolder(ctx, tx, tA, fB)
		if err != nil || f.Path != "/Infrastructure/Prod" {
			return errors.New("child path after rename: " + f.Path)
		}
		if err := MoveFolder(ctx, tx, tA, fB, nil, nil, "/Prod", uA); err != nil {
			return err
		}
		f, _ = GetFolder(ctx, tx, tA, fB)
		if f.ParentID != nil || len(f.Ancestors) != 0 || f.Path != "/Prod" {
			return errors.New("move")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error { return DeleteFolder(ctx, tx, tA, fB) }); err == nil || !strings.Contains(err.Error(), "foreign key") {
		t.Fatalf("folder with secrets deleted: %v", err)
	}
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// TestInsertKeepsGivenTimestamps: a migration passes the original times and
// authors; zero values still mean now() and the creator.
func TestInsertKeepsGivenTimestamps(t *testing.T) {
	adminDSN, appDSN := startDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	st, err := Open(ctx, appDSN, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	created := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
	updated := created.Add(48 * time.Hour)
	by, other := uA, "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c88"
	f1, f2, s1, s2 := NewID(), NewID(), NewID(), NewID()
	var gOld, gNow Grant
	err = st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
		if err := InsertFolder(ctx, tx, Folder{ID: f1, TenantID: tA, Name: "Old", Path: "/Old", CreatedBy: &by, UpdatedBy: &other, CreatedAt: created, UpdatedAt: updated}); err != nil {
			return err
		}
		if err := InsertFolder(ctx, tx, Folder{ID: f2, TenantID: tA, Name: "New", Path: "/New", CreatedBy: &by}); err != nil {
			return err
		}
		if err := InsertSecret(ctx, tx, Secret{ID: s1, TenantID: tA, FolderID: &f1, Name: "old", VaultPath: "p1", CurrentVersion: 3, HasTOTP: true, CreatedBy: &by, UpdatedBy: &other, CreatedAt: created, UpdatedAt: updated}); err != nil {
			return err
		}
		if err := InsertSecret(ctx, tx, Secret{ID: s2, TenantID: tA, Name: "created-only", VaultPath: "p2", CreatedBy: &by, CreatedAt: created}); err != nil {
			return err
		}
		if err := InsertVersion(ctx, tx, SecretVersion{SecretID: s1, TenantID: tA, Version: 3, Checksum: "c", Source: "migration-v3", CreatedBy: &other, CreatedAt: updated}); err != nil {
			return err
		}
		if err := InsertVersion(ctx, tx, SecretVersion{SecretID: s1, TenantID: tA, Version: 4, Checksum: "c", Source: "api", CreatedBy: &by}); err != nil {
			return err
		}
		if gOld, err = UpsertGrant(ctx, tx, Grant{ID: NewID(), TenantID: tA, ResourceType: "folder", ResourceID: f1, SubjectType: "user", SubjectID: other, Relation: "viewer", GrantedBy: &by, GrantedAt: created}); err != nil {
			return err
		}
		gNow, err = UpsertGrant(ctx, tx, Grant{ID: NewID(), TenantID: tA, ResourceType: "folder", ResourceID: f2, SubjectType: "tenant", Relation: "viewer", GrantedBy: &by})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	recent := func(ts time.Time) bool { return time.Since(ts) < time.Minute }
	_ = st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
		old, _ := GetFolder(ctx, tx, tA, f1)
		if !old.CreatedAt.Equal(created) || !old.UpdatedAt.Equal(updated) || *old.CreatedBy != by || *old.UpdatedBy != other {
			t.Errorf("folder %+v", old)
		}
		nw, _ := GetFolder(ctx, tx, tA, f2)
		if !recent(nw.CreatedAt) || !recent(nw.UpdatedAt) || *nw.UpdatedBy != by {
			t.Errorf("folder defaults %+v", nw)
		}
		s, _ := GetSecret(ctx, tx, tA, s1)
		if !s.CreatedAt.Equal(created) || !s.UpdatedAt.Equal(updated) || *s.UpdatedBy != other || s.CurrentVersion != 3 || !s.HasTOTP {
			t.Errorf("secret %+v", s)
		}
		c, _ := GetSecret(ctx, tx, tA, s2)
		if !c.CreatedAt.Equal(created) || !c.UpdatedAt.Equal(created) || *c.UpdatedBy != by {
			t.Errorf("secret updated defaults to created: %+v", c)
		}
		v3, _ := GetVersion(ctx, tx, tA, s1, 3)
		v4, _ := GetVersion(ctx, tx, tA, s1, 4)
		if !v3.CreatedAt.Equal(updated) || *v3.CreatedBy != other || !recent(v4.CreatedAt) {
			t.Errorf("versions %+v %+v", v3, v4)
		}
		if !gOld.GrantedAt.Equal(created) || !recent(gNow.GrantedAt) {
			t.Errorf("grants %v %v", gOld.GrantedAt, gNow.GrantedAt)
		}
		// Re-granting without a time refreshes granted_at as before.
		g, err := UpsertGrant(ctx, tx, Grant{ID: NewID(), TenantID: tA, ResourceType: "folder", ResourceID: f1, SubjectType: "user", SubjectID: other, Relation: "editor", GrantedBy: &by})
		if err != nil || g.ID != gOld.ID || !recent(g.GrantedAt) {
			t.Errorf("regrant %+v %v", g, err)
		}
		return nil
	})
}
