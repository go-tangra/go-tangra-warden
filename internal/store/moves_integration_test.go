//go:build integration

package store

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestMoveTargetsAndFolderCounts: a move to a folder that is missing, of
// another tenant or malformed updates nothing and is ErrNotFound; the
// composite FKs of 0007 refuse a cross-tenant folder even to a superuser;
// the per-folder count is of live secrets only.
func TestMoveTargetsAndFolderCounts(t *testing.T) {
	adminDSN, appDSN := startDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	st, err := Open(ctx, appDSN, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	by := uA
	fa, fa2, fb, sec, gone := NewID(), NewID(), NewID(), NewID(), NewID()
	inTenant := func(tid string, fn func(tx pgx.Tx) error) error { return st.Tx(ctx, Scope{TenantID: tid}, fn) }
	if err := inTenant(tA, func(tx pgx.Tx) error {
		if err := InsertFolder(ctx, tx, Folder{ID: fa, TenantID: tA, Name: "Infra", Path: "/Infra", CreatedBy: &by}); err != nil {
			return err
		}
		if err := InsertFolder(ctx, tx, Folder{ID: fa2, TenantID: tA, Name: "Apps", Path: "/Apps", CreatedBy: &by}); err != nil {
			return err
		}
		if err := InsertSecret(ctx, tx, Secret{ID: sec, TenantID: tA, FolderID: &fa, Name: "db", VaultPath: "p", CurrentVersion: 1, CreatedBy: &by}); err != nil {
			return err
		}
		if err := InsertSecret(ctx, tx, Secret{ID: gone, TenantID: tA, FolderID: &fa, Name: "gone", VaultPath: "p", CurrentVersion: 1, CreatedBy: &by}); err != nil {
			return err
		}
		return SoftDeleteSecret(ctx, tx, tA, gone)
	}); err != nil {
		t.Fatal(err)
	}
	if err := inTenant(tB, func(tx pgx.Tx) error {
		return InsertFolder(ctx, tx, Folder{ID: fb, TenantID: tB, Name: "Foreign", Path: "/Foreign", CreatedBy: &by})
	}); err != nil {
		t.Fatal(err)
	}
	missing, malformed := NewID(), "not-a-uuid"
	for _, target := range []string{fb, missing, malformed} {
		target := target
		err := inTenant(tA, func(tx pgx.Tx) error { return MoveSecret(ctx, tx, tA, sec, &target, &by) })
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("move secret to %s: %v", target, err)
		}
		err = inTenant(tA, func(tx pgx.Tx) error { return MoveFolder(ctx, tx, tA, fa2, &target, []string{target}, "/x/Apps", by) })
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("move folder to %s: %v", target, err)
		}
	}
	if err := inTenant(tA, func(tx pgx.Tx) error {
		s, err := GetSecret(ctx, tx, tA, sec)
		if err != nil || s.FolderID == nil || *s.FolderID != fa {
			t.Fatalf("refused moves changed the secret: %+v %v", s.FolderID, err)
		}
		f, err := GetFolder(ctx, tx, tA, fa2)
		if err != nil || f.ParentID != nil || f.Path != "/Apps" {
			t.Fatalf("refused moves changed the folder: %+v %v", f, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A valid move still works.
	if err := inTenant(tA, func(tx pgx.Tx) error { return MoveSecret(ctx, tx, tA, sec, &fa2, &by) }); err != nil {
		t.Fatal(err)
	}
	if err := inTenant(tA, func(tx pgx.Tx) error { return MoveSecret(ctx, tx, tA, sec, &fa, &by) }); err != nil {
		t.Fatal(err)
	}
	// The database itself refuses a cross-tenant reference (superuser, no RLS).
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	for _, q := range []string{"UPDATE secrets SET folder_id = $1 WHERE id = $2", "UPDATE folders SET parent_id = $1 WHERE id = $2"} {
		id := sec
		if q[7] == 'f' {
			id = fa2
		}
		_, err := admin.Exec(ctx, q, fb, id)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "23503" {
			t.Fatalf("%s: want a foreign-key violation, got %v", q, err)
		}
	}
	// Counts: live secrets only, per folder.
	if err := inTenant(tA, func(tx pgx.Tx) error {
		counts, err := FolderSecretCounts(ctx, tx, tA)
		if err != nil || len(counts) != 1 || counts[fa] != 1 {
			t.Fatalf("counts %v %v", counts, err)
		}
		_, n, err := CountFolderContents(ctx, tx, tA, fa)
		if err != nil || n != 1 {
			t.Fatalf("contents %d %v", n, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := inTenant(tB, func(tx pgx.Tx) error {
		counts, err := FolderSecretCounts(ctx, tx, tB)
		if err != nil || len(counts) != 0 {
			t.Fatalf("foreign counts %v %v", counts, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
