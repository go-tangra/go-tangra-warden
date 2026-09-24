// Package repodb binds repo.Store to the database: every call runs in a
// tenant-scoped transaction (RLS), system-scope calls in a system
// transaction. Covered by the tagged integration suite.
package repodb

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-warden/v4/internal/repo"
	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
)

// DB implements repo.Store over *store.Store.
type DB struct {
	St *store.Store
	tx pgx.Tx // set inside Atomic
}

// New wraps the store.
func New(st *store.Store) *DB { return &DB{St: st} }

func (d *DB) run(ctx context.Context, scope store.Scope, fn func(tx pgx.Tx) error) error {
	if d.tx != nil {
		return fn(d.tx)
	}
	return d.St.Tx(ctx, scope, fn)
}

func (d *DB) tenant(ctx context.Context, tid string, fn func(tx pgx.Tx) error) error {
	return d.run(ctx, store.Scope{TenantID: tid}, fn)
}

func (d *DB) system(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return d.run(ctx, store.Scope{System: true}, fn)
}

// Atomic runs fn in one tenant transaction.
func (d *DB) Atomic(ctx context.Context, tenantID string, fn func(repo.Store) error) error {
	if d.tx != nil {
		return fn(d)
	}
	return d.St.Tx(ctx, store.Scope{TenantID: tenantID}, func(tx pgx.Tx) error { return fn(&DB{St: d.St, tx: tx}) })
}

// ---- folders

func (d *DB) InsertFolder(ctx context.Context, f store.Folder) error {
	return d.tenant(ctx, f.TenantID, func(tx pgx.Tx) error { return store.InsertFolder(ctx, tx, f) })
}
func (d *DB) GetFolder(ctx context.Context, tid, id string) (out store.Folder, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.GetFolder(ctx, tx, tid, id); return err })
	return
}
func (d *DB) FolderChildren(ctx context.Context, tid string, parent *string) (out []store.Folder, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.FolderChildren(ctx, tx, tid, parent); return err })
	return
}
func (d *DB) AllFolders(ctx context.Context, tid string, limit int) (out []store.Folder, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.AllFolders(ctx, tx, tid, limit); return err })
	return
}
func (d *DB) FolderSubtree(ctx context.Context, tid, id string) (out []store.Folder, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.FolderSubtree(ctx, tx, tid, id); return err })
	return
}
func (d *DB) RenameFolder(ctx context.Context, tid, id, name, by string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.RenameFolder(ctx, tx, tid, id, name, by) })
}
func (d *DB) MoveFolder(ctx context.Context, tid, id string, parent *string, anc []string, path, by string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.MoveFolder(ctx, tx, tid, id, parent, anc, path, by) })
}
func (d *DB) DeleteFolder(ctx context.Context, tid, id string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.DeleteFolder(ctx, tx, tid, id) })
}
func (d *DB) CountFolderContents(ctx context.Context, tid, id string) (f, s int, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { f, s, err = store.CountFolderContents(ctx, tx, tid, id); return err })
	return
}

// ---- secrets

func (d *DB) InsertSecret(ctx context.Context, s store.Secret) error {
	return d.tenant(ctx, s.TenantID, func(tx pgx.Tx) error { return store.InsertSecret(ctx, tx, s) })
}
func (d *DB) GetSecret(ctx context.Context, tid, id string) (out store.Secret, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.GetSecret(ctx, tx, tid, id); return err })
	return
}
func (d *DB) SecretsInFolder(ctx context.Context, tid string, folder *string, afterName, afterID string, limit int) (out []store.Secret, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error {
		out, err = store.SecretsInFolder(ctx, tx, tid, folder, afterName, afterID, limit)
		return err
	})
	return
}
func (d *DB) SecretsByIDs(ctx context.Context, tid string, ids []string) (out []store.Secret, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.SecretsByIDs(ctx, tx, tid, ids); return err })
	return
}
func (d *DB) SecretsInFolders(ctx context.Context, tid string, ids []string) (out []store.Secret, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.SecretsInFolders(ctx, tx, tid, ids); return err })
	return
}
func (d *DB) AllSecrets(ctx context.Context, tid string, limit int) (out []store.Secret, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.AllSecrets(ctx, tx, tid, limit); return err })
	return
}
func (d *DB) SearchSecrets(ctx context.Context, tid, q string, sids, fids []string, root bool, limit int) (out []store.Secret, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error {
		out, err = store.SearchSecrets(ctx, tx, tid, q, sids, fids, root, limit)
		return err
	})
	return
}
func (d *DB) UpdateSecret(ctx context.Context, s store.Secret) error {
	return d.tenant(ctx, s.TenantID, func(tx pgx.Tx) error { return store.UpdateSecret(ctx, tx, s) })
}
func (d *DB) SetSecretVersion(ctx context.Context, tid, id string, v int, by *string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.SetSecretVersion(ctx, tx, tid, id, v, by) })
}
func (d *DB) SetSecretTOTP(ctx context.Context, tid, id string, has bool, by *string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.SetSecretTOTP(ctx, tx, tid, id, has, by) })
}
func (d *DB) MoveSecret(ctx context.Context, tid, id string, folder *string, by *string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.MoveSecret(ctx, tx, tid, id, folder, by) })
}
func (d *DB) SoftDeleteSecret(ctx context.Context, tid, id string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.SoftDeleteSecret(ctx, tx, tid, id) })
}
func (d *DB) HardDeleteSecret(ctx context.Context, tid, id string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.HardDeleteSecret(ctx, tx, tid, id) })
}
func (d *DB) SoftDeletedSecrets(ctx context.Context, tid string) (out []store.Secret, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.SoftDeletedSecrets(ctx, tx, tid); return err })
	return
}
func (d *DB) RecentSecrets(ctx context.Context, since time.Time, limit int) (out []store.Secret, err error) {
	err = d.system(ctx, func(tx pgx.Tx) error { out, err = store.RecentSecrets(ctx, tx, since, limit); return err })
	return
}
func (d *DB) PendingSecrets(ctx context.Context, olderThan time.Time, limit int) (out []store.Secret, err error) {
	err = d.system(ctx, func(tx pgx.Tx) error { out, err = store.PendingSecrets(ctx, tx, olderThan, limit); return err })
	return
}
func (d *DB) InsertVersion(ctx context.Context, v store.SecretVersion) error {
	return d.tenant(ctx, v.TenantID, func(tx pgx.Tx) error { return store.InsertVersion(ctx, tx, v) })
}
func (d *DB) VersionsOf(ctx context.Context, tid, sid string) (out []store.SecretVersion, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.VersionsOf(ctx, tx, tid, sid); return err })
	return
}
func (d *DB) GetVersion(ctx context.Context, tid, sid string, v int) (out store.SecretVersion, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.GetVersion(ctx, tx, tid, sid, v); return err })
	return
}

// ---- grants

func (d *DB) UpsertGrant(ctx context.Context, g store.Grant) (out store.Grant, err error) {
	err = d.tenant(ctx, g.TenantID, func(tx pgx.Tx) error { out, err = store.UpsertGrant(ctx, tx, g); return err })
	return
}
func (d *DB) GetGrant(ctx context.Context, tid, id string) (out store.Grant, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.GetGrant(ctx, tx, tid, id); return err })
	return
}
func (d *DB) DeleteGrant(ctx context.Context, tid, id string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.DeleteGrant(ctx, tx, tid, id) })
}
func (d *DB) GrantsOnResources(ctx context.Context, tid string, ids []string) (out []store.Grant, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.GrantsOnResources(ctx, tx, tid, ids); return err })
	return
}
func (d *DB) GrantsForSubjects(ctx context.Context, tid, uid string, roles []string, now time.Time) (out []store.Grant, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error {
		out, err = store.GrantsForSubjects(ctx, tx, tid, uid, roles, now)
		return err
	})
	return
}
func (d *DB) DeleteGrantsOfResource(ctx context.Context, tid, rtype, rid string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.DeleteGrantsOfResource(ctx, tx, tid, rtype, rid) })
}

// ---- shares

func (d *DB) InsertShare(ctx context.Context, s store.Share) error {
	return d.tenant(ctx, s.TenantID, func(tx pgx.Tx) error { return store.InsertShare(ctx, tx, s) })
}
func (d *DB) ShareByTokenHash(ctx context.Context, hash string) (out store.Share, err error) {
	err = d.system(ctx, func(tx pgx.Tx) error { out, err = store.ShareByTokenHash(ctx, tx, hash); return err })
	return
}
func (d *DB) GetShare(ctx context.Context, tid, id string) (out store.Share, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.GetShare(ctx, tx, tid, id); return err })
	return
}
func (d *DB) SharesOfSecret(ctx context.Context, tid, sid, by string) (out []store.Share, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.SharesOfSecret(ctx, tx, tid, sid, by); return err })
	return
}
func (d *DB) ConsumeShareOpen(ctx context.Context, id string) (out store.Share, err error) {
	err = d.system(ctx, func(tx pgx.Tx) error { out, err = store.ConsumeShareOpen(ctx, tx, id); return err })
	return
}
func (d *DB) SetShareState(ctx context.Context, tid, id, state string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.SetShareState(ctx, tx, tid, id, state) })
}
func (d *DB) ExpireShares(ctx context.Context, now time.Time) (n int64, err error) {
	err = d.system(ctx, func(tx pgx.Tx) error { n, err = store.ExpireShares(ctx, tx, now); return err })
	return
}

// ---- audit & stats

func (d *DB) InsertAuditRows(ctx context.Context, rows []store.AuditRow) error {
	return d.system(ctx, func(tx pgx.Tx) error { return store.InsertAuditRows(ctx, tx, rows) })
}
func (d *DB) QueryAudit(ctx context.Context, tid, et, actor string, from, to, cursor time.Time, limit int) (out []store.AuditRow, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error {
		out, err = store.QueryAudit(ctx, tx, tid, et, actor, from, to, cursor, limit)
		return err
	})
	return
}
func (d *DB) TenantStats(ctx context.Context, tid string, now time.Time) (out store.Stats, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.TenantStats(ctx, tx, tid, now); return err })
	return
}

var _ repo.Store = (*DB)(nil)
