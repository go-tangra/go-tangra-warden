package repodb

import (
	"context"

	"github.com/go-tangra/go-tangra/v4/listquery"
	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
)

// List-contract pages (go-tangra specs/032-server-side-tables): count and
// page run in one tenant transaction (RLS).

// PageSecretsInFolder implements repo.Store.
func (d *DB) PageSecretsInFolder(ctx context.Context, tid string, folder *string, scope store.SecretScope, req listquery.Request) (out []store.Secret, total int, applied listquery.Request, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error {
		var e error
		out, total, applied, e = store.PageSecretsInFolder(ctx, tx, tid, folder, scope, req)
		return e
	})
	return
}

// PageSearchSecrets implements repo.Store.
func (d *DB) PageSearchSecrets(ctx context.Context, tid, q string, scope store.SecretScope, req listquery.Request) (out []store.Secret, total int, applied listquery.Request, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error {
		var e error
		out, total, applied, e = store.PageSearchSecrets(ctx, tx, tid, q, scope, req)
		return e
	})
	return
}

// PageSharesOfSecret implements repo.Store.
func (d *DB) PageSharesOfSecret(ctx context.Context, tid, sid, by string, req listquery.Request) (out []store.Share, total int, applied listquery.Request, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error {
		var e error
		out, total, applied, e = store.PageSharesOfSecret(ctx, tx, tid, sid, by, req)
		return e
	})
	return
}

// PageAudit implements repo.Store.
func (d *DB) PageAudit(ctx context.Context, tid string, f store.AuditQuery, req listquery.Request) (out []store.AuditRow, total int, applied listquery.Request, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error {
		var e error
		out, total, applied, e = store.PageAudit(ctx, tx, tid, f, req)
		return e
	})
	return
}
