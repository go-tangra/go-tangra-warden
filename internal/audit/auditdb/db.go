// Package auditdb binds the audit package to the database; covered by the
// tagged integration suite.
package auditdb

import (
	"context"
	"time"

	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
	"github.com/jackc/pgx/v5"
)

// DBQuerier reads from the database under the tenant scope.
type DBQuerier struct{ St *store.Store }

// QueryAudit implements audit.Querier.
func (d DBQuerier) QueryAudit(ctx context.Context, tid, et, actor string, from, to, cursor time.Time, limit int) (out []store.AuditRow, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error {
		out, err = store.QueryAudit(ctx, tx, tid, et, actor, from, to, cursor, limit)
		return err
	})
	return
}
