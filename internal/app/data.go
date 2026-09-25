package app

import (
	"context"
	"log/slog"
	"os"

	"github.com/go-tangra/go-tangra-warden/v4/internal/audit"
	"github.com/go-tangra/go-tangra-warden/v4/internal/config"
	"github.com/go-tangra/go-tangra-warden/v4/internal/repo"
	"github.com/go-tangra/go-tangra-warden/v4/internal/repo/repodb"
	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
	"github.com/go-tangra/go-tangra-warden/v4/internal/vault"
)

// Data is the persistence, the material store and the audit writer without
// the runtime, the cache or any listener: one-off commands (import-v3) use
// it so they neither enroll, register nor serve.
type Data struct {
	Log   *slog.Logger
	Store *store.Store
	Repo  repo.Store
	Vault *vault.Client
	Audit *audit.Writer
}

// OpenData validates cfg, applies the migrations when asked and connects the
// database and the vault.
func OpenData(ctx context.Context, cfg config.Config, migrate bool) (*Data, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if migrate {
		dsn := cfg.DB.MigrateDSN
		if dsn == "" {
			dsn = cfg.DB.DSN
		}
		if err := store.Migrate(ctx, dsn); err != nil {
			return nil, err
		}
	}
	st, err := store.Open(ctx, cfg.DB.DSN, cfg.DB.MaxConns)
	if err != nil {
		return nil, err
	}
	v, err := openVault(ctx, cfg, log)
	if err != nil {
		st.Close()
		return nil, err
	}
	d := &Data{Log: log, Store: st, Repo: repodb.New(st), Vault: v}
	d.Audit = audit.NewWriter(d.Repo, func(err error) { log.Error("audit write failed", "err", err) })
	return d, nil
}

// Close flushes the audit writer and releases the connections.
func (d *Data) Close() {
	d.Audit.Close()
	d.Vault.Close()
	d.Store.Close()
}
