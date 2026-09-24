package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra-warden/v4/internal/app"
	"github.com/go-tangra/go-tangra-warden/v4/internal/config"
	"github.com/go-tangra/go-tangra-warden/v4/internal/vault"
)

// bootstrap prepares a deployment: migrations, a vault access check (AppRole
// login and a KV round trip on a probe path) and the dependency health. It is
// idempotent and never serves.
func bootstrap(args []string) int {
	fs := flag.NewFlagSet("wardensvc bootstrap", flag.ContinueOnError)
	cfgPath := fs.String("config", "deploy/dev.yaml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cfg.Server.GRPCAddr, cfg.Admin.Addr = "127.0.0.1:0", "127.0.0.1:0"
	if cfg.Server.HTTPAddr != "" {
		cfg.Server.HTTPAddr = "127.0.0.1:0"
	}
	a, err := app.Build(ctx, cfg, app.Options{Migrate: true, Verifier: noVerifier{}})
	if err != nil {
		return fail(err)
	}
	defer a.Close()
	res := struct {
		Migrated bool       `json:"migrated"`
		Health   app.Health `json:"health"`
		Probe    string     `json:"vault_probe"`
	}{Migrated: true, Health: a.Health(ctx), Probe: "ok"}
	if err := probeVault(ctx, a.Vault); err != nil {
		res.Probe = err.Error()
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
	if res.Health.DB != "ok" || res.Health.Vault != vault.HealthOK || res.Probe != "ok" {
		return 1
	}
	return 0
}

// probeVault writes, reads and destroys a probe secret under a reserved
// tenant id so misconfigured policies surface before the first user does.
func probeVault(ctx context.Context, v vault.Store) error {
	const tenant, secret = "00000000-0000-7000-8000-000000000000", "00000000-0000-7000-8000-000000000001"
	if _, err := v.PutPassword(ctx, tenant, secret, "probe"); err != nil {
		return fmt.Errorf("put: %w", err)
	}
	if _, err := v.GetPassword(ctx, tenant, secret, 0); err != nil {
		return fmt.Errorf("get: %w", err)
	}
	if err := v.DeleteSecret(ctx, tenant, secret); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	return nil
}

// noVerifier refuses every token: bootstrap never serves requests.
type noVerifier struct{}

func (noVerifier) Verify(context.Context, string) (authclient.Identity, error) {
	return authclient.Identity{}, authclient.ErrUnauthenticated
}
