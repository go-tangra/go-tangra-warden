package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-tangra/go-tangra-warden/v4/internal/app"
	"github.com/go-tangra/go-tangra-warden/v4/internal/config"
	"github.com/go-tangra/go-tangra-warden/v4/internal/migrate3"
	"github.com/go-tangra/go-tangra-warden/v4/internal/migrate3/v3db"
	"github.com/go-tangra/go-tangra-warden/v4/internal/transfer"
	"github.com/go-tangra/go-tangra-warden/v4/internal/vault"
)

// exportV3 reads a warden v3 tenant (portal Postgres + v3 Vault) into a
// sealed bundle and a one-time key file. It needs no v4 configuration and
// runs on the v3 network. Prints a summary (never material or the key).
func exportV3(args []string) int {
	fs := flag.NewFlagSet("wardensvc export-v3", flag.ContinueOnError)
	dsnFile := fs.String("dsn-file", "", "file containing the v3 Postgres DSN (database gwa)")
	vaultAddr := fs.String("vault-addr", "", "v3 Vault address, e.g. http://vault:8200")
	roleIDFile := fs.String("role-id-file", "", "v3 AppRole role_id file")
	secretIDFile := fs.String("secret-id-file", "", "v3 AppRole secret_id file")
	mount := fs.String("mount", "secret", "v3 KV v2 mount")
	tenant := fs.Uint("tenant", 0, "v3 tenant id")
	out := fs.String("out", "", "bundle file to create (0600, never overwritten)")
	keyOut := fs.String("key-out", "", "key file to create (0600, never overwritten)")
	includeDeleted := fs.Bool("include-deleted", false, "also export secrets with status DELETED")
	allowPlaintext := fs.Bool("allow-plaintext", false, "accept an http:// Vault address (private network only)")
	vaultCA := fs.String("vault-ca", "", "CA bundle for an https Vault")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dsnFile == "" || *vaultAddr == "" || *roleIDFile == "" || *secretIDFile == "" || *out == "" || *keyOut == "" || *tenant > 1<<32-1 {
		fmt.Fprintln(os.Stderr, "wardensvc export-v3: -dsn-file, -vault-addr, -role-id-file, -secret-id-file, -out and -key-out are required")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	dsn, err := vault.LoadCredential(*dsnFile)
	if err != nil {
		return fail(fmt.Errorf("dsn file: %w", err))
	}
	roleID, err := vault.LoadCredential(*roleIDFile)
	if err != nil {
		return fail(err)
	}
	secretID, err := vault.LoadCredential(*secretIDFile)
	if err != nil {
		return fail(err)
	}
	pg, err := v3db.Open(ctx, dsn, uint32(*tenant)) // #nosec G115 -- bounded above
	if err != nil {
		return fail(err)
	}
	defer pg.Close(context.Background())
	kv, err := v3db.OpenVault(ctx, v3db.VaultOptions{Address: *vaultAddr, Mount: *mount, RoleID: roleID, SecretID: secretID, AllowPlaintext: *allowPlaintext, CAFile: *vaultCA})
	if err != nil {
		return fail(err)
	}
	sum, err := migrate3.RunExport(ctx, migrate3.ExportConfig{Out: *out, KeyOut: *keyOut, Tenant: uint32(*tenant), IncludeDeleted: *includeDeleted}, pg, kv) // #nosec G115 -- bounded above
	if err != nil {
		return fail(err)
	}
	printJSON(sum)
	return 0
}

// importV3 opens a bundle in memory and imports it into the configured v4
// warden (database + vault of the normal configuration), or with -dry-run
// only reports what it would do. Exit 1 when anything needs attention.
func importV3(args []string) int {
	fs := flag.NewFlagSet("wardensvc import-v3", flag.ContinueOnError)
	cfgPath := fs.String("config", "deploy/container.yaml", "warden configuration file")
	in := fs.String("in", "", "bundle written by export-v3")
	keyFile := fs.String("key-file", "", "key file written by export-v3")
	users := fs.String("users", "", "CSV email,user_uuid of the v4 tenant's users")
	tenant := fs.String("tenant", migrate3.DefaultTenant, "v4 tenant UUID")
	roleMap := fs.String("role-map", "", "v3 role → v4 role, e.g. platform:admin=admin,1=admin")
	dryRun := fs.Bool("dry-run", false, "report only; write nothing")
	actorEmail := fs.String("actor-email", "", "operator e-mail (a v4 user): audit actor and author when the original has no v4 account")
	allowExisting := fs.Bool("allow-existing", false, "import although the tenant already has secrets")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	d, err := app.OpenData(ctx, cfg, !*dryRun)
	if err != nil {
		return fail(err)
	}
	defer d.Close()
	svc := transfer.New(d.Repo, nil, nil, nil, d.Audit)
	res, err := migrate3.RunImport(ctx, migrate3.ImportConfig{In: *in, KeyFile: *keyFile, UsersFile: *users, TenantID: *tenant, RoleMap: *roleMap,
		ActorEmail: *actorEmail, DryRun: *dryRun, AllowExisting: *allowExisting}, svc, d.Vault)
	if err != nil {
		printJSON(res.Mapping)
		return fail(err)
	}
	printJSON(res)
	if res.Failed() {
		return 1
	}
	return 0
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
