// Package app wires the warden service: configuration → Freya runtime →
// TimescaleDB, Valkey, Vault, audit → token verifier → browser API on the
// Freya HTTP server (reached only through the gateway) and the warden.v1 gRPC
// API → gateway registration. cmd/wardensvc and the integration harness use it.
package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"time"

	kmiddleware "github.com/go-kratos/kratos/v3/middleware"

	"github.com/go-freya/freya"
	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
	"github.com/go-freya/freya/services/auth/pkg/authclient"
	"github.com/go-freya/freya/services/lcm/pkg/lcmidentity"
	"github.com/go-freya/freya/services/gateway/pkg/gatewayclient"
	"github.com/go-freya/freya/services/warden/internal/audit"
	"github.com/go-freya/freya/services/warden/internal/authz"
	"github.com/go-freya/freya/services/warden/internal/cache"
	"github.com/go-freya/freya/services/warden/internal/config"
	"github.com/go-freya/freya/services/warden/internal/folders"
	"github.com/go-freya/freya/services/warden/internal/httpapi"
	"github.com/go-freya/freya/services/warden/internal/repo"
	"github.com/go-freya/freya/services/warden/internal/repo/repodb"
	"github.com/go-freya/freya/services/warden/internal/secrets"
	"github.com/go-freya/freya/services/warden/internal/share"
	"github.com/go-freya/freya/services/warden/internal/store"
	"github.com/go-freya/freya/services/warden/internal/transfer"
	"github.com/go-freya/freya/services/warden/internal/vault"
	"github.com/go-freya/freya/services/warden/pkg/wardenmanifest"
)

// Options override infrastructure (tests) and attach optional parts.
type Options struct {
	Logger   slog.Handler
	KV       cache.KV               // nil = Valkey from config
	Vault    vault.Store            // nil = Vault from config
	Verifier httpapi.Verifier       // nil = authclient against the auth service
	GRPCAuth kmiddleware.Middleware // gRPC user middleware when Verifier is not an authclient.Verifier (tests)
	Remote   fs.FS                  // nil = no federated remote
	Mail     share.Sender           // nil = SMTP/log sender from config
	Freya    []freya.Option
	Migrate  bool
	// Register lets the caller mount handlers after the core is wired (the
	// stories add their Register* calls in wire.go).
	Register func(a *App) error
}

// App holds every wired component.
type App struct {
	Cfg      config.Config
	Log      *slog.Logger
	Freya    *freya.App
	Store    *store.Store
	Repo     repo.Store
	Cache    *cache.Cache
	Vault    vault.Store
	Audit    *audit.Writer
	Verifier httpapi.Verifier
	GRPCAuth kmiddleware.Middleware
	HTTP     *httpapi.Server
	Authz    *authz.Authz
	Secrets  *secrets.Service
	Folders  *folders.Service
	Transfer *transfer.Service
	Shares   *share.Service
	Mail     share.Sender // nil = from config
	closers  []func()
	workers  []func(ctx contextT)
}

type contextT = context.Context

// Build validates cfg and connects every dependency; nothing is served yet.
func Build(ctx context.Context, cfg config.Config, o Options) (a *App, err error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	handler := o.Logger
	if handler == nil {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	}
	log := slog.New(handler)
	for _, w := range cfg.Warnings() {
		log.Warn(w)
	}
	built := &App{Cfg: cfg, Log: log}
	a = built
	defer func() {
		if err != nil {
			built.Close()
		}
	}()
	if o.Migrate {
		dsn := cfg.DB.MigrateDSN
		if dsn == "" {
			dsn = cfg.DB.DSN
		}
		if err := store.Migrate(ctx, dsn); err != nil {
			return nil, err
		}
	}
	if a.Store, err = store.Open(ctx, cfg.DB.DSN, cfg.DB.MaxConns); err != nil {
		return nil, err
	}
	a.closers = append(a.closers, a.Store.Close)
	a.Repo = repodb.New(a.Store)
	kv := o.KV
	if kv == nil {
		vc := cache.ValkeyConfig{Addresses: cfg.Valkey.Addresses, Username: cfg.Valkey.Username, Password: cfg.Valkey.Password, AllowPlaintext: cfg.Valkey.AllowPlaintext}
		if cfg.Valkey.CAFile != "" {
			if vc.CAPEM, err = os.ReadFile(cfg.Valkey.CAFile); err != nil {
				return nil, fmt.Errorf("valkey ca: %w", err)
			}
		}
		if kv, err = cache.NewValkey(vc); err != nil {
			return nil, err
		}
	}
	a.Cache = cache.New(kv)
	a.closers = append(a.closers, a.Cache.Close)
	a.Vault = o.Vault
	if a.Vault == nil {
		if a.Vault, err = openVault(ctx, cfg, log); err != nil {
			return nil, err
		}
	}
	a.Audit = audit.NewWriter(a.Repo, func(err error) { log.Error("audit write failed", "err", err) })
	a.closers = append(a.closers, a.Audit.Close)
	fopts := append([]freya.Option{freya.WithLogger(handler)}, o.Freya...)
	if cfg.Enroll.Enabled {
		raw, rerr := os.ReadFile(cfg.Enroll.TokenFile)
		if rerr != nil {
			return nil, fmt.Errorf("warden: enroll token: %w", rerr)
		}
		prov, perr := lcmidentity.NewNet(ctx, lcmidentity.NetConfig{
			EnrollURL: cfg.Enroll.EnrollURL, LCMGRPCTarget: cfg.Enroll.LCMGRPCTarget,
			TenantID: cfg.Enroll.TenantID, TrustDomain: cfg.Config.TrustDomain, ServiceName: cfg.Config.ServiceName,
			EnrollmentToken: strings.TrimSpace(string(raw)), Insecure: cfg.Enroll.Insecure, StateFile: cfg.Enroll.StateFile,
		})
		if perr != nil {
			return nil, fmt.Errorf("warden: enroll: %w", perr)
		}
		a.closers = append(a.closers, func() { _ = prov.Close() })
		fopts = append(fopts, freya.WithIdentityProvider(prov))
	}
	if a.Freya, err = freya.New(cfg.Config, fopts...); err != nil {
		return nil, err
	}
	a.closers = append(a.closers, a.Freya.Close)
	a.Verifier, a.GRPCAuth, a.Mail = o.Verifier, o.GRPCAuth, o.Mail
	if a.Verifier == nil {
		// Platform tokens forwarded by the gateway are verified against the
		// auth service's keys and revocation feed over the Freya channel.
		conn, err := a.Freya.Client(ctx, "auth")
		if err != nil {
			return nil, fmt.Errorf("auth client: %w", err)
		}
		v := authclient.New(authclient.Config{Issuer: cfg.Gateway.Issuer}, authclient.GRPCKeys{Client: authv1.NewKeysClient(conn)}, authclient.GRPCRevocations{Client: authv1.NewSessionsClient(conn)})
		a.Verifier = v
	}
	hopts := []httpapi.Option{httpapi.WithVerifier(a.Verifier)}
	if o.Remote != nil {
		hopts = append(hopts, httpapi.WithRemote(o.Remote))
	}
	if a.HTTP, err = httpapi.NewHandler(a.Freya, hopts...); err != nil {
		return nil, err
	}
	a.Freya.HTTP().HandlePrefix("/", a.HTTP.Handler())
	if o.Register != nil {
		if err := o.Register(a); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// CheckRoutes fails when a declared route has no handler: it would answer
// 501 and hide a wiring mistake. Called once every story is registered.
func (a *App) CheckRoutes() error {
	if missing := a.HTTP.Missing(); len(missing) > 0 {
		return fmt.Errorf("app: %d routes declared in the OpenAPI document without a handler (first: %s)", len(missing), missing[0])
	}
	return nil
}

// openVault loads the AppRole credentials (files, or environment variables
// named by role_id_secret/secret_id_secret) and logs in.
func openVault(ctx context.Context, cfg config.Config, log *slog.Logger) (*vault.Client, error) {
	roleID, err := credential(cfg.Vault.RoleIDFile, cfg.Vault.RoleIDSecret)
	if err != nil {
		return nil, fmt.Errorf("vault role id: %w", err)
	}
	secretID, err := credential(cfg.Vault.SecretIDFile, cfg.Vault.SecretIDSecret)
	if err != nil {
		return nil, fmt.Errorf("vault secret id: %w", err)
	}
	return vault.New(ctx, vault.Options{Address: cfg.Vault.Address, Mount: cfg.Vault.Mount, RoleID: roleID, SecretID: secretID,
		AllowPlaintext: cfg.Vault.AllowPlaintext, CAFile: cfg.Vault.CAFile, Logger: log})
}

func credential(file, env string) (string, error) {
	if file != "" {
		return vault.LoadCredential(file)
	}
	v := os.Getenv(env)
	if v == "" {
		return "", errors.New("environment variable " + env + " is empty")
	}
	return v, nil
}

// Health reports the dependencies for the health route and bootstrap.
type Health struct {
	DB    string       `json:"db"`
	Vault vault.Health `json:"vault"`
}

// Health checks the database and the vault, each within its own deadline
// so a hanging vault never makes the database look down.
func (a *App) Health(ctx context.Context) Health {
	h := Health{DB: "ok"}
	dbCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	if err := a.Store.Ping(dbCtx); err != nil {
		h.DB = "unreachable"
	}
	cancel()
	vCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	h.Vault = a.Vault.Health(vCtx)
	cancel()
	return h
}

// Run serves until ctx is done: the verifier feed, the gateway lease and
// background workers stop with it.
func (a *App) Run(ctx context.Context) error {
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if v, ok := a.Verifier.(*authclient.Verifier); ok {
		go func() {
			for wctx.Err() == nil {
				if err := v.Start(wctx, func(err error) { a.Log.Warn("verifier", "err", err) }); err == nil {
					return
				} else {
					a.Log.Warn("verifier start failed; retrying", "err", err)
				}
				select {
				case <-wctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
		}()
	}
	go a.register(wctx)
	for _, w := range a.workers {
		go w(wctx)
	}
	go func() {
		for wctx.Err() == nil && !a.Freya.Ready() {
			time.Sleep(100 * time.Millisecond)
		}
		a.seedLoop(wctx)
	}()
	return a.Freya.Run(ctx)
}

// register keeps the gateway lease for the manifest.
func (a *App) register(ctx context.Context) {
	for ctx.Err() == nil && !a.Freya.Ready() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	man, err := wardenmanifest.Manifest()
	if err != nil {
		a.Log.Error("gateway manifest", "err", err)
		return
	}
	httpEP, err := a.Freya.HTTP().Endpoint()
	if err != nil {
		a.Log.Error("gateway registration: http endpoint", "err", err)
		return
	}
	grpcEP, err := a.Freya.GRPC().Endpoint()
	if err != nil {
		a.Log.Error("gateway registration: grpc endpoint", "err", err)
		return
	}
	var client *gatewayclient.Client
	for ctx.Err() == nil && client == nil {
		conn, err := a.Freya.Client(ctx, a.Cfg.Gateway.Service)
		if err != nil {
			a.Log.Warn("gateway connection", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		client, err = gatewayclient.New(conn, gatewayclient.Options{Manifest: man, HTTPURL: "https://" + httpEP.Host, GRPCTarget: grpcEP.Host, Logger: a.Log,
			OnState: func(s gatewayclient.State) {
				a.Log.Info("gateway lease", "registered", s.Registered, "lease", s.LeaseID, "err", s.Err)
			}})
		if err != nil {
			a.Log.Error("gateway client", "err", err)
			return
		}
	}
	if client != nil {
		if err := client.Run(ctx); err != nil {
			a.Log.Error("gateway registration", "err", err)
		}
	}
}

// Close releases everything Build acquired (idempotent, reverse order).
func (a *App) Close() {
	for i := len(a.closers) - 1; i >= 0; i-- {
		a.closers[i]()
	}
	a.closers = nil
}
