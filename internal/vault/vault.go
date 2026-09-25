package vault

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
)

// Errors reported to callers (never carrying material).
var (
	ErrUnavailable = errors.New("vault: unavailable")    // unreachable, sealed, or refused (fail closed)
	ErrNotFound    = errors.New("vault: not found")      // no such path or version
	ErrBadPath     = errors.New("vault: malformed path") // id outside the allowed grammar
)

// Store is the material store: passwords (versioned) and TOTP seeds, per tenant.
type Store interface {
	PutPassword(ctx context.Context, tenantID, secretID, password string) (version int, err error)
	GetPassword(ctx context.Context, tenantID, secretID string, version int) (string, error) // 0 = current
	Versions(ctx context.Context, tenantID, secretID string) ([]int, error)
	DeleteSecret(ctx context.Context, tenantID, secretID string) error // destroys every version and the seed
	PutTOTP(ctx context.Context, tenantID, secretID, seed string) error
	GetTOTP(ctx context.Context, tenantID, secretID string) (string, error)
	DeleteTOTP(ctx context.Context, tenantID, secretID string) error
	Health(ctx context.Context) Health
}

// Health is the state reported by the service health endpoint.
type Health string

// Health states.
const (
	HealthOK              Health = "ok"
	HealthSealed          Health = "sealed"
	HealthUnreachable     Health = "unreachable"
	HealthUnauthenticated Health = "unauthenticated"
)

// Options configure the client.
type Options struct {
	Address        string
	Mount          string
	RoleID         string // AppRole role id (loaded by the caller from a file or secrets provider)
	SecretID       string
	AllowPlaintext bool
	CAFile         string
	Logger         *slog.Logger
	Timeout        time.Duration // per request (default 5 s)
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Path builds the KV path (relative to the mount) for a tenant's secret. Both
// ids must be UUIDs so no input can escape the tenant prefix.
func Path(tenantID, secretID string) (string, error) {
	if !uuidRE.MatchString(tenantID) || !uuidRE.MatchString(secretID) {
		return "", ErrBadPath
	}
	return tenantID + "/secrets/" + secretID, nil
}

// Client is the HashiCorp Vault KV v2 store with AppRole authentication and
// automatic token renewal.
type Client struct {
	api      *api.Client
	kv       *api.KVv2
	mount    string
	auth     api.AuthMethod
	log      *slog.Logger
	mu       sync.Mutex
	watcher  *api.LifetimeWatcher
	loggedIn bool
}

// New builds the client and performs the first login.
func New(ctx context.Context, o Options) (*Client, error) {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if strings.HasPrefix(o.Address, "http://") && !o.AllowPlaintext {
		return nil, errors.New("vault: plaintext address refused (set allow_plaintext for development)")
	}
	if o.RoleID == "" || o.SecretID == "" {
		return nil, errors.New("vault: role id and secret id are required")
	}
	cfg := api.DefaultConfig()
	cfg.Address = o.Address
	cfg.Timeout = o.Timeout
	cfg.MaxRetries = 1
	tlsCfg := &api.TLSConfig{}
	if o.CAFile != "" {
		tlsCfg.CACert = o.CAFile
	}
	if err := cfg.ConfigureTLS(tlsCfg); err != nil {
		return nil, fmt.Errorf("vault: tls: %w", err)
	}
	c, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vault: client: %w", err)
	}
	auth, err := newAuth(o.RoleID, &approle.SecretID{FromString: o.SecretID})
	if err != nil {
		return nil, fmt.Errorf("vault: approle: %w", err)
	}
	cl := &Client{api: c, kv: c.KVv2(o.Mount), mount: o.Mount, auth: auth, log: o.Logger}
	if err := cl.login(ctx); err != nil {
		return nil, err
	}
	return cl, nil
}

// Seams for tests: the AppRole auth and the lifetime watcher constructors.
var (
	newAuth = func(roleID string, sid *approle.SecretID) (api.AuthMethod, error) {
		return approle.NewAppRoleAuth(roleID, sid)
	}
	newWatcher = func(c *api.Client, in *api.LifetimeWatcherInput) (*api.LifetimeWatcher, error) {
		return c.NewLifetimeWatcher(in)
	}
)

// LoadCredential reads an AppRole credential file (mode-agnostic, trimmed).
func LoadCredential(path string) (string, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-supplied credential path
	if err != nil {
		return "", fmt.Errorf("vault: credential: %w", err)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", errors.New("vault: credential file is empty")
	}
	return v, nil
}

func (c *Client) login(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	sec, err := c.api.Auth().Login(ctx, c.auth)
	if err != nil || sec == nil || sec.Auth == nil {
		c.loggedIn = false
		return fmt.Errorf("%w: login failed", ErrUnavailable)
	}
	c.loggedIn = true
	if c.watcher != nil {
		c.watcher.Stop()
	}
	// Renewal errors end the watcher at once so the client logs in again
	// instead of backing off until the token expires.
	w, err := newWatcher(c.api, &api.LifetimeWatcherInput{Secret: sec, RenewBehavior: api.RenewBehaviorErrorOnErrors})
	if err != nil {
		return fmt.Errorf("vault: watcher: %w", err)
	}
	c.watcher = w
	go w.Start()
	go c.watch(w) // #nosec G118 -- the renewal loop outlives the login request by design
	return nil
}

// watch renews the token and re-logs in when renewal ends.
func (c *Client) watch(w *api.LifetimeWatcher) {
	for {
		select {
		case err := <-w.DoneCh():
			if err != nil {
				c.log.Warn("vault token renewal ended", "err", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := c.login(ctx); err != nil {
				c.log.Error("vault re-login failed", "err", err)
			}
			cancel()
			return
		case <-w.RenewCh():
		}
	}
}

// Close stops the renewal watcher.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.watcher != nil {
		c.watcher.Stop()
	}
}

// mapErr classifies a non-nil client error.
func mapErr(err error) error {
	if errors.Is(err, api.ErrSecretNotFound) {
		return ErrNotFound
	}
	var re *api.ResponseError
	if errors.As(err, &re) {
		switch re.StatusCode {
		case 404:
			return ErrNotFound
		case 403:
			return fmt.Errorf("%w: permission denied", ErrUnavailable)
		}
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, redact(err))
}

// redact keeps error text free of anything that could be material.
func redact(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// PutPassword writes a new KV version and returns its number.
func (c *Client) PutPassword(ctx context.Context, tenantID, secretID, password string) (int, error) {
	p, err := Path(tenantID, secretID)
	if err != nil {
		return 0, err
	}
	sec, err := c.kv.Put(ctx, p, map[string]any{"password": password})
	if err != nil {
		return 0, mapErr(err)
	}
	if sec == nil || sec.VersionMetadata == nil {
		return 0, fmt.Errorf("%w: no version metadata", ErrUnavailable)
	}
	return sec.VersionMetadata.Version, nil
}

// SkipVersion consumes the next KV version number without keeping material:
// it writes an empty marker and soft-deletes it at once (the data path's
// delete capability, already in the policy). A migration replaying a history
// whose older versions were destroyed uses it to keep the original version
// numbers; reads of a skipped version answer ErrNotFound.
func (c *Client) SkipVersion(ctx context.Context, tenantID, secretID string) (int, error) {
	p, err := Path(tenantID, secretID)
	if err != nil {
		return 0, err
	}
	sec, err := c.kv.Put(ctx, p, map[string]any{"skipped": true})
	if err != nil {
		return 0, mapErr(err)
	}
	if sec == nil || sec.VersionMetadata == nil {
		return 0, fmt.Errorf("%w: no version metadata", ErrUnavailable)
	}
	if err := c.kv.Delete(ctx, p); err != nil {
		return 0, mapErr(err)
	}
	return sec.VersionMetadata.Version, nil
}

// GetPassword reads one version (0 = current).
func (c *Client) GetPassword(ctx context.Context, tenantID, secretID string, version int) (string, error) {
	p, err := Path(tenantID, secretID)
	if err != nil {
		return "", err
	}
	var sec *api.KVSecret
	if version <= 0 {
		sec, err = c.kv.Get(ctx, p)
	} else {
		sec, err = c.kv.GetVersion(ctx, p, version)
	}
	if err != nil {
		return "", mapErr(err)
	}
	if sec == nil || sec.Data == nil {
		return "", ErrNotFound
	}
	if sec.VersionMetadata != nil && (sec.VersionMetadata.Destroyed || !sec.VersionMetadata.DeletionTime.IsZero()) {
		return "", ErrNotFound
	}
	v, _ := sec.Data["password"].(string)
	return v, nil
}

// Versions lists the live version numbers, ascending.
func (c *Client) Versions(ctx context.Context, tenantID, secretID string) ([]int, error) {
	p, err := Path(tenantID, secretID)
	if err != nil {
		return nil, err
	}
	list, err := c.kv.GetVersionsAsList(ctx, p)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]int, 0, len(list))
	for _, v := range list {
		if !v.Destroyed && v.DeletionTime.IsZero() {
			out = append(out, v.Version)
		}
	}
	return out, nil
}

// DeleteSecret destroys every version and the TOTP seed.
func (c *Client) DeleteSecret(ctx context.Context, tenantID, secretID string) error {
	p, err := Path(tenantID, secretID)
	if err != nil {
		return err
	}
	if err := c.kv.DeleteMetadata(ctx, p); err != nil && !errors.Is(mapErr(err), ErrNotFound) {
		return mapErr(err)
	}
	if err := c.kv.DeleteMetadata(ctx, p+"/totp"); err != nil && !errors.Is(mapErr(err), ErrNotFound) {
		return mapErr(err)
	}
	return nil
}

// PutTOTP stores (overwrites) the seed.
func (c *Client) PutTOTP(ctx context.Context, tenantID, secretID, seed string) error {
	p, err := Path(tenantID, secretID)
	if err != nil {
		return err
	}
	if _, err := c.kv.Put(ctx, p+"/totp", map[string]any{"seed": seed}); err != nil {
		return mapErr(err)
	}
	return nil
}

// GetTOTP reads the seed.
func (c *Client) GetTOTP(ctx context.Context, tenantID, secretID string) (string, error) {
	p, err := Path(tenantID, secretID)
	if err != nil {
		return "", err
	}
	sec, err := c.kv.Get(ctx, p+"/totp")
	if err != nil {
		return "", mapErr(err)
	}
	if sec == nil || sec.Data == nil {
		return "", ErrNotFound
	}
	v, _ := sec.Data["seed"].(string)
	if v == "" {
		return "", ErrNotFound
	}
	return v, nil
}

// DeleteTOTP destroys the seed.
func (c *Client) DeleteTOTP(ctx context.Context, tenantID, secretID string) error {
	p, err := Path(tenantID, secretID)
	if err != nil {
		return err
	}
	if err := c.kv.DeleteMetadata(ctx, p+"/totp"); err != nil && !errors.Is(mapErr(err), ErrNotFound) {
		return mapErr(err)
	}
	return nil
}

// Health probes the server and the token.
func (c *Client) Health(ctx context.Context) Health {
	h, err := c.api.Sys().HealthWithContext(ctx)
	if err != nil || h == nil {
		return HealthUnreachable
	}
	if h.Sealed || !h.Initialized {
		return HealthSealed
	}
	if _, err := c.api.Auth().Token().LookupSelfWithContext(ctx); err != nil {
		return HealthUnauthenticated
	}
	return HealthOK
}
