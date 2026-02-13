package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
)

// Config holds Vault client configuration
type Config struct {
	Address        string        `json:"address" yaml:"address"`
	RoleID         string        `json:"role_id" yaml:"role_id"`
	SecretID       string        `json:"secret_id" yaml:"secret_id"`
	RoleIDFile     string        `json:"role_id_file" yaml:"role_id_file"`         // Path to file containing role ID
	SecretIDFile   string        `json:"secret_id_file" yaml:"secret_id_file"`     // Path to file containing secret ID
	MountPath      string        `json:"mount_path" yaml:"mount_path"`
	Namespace      string        `json:"namespace" yaml:"namespace"`
	RetryMax       int           `json:"retry_max" yaml:"retry_max"`
	RetryWaitMin   time.Duration `json:"retry_wait_min" yaml:"retry_wait_min"`
	RetryWaitMax   time.Duration `json:"retry_wait_max" yaml:"retry_wait_max"`
	Timeout        time.Duration `json:"timeout" yaml:"timeout"`
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		Address:      "http://localhost:8200",
		MountPath:    "secret",
		RetryMax:     3,
		RetryWaitMin: 1 * time.Second,
		RetryWaitMax: 5 * time.Second,
		Timeout:      30 * time.Second,
	}
}

// Client wraps HashiCorp Vault client with AppRole authentication
type Client struct {
	client    *vault.Client
	config    *Config
	log       *log.Helper
	mountPath string
	cancel    context.CancelFunc // stops the token renewal goroutine
}

// NewClient creates a new Vault client with AppRole authentication
func NewClient(cfg *Config, logger log.Logger) (*Client, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	l := log.NewHelper(log.With(logger, "module", "vault/client"))

	// Load credentials from files if file paths are provided
	if err := cfg.loadCredentialsFromFiles(); err != nil {
		return nil, fmt.Errorf("failed to load credentials from files: %w", err)
	}

	// Also check environment variables for file paths
	if err := cfg.loadCredentialsFromEnv(); err != nil {
		return nil, fmt.Errorf("failed to load credentials from env: %w", err)
	}

	// Create Vault client config
	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = cfg.Address
	vaultConfig.Timeout = cfg.Timeout
	vaultConfig.MaxRetries = cfg.RetryMax
	vaultConfig.MinRetryWait = cfg.RetryWaitMin
	vaultConfig.MaxRetryWait = cfg.RetryWaitMax

	// Create Vault client
	client, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Set namespace if configured
	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	c := &Client{
		client:    client,
		config:    cfg,
		log:       l,
		mountPath: cfg.MountPath,
	}

	// Authenticate with AppRole if credentials are provided
	if cfg.RoleID != "" && cfg.SecretID != "" {
		authInfo, err := c.authenticateAppRole(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to authenticate with AppRole: %w", err)
		}
		// Start background token renewal
		ctx, cancel := context.WithCancel(context.Background())
		c.cancel = cancel
		go c.renewToken(ctx, authInfo)
	}

	return c, nil
}

// loadCredentialsFromFiles loads role_id and secret_id from files if paths are configured
func (c *Config) loadCredentialsFromFiles() error {
	// Load role ID from file
	if c.RoleIDFile != "" && c.RoleID == "" {
		data, err := os.ReadFile(c.RoleIDFile)
		if err != nil {
			return fmt.Errorf("failed to read role_id file %s: %w", c.RoleIDFile, err)
		}
		c.RoleID = strings.TrimSpace(string(data))
	}

	// Load secret ID from file
	if c.SecretIDFile != "" && c.SecretID == "" {
		data, err := os.ReadFile(c.SecretIDFile)
		if err != nil {
			return fmt.Errorf("failed to read secret_id file %s: %w", c.SecretIDFile, err)
		}
		c.SecretID = strings.TrimSpace(string(data))
	}

	return nil
}

// loadCredentialsFromEnv loads credentials from environment variables
// Supports VAULT_ROLE_ID, VAULT_SECRET_ID (direct values)
// and VAULT_ROLE_ID_FILE, VAULT_SECRET_ID_FILE (file paths)
func (c *Config) loadCredentialsFromEnv() error {
	// Check for direct values first
	if c.RoleID == "" {
		c.RoleID = os.Getenv("VAULT_ROLE_ID")
	}
	if c.SecretID == "" {
		c.SecretID = os.Getenv("VAULT_SECRET_ID")
	}

	// Check for file paths
	if c.RoleID == "" {
		if roleIDFile := os.Getenv("VAULT_ROLE_ID_FILE"); roleIDFile != "" {
			data, err := os.ReadFile(roleIDFile)
			if err != nil {
				return fmt.Errorf("failed to read VAULT_ROLE_ID_FILE %s: %w", roleIDFile, err)
			}
			c.RoleID = strings.TrimSpace(string(data))
		}
	}

	if c.SecretID == "" {
		if secretIDFile := os.Getenv("VAULT_SECRET_ID_FILE"); secretIDFile != "" {
			data, err := os.ReadFile(secretIDFile)
			if err != nil {
				return fmt.Errorf("failed to read VAULT_SECRET_ID_FILE %s: %w", secretIDFile, err)
			}
			c.SecretID = strings.TrimSpace(string(data))
		}
	}

	return nil
}

// authenticateAppRole authenticates using AppRole method
func (c *Client) authenticateAppRole(ctx context.Context) (*vault.Secret, error) {
	appRoleAuth, err := approle.NewAppRoleAuth(
		c.config.RoleID,
		&approle.SecretID{FromString: c.config.SecretID},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create AppRole auth: %w", err)
	}

	authInfo, err := c.client.Auth().Login(ctx, appRoleAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to login with AppRole: %w", err)
	}

	if authInfo == nil {
		return nil, errors.New("no auth info returned from AppRole login")
	}

	c.log.Infof("Successfully authenticated with Vault using AppRole")
	return authInfo, nil
}

// renewToken runs a background loop that renews the Vault token before it expires.
// If renewal fails (e.g. past max TTL), it re-authenticates with AppRole.
func (c *Client) renewToken(ctx context.Context, secret *vault.Secret) {
	if secret == nil || secret.Auth == nil {
		c.log.Warn("No auth secret to renew")
		return
	}

	watcher, err := c.client.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
		Secret: secret,
	})
	if err != nil {
		c.log.Errorf("Failed to create token lifetime watcher: %v", err)
		return
	}

	go watcher.Start()
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			c.log.Info("Vault token renewal stopped")
			return
		case err := <-watcher.DoneCh():
			// Token can no longer be renewed (past max TTL or revoked).
			// Re-authenticate with AppRole to get a fresh token.
			c.log.Warnf("Vault token renewal ended (err=%v), re-authenticating", err)
			newSecret, authErr := c.authenticateAppRole(ctx)
			if authErr != nil {
				c.log.Errorf("Failed to re-authenticate with Vault: %v", authErr)
				// Retry after a delay
				select {
				case <-ctx.Done():
					return
				case <-time.After(10 * time.Second):
				}
				continue
			}
			// Restart watcher with the new token
			watcher.Stop()
			watcher, err = c.client.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
				Secret: newSecret,
			})
			if err != nil {
				c.log.Errorf("Failed to create new token lifetime watcher: %v", err)
				return
			}
			go watcher.Start()
		case info := <-watcher.RenewCh():
			c.log.Infof("Vault token renewed, next renewal in %ds", info.Secret.Auth.LeaseDuration)
		}
	}
}

// Health checks Vault health status
func (c *Client) Health(ctx context.Context) (*vault.HealthResponse, error) {
	return c.client.Sys().HealthWithContext(ctx)
}

// IsSealed checks if Vault is sealed
func (c *Client) IsSealed(ctx context.Context) (bool, error) {
	health, err := c.Health(ctx)
	if err != nil {
		return true, err
	}
	return health.Sealed, nil
}

// GetClient returns the underlying Vault client
func (c *Client) GetClient() *vault.Client {
	return c.client
}

// GetMountPath returns the configured mount path
func (c *Client) GetMountPath() string {
	return c.mountPath
}

// Close stops token renewal and cleans up the client
func (c *Client) Close() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}
