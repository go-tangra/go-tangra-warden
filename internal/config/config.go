package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	fconfig "github.com/go-tangra/go-tangra/v4/config"
	"gopkg.in/yaml.v3"
)

// Config is the warden service configuration: the Freya framework config plus
// the module's own sections. Every value is explicit and validated at start.
type Config struct {
	fconfig.Config `yaml:",inline"`

	DB      DB      `yaml:"db"`
	Valkey  Valkey  `yaml:"valkey"`
	Vault   Vault   `yaml:"vault"`
	Gateway Gateway `yaml:"gateway"`
	Share   Share   `yaml:"share"`
	Mail    Mail    `yaml:"mail"`
	Limits  Limits  `yaml:"limits_warden"`
	Enroll  Enroll  `yaml:"enroll"`
}

// DB configures TimescaleDB.
type DB struct {
	DSN        string `yaml:"dsn"`         // application role (no BYPASSRLS)
	MigrateDSN string `yaml:"migrate_dsn"` // migration role; empty = DSN
	MaxConns   int32  `yaml:"max_conns"`
}

// Valkey configures the cache (rate limits, share counters).
type Valkey struct {
	Addresses      []string `yaml:"addresses"`
	Username       string   `yaml:"username"`
	Password       string   `yaml:"password"`
	AllowPlaintext bool     `yaml:"allow_plaintext"`
	CAFile         string   `yaml:"ca_file"`
}

// Vault configures the secrets vault (HashiCorp Vault KV v2, AppRole).
type Vault struct {
	Address        string `yaml:"address"`
	Mount          string `yaml:"mount"`
	RoleIDFile     string `yaml:"role_id_file"`
	SecretIDFile   string `yaml:"secret_id_file"`
	RoleIDSecret   string `yaml:"role_id_secret"`   // secrets-provider key (alternative to the files)
	SecretIDSecret string `yaml:"secret_id_secret"` // secrets-provider key
	AllowPlaintext bool   `yaml:"allow_plaintext"`
	CAFile         string `yaml:"ca_file"`
}

// Gateway names the application gateway and the platform token issuer.
// Enroll makes warden obtain its SVID by enrolling with lcm over the network.
type Enroll struct {
	Enabled       bool   `yaml:"enabled"`
	EnrollURL     string `yaml:"enroll_url"`
	LCMGRPCTarget string `yaml:"lcm_grpc"`
	TenantID      string `yaml:"tenant_id"`
	TokenFile     string `yaml:"token_file"`
	StateFile     string `yaml:"state_file"`
	Insecure      bool   `yaml:"insecure"`
}

type Gateway struct {
	Service string `yaml:"service"`
	Issuer  string `yaml:"issuer"`
}

// Share configures external shares.
type Share struct {
	PublicOrigin           string `yaml:"public_origin"` // origin of the platform (share links)
	DefaultValiditySeconds int    `yaml:"default_validity_seconds"`
	DefaultMaxOpens        int    `yaml:"default_max_opens"`
}

// Mail configures the SMTP sender for share links.
type Mail struct {
	Transport      string `yaml:"transport"` // smtp | log
	Host           string `yaml:"host"`
	Port           int    `yaml:"port"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	From           string `yaml:"from"`
	AllowPlaintext bool   `yaml:"allow_plaintext"`
}

// Limits bound the module's own request shapes.
type Limits struct {
	TransferMaxBytes    int64 `yaml:"transfer_max_bytes"`     // Bitwarden / backup documents
	LookupRatePerMinute int   `yaml:"lookup_rate_per_minute"` // share opens and searches per subject
}

// Default returns secure defaults on top of the Freya defaults.
func Default() Config {
	c := Config{
		Config:  fconfig.Default(),
		DB:      DB{MaxConns: 16},
		Vault:   Vault{Mount: "warden"},
		Gateway: Gateway{Service: "gateway"},
		Share:   Share{DefaultValiditySeconds: 3600, DefaultMaxOpens: 1},
		Mail:    Mail{Transport: "smtp", Port: 465},
		Limits:  Limits{TransferMaxBytes: 16 << 20, LookupRatePerMinute: 120},
	}
	return c
}

// Load reads YAML over Default(); unknown fields are rejected. Not yet validated.
func Load(path string) (Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path
	if err != nil {
		return cfg, fmt.Errorf("config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

// Validate checks the Freya config and every module section.
func (c Config) Validate() error {
	if err := c.Config.Validate(); err != nil {
		return err
	}
	prod := c.IsProduction()
	if c.DB.DSN == "" {
		return errors.New("config: db.dsn is required")
	}
	if prod && !strings.Contains(c.DB.DSN, "sslmode=verify-full") && !strings.Contains(c.DB.DSN, "sslmode=verify-ca") {
		return errors.New("config: db.dsn must use sslmode=verify-full (or verify-ca) in production")
	}
	if len(c.Valkey.Addresses) == 0 {
		return errors.New("config: valkey.addresses is required")
	}
	if prod && c.Valkey.AllowPlaintext {
		return errors.New("config: valkey.allow_plaintext is not permitted in production")
	}
	vu, err := url.Parse(c.Vault.Address)
	if err != nil || vu.Host == "" || (vu.Scheme != "https" && vu.Scheme != "http") {
		return errors.New("config: vault.address must be an http(s) URL")
	}
	if vu.Scheme == "http" && !c.Vault.AllowPlaintext {
		return errors.New("config: vault.address is plaintext; set vault.allow_plaintext (development only)")
	}
	if prod && c.Vault.AllowPlaintext {
		return errors.New("config: vault.allow_plaintext is not permitted in production")
	}
	if c.Vault.Mount == "" || strings.ContainsAny(c.Vault.Mount, "/ ") {
		return errors.New("config: vault.mount must be a single path segment")
	}
	if (c.Vault.RoleIDFile == "") == (c.Vault.RoleIDSecret == "") || (c.Vault.SecretIDFile == "") == (c.Vault.SecretIDSecret == "") {
		return errors.New("config: vault.role_id_file/secret_id_file or vault.role_id_secret/secret_id_secret must be set (exactly one source each)")
	}
	if c.Gateway.Service == "" {
		return errors.New("config: gateway.service is required")
	}
	if iu, err := url.Parse(c.Gateway.Issuer); err != nil || iu.Scheme != "https" || iu.Host == "" {
		return errors.New("config: gateway.issuer must be an https origin")
	}
	if ou, err := url.Parse(c.Share.PublicOrigin); err != nil || ou.Scheme != "https" || ou.Host == "" || (ou.Path != "" && ou.Path != "/") {
		return errors.New("config: share.public_origin must be an https origin without path")
	}
	if c.Share.DefaultValiditySeconds < 300 || c.Share.DefaultValiditySeconds > 7*24*3600 {
		return errors.New("config: share.default_validity_seconds must be within [300, 604800]")
	}
	if c.Share.DefaultMaxOpens < 1 || c.Share.DefaultMaxOpens > 10 {
		return errors.New("config: share.default_max_opens must be within [1, 10]")
	}
	if c.Limits.TransferMaxBytes < 4<<20 || c.Limits.TransferMaxBytes > 64<<20 {
		return errors.New("config: limits_warden.transfer_max_bytes must be within [4 MiB, 64 MiB]")
	}
	if c.Config.Limits.MaxRequestBytes < c.Limits.TransferMaxBytes {
		return errors.New("config: limits.max_request_bytes must be at least limits_warden.transfer_max_bytes (transfer uploads)")
	}
	if c.Limits.LookupRatePerMinute <= 0 {
		return errors.New("config: limits_warden.lookup_rate_per_minute must be positive")
	}
	switch c.Mail.Transport {
	case "smtp", "log":
	default:
		return errors.New("config: mail.transport must be smtp or log")
	}
	if prod && c.Mail.AllowPlaintext {
		return errors.New("config: mail.allow_plaintext is not permitted in production")
	}
	return nil
}

// Warnings lists accepted insecure opt-outs (logged at start).
func (c Config) Warnings() []string {
	w := c.Config.Warnings()
	if c.Vault.AllowPlaintext {
		w = append(w, "vault.allow_plaintext: material travels to the vault without TLS (development only)")
	}
	if c.Valkey.AllowPlaintext {
		w = append(w, "valkey.allow_plaintext: cache traffic without TLS (development only)")
	}
	if c.Mail.AllowPlaintext {
		w = append(w, "mail.allow_plaintext: share links mailed without TLS (development only)")
	}
	return w
}
