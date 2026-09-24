package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func valid() Config {
	c := Default()
	c.ServiceName, c.TrustDomain, c.Env = "warden", "example.org", "dev"
	c.Identity.Provider = "file"
	c.Identity.File.Cert, c.Identity.File.Key, c.Identity.File.Bundle = "c", "k", "b"
	c.Authz.Source, c.Authz.Path = "file", "p.yaml"
	c.Config.Limits.MaxRequestBytes = 17 << 20
	c.DB.DSN = "postgres://warden_app:x@db/warden?sslmode=disable"
	c.Valkey.Addresses = []string{"127.0.0.1:6379"}
	c.Valkey.AllowPlaintext = true
	c.Vault.Address = "http://127.0.0.1:8200"
	c.Vault.RoleIDFile, c.Vault.SecretIDFile = "/r", "/s"
	c.Vault.AllowPlaintext = true
	c.Gateway.Issuer = "https://localhost:8443"
	c.Share.PublicOrigin = "https://localhost:8443"
	c.Mail.AllowPlaintext = true
	return c
}

func TestDefaultsAreSecure(t *testing.T) {
	c := Default()
	if c.Vault.AllowPlaintext || c.Valkey.AllowPlaintext || c.Mail.AllowPlaintext {
		t.Fatal("plaintext must be opt-in")
	}
	if c.Vault.Mount != "warden" || c.Share.DefaultValiditySeconds != 3600 || c.Share.DefaultMaxOpens != 1 || c.Limits.TransferMaxBytes != 16<<20 || c.Limits.LookupRatePerMinute != 120 || c.Gateway.Service != "gateway" || c.Mail.Port != 465 {
		t.Fatalf("defaults %+v", c)
	}
}

func TestValidateAcceptsDevShape(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"db dsn", func(c *Config) { c.DB.DSN = "" }, "db.dsn"},
		{"db sslmode prod", func(c *Config) {
			c.Env = "production"
			c.Valkey.AllowPlaintext = false
			c.Vault.AllowPlaintext = false
			c.Mail.AllowPlaintext = false
		}, "sslmode"},
		{"valkey addresses", func(c *Config) { c.Valkey.Addresses = nil }, "valkey.addresses"},
		{"valkey plaintext prod", func(c *Config) { c.Env = "production"; c.DB.DSN += "&sslmode=verify-full" }, "valkey.allow_plaintext"},
		{"vault address", func(c *Config) { c.Vault.Address = "" }, "vault.address"},
		{"vault plaintext prod", func(c *Config) {
			c.Env = "production"
			c.DB.DSN = "postgres://u:p@db/warden?sslmode=verify-full"
			c.Valkey.AllowPlaintext = false
			c.Mail.AllowPlaintext = false
		}, "vault.allow_plaintext"},
		{"vault credential source", func(c *Config) { c.Vault.RoleIDFile = "" }, "vault.role_id"},
		{"vault mount", func(c *Config) { c.Vault.Mount = "" }, "vault.mount"},
		{"gateway service", func(c *Config) { c.Gateway.Service = "" }, "gateway.service"},
		{"gateway issuer", func(c *Config) { c.Gateway.Issuer = "http://x" }, "gateway.issuer"},
		{"share origin", func(c *Config) { c.Share.PublicOrigin = "ftp://x" }, "share.public_origin"},
		{"share validity", func(c *Config) { c.Share.DefaultValiditySeconds = 60 }, "share.default_validity_seconds"},
		{"share opens", func(c *Config) { c.Share.DefaultMaxOpens = 11 }, "share.default_max_opens"},
		{"transfer limit", func(c *Config) { c.Limits.TransferMaxBytes = 1 << 20 }, "transfer_max_bytes"},
		{"request limit below transfer", func(c *Config) { c.Config.Limits.MaxRequestBytes = 1 << 20 }, "max_request_bytes"},
		{"lookup rate", func(c *Config) { c.Limits.LookupRatePerMinute = 0 }, "lookup_rate_per_minute"},
		{"mail transport", func(c *Config) { c.Mail.Transport = "carrier-pigeon" }, "mail.transport"},
		{"mail plaintext prod", func(c *Config) {
			c.Env = "production"
			c.DB.DSN = "postgres://u:p@db/warden?sslmode=verify-full"
			c.Valkey.AllowPlaintext = false
			c.Vault.AllowPlaintext = false
			c.Vault.Address = "https://vault:8200"
		}, "mail.allow_plaintext"},
	}
	for _, tc := range cases {
		c := valid()
		tc.mut(&c)
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestWarningsAndLoad(t *testing.T) {
	c := valid()
	w := c.Warnings()
	joined := strings.Join(w, "\n")
	for _, want := range []string{"vault.allow_plaintext", "valkey.allow_plaintext", "mail.allow_plaintext"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warning %q missing in %v", want, w)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	_ = os.WriteFile(path, []byte("service_name: warden\nvault:\n  address: http://127.0.0.1:8200\n  mount: kv\n"), 0o600)
	got, err := Load(path)
	if err != nil || got.Vault.Mount != "kv" || got.Share.DefaultMaxOpens != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	_ = os.WriteFile(path, []byte("vault:\n  nope: 1\n"), 0o600)
	if _, err := Load(path); err == nil {
		t.Fatal("unknown field must be refused")
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("missing file")
	}
}
