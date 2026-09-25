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
	return c
}

func TestDefaultsAreSecure(t *testing.T) {
	c := Default()
	if c.Vault.AllowPlaintext || c.Valkey.AllowPlaintext {
		t.Fatal("plaintext must be opt-in")
	}
	if c.Vault.Mount != "warden" || c.Share.DefaultValiditySeconds != 3600 || c.Share.DefaultMaxOpens != 1 || c.Limits.TransferMaxBytes != 16<<20 || c.Limits.LookupRatePerMinute != 120 || c.Gateway.Service != "gateway" ||
		c.Mail.Transport != "notification" || c.Mail.IgnoredRelayKeys() != nil {
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
		}, "sslmode"},
		{"valkey addresses", func(c *Config) { c.Valkey.Addresses = nil }, "valkey.addresses"},
		{"valkey plaintext prod", func(c *Config) { c.Env = "production"; c.DB.DSN += "&sslmode=verify-full" }, "valkey.allow_plaintext"},
		{"vault address", func(c *Config) { c.Vault.Address = "" }, "vault.address"},
		{"vault plaintext prod", func(c *Config) {
			c.Env = "production"
			c.DB.DSN = "postgres://u:p@db/warden?sslmode=verify-full"
			c.Valkey.AllowPlaintext = false
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
		{"mail log prod", func(c *Config) {
			c.Env = "production"
			c.DB.DSN = "postgres://u:p@db/warden?sslmode=verify-full"
			c.Valkey.AllowPlaintext = false
			c.Vault.AllowPlaintext = false
			c.Vault.Address = "https://vault:8200"
			c.Mail.Transport = "log"
		}, "mail.transport"},
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
	for _, want := range []string{"vault.allow_plaintext", "valkey.allow_plaintext"} {
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

func production() Config {
	c := valid()
	c.Env = "production"
	c.DB.DSN = "postgres://u:p@db/warden?sslmode=verify-full"
	c.Valkey.AllowPlaintext = false
	c.Vault.AllowPlaintext = false
	c.Vault.Address = "https://vault:8200"
	return c
}

func mailWarnings(c Config) []string {
	var out []string
	for _, w := range c.Warnings() {
		if strings.HasPrefix(w, "mail.") {
			out = append(out, w)
		}
	}
	return out
}

func TestMailTransport(t *testing.T) {
	// notification is the default and needs nothing else.
	if err := production().Validate(); err != nil {
		t.Fatal(err)
	}
	if w := mailWarnings(production()); len(w) != 0 {
		t.Fatalf("no relay keys, no warning: %v", w)
	}
	// log is accepted for development only.
	c := valid()
	c.Mail.Transport = "log"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	// smtp and the old relay keys are accepted (even in production and with
	// allow_plaintext: they are ignored) and reported in one warning.
	c = production()
	c.Mail = Mail{Transport: "smtp", Host: "mx01.example.net", Port: 25, Username: "u", Password: "RELAY-PASSWORD", From: "warden@example.org", AllowPlaintext: true}
	if err := c.Validate(); err != nil {
		t.Fatalf("ignored relay keys refused: %v", err)
	}
	w := mailWarnings(c)
	if len(w) != 1 {
		t.Fatalf("want one mail warning, got %v", w)
	}
	for _, key := range []string{"mail.transport: smtp", "host", "port", "username", "password", "from", "allow_plaintext", "notification"} {
		if !strings.Contains(w[0], key) {
			t.Errorf("warning %q misses %q", w[0], key)
		}
	}
	if strings.Contains(w[0], "RELAY-PASSWORD") || strings.Contains(w[0], "mx01") {
		t.Fatalf("warning carries values: %q", w[0])
	}
	if got := c.Mail.IgnoredRelayKeys(); strings.Join(got, ",") != "host,port,username,password,from,allow_plaintext" {
		t.Fatalf("ignored keys %v", got)
	}
	// Only the keys actually set are listed.
	c = valid()
	c.Mail.Host = "relay"
	if w := mailWarnings(c); len(w) != 1 || strings.Contains(w[0], "username") || !strings.Contains(w[0], "host") {
		t.Fatalf("partial keys: %v", w)
	}
	// smtp alone (no relay keys) still warns: it now means notification.
	c = valid()
	c.Mail.Transport = "smtp"
	if w := mailWarnings(c); len(w) != 1 || !strings.Contains(w[0], "smtp") {
		t.Fatalf("smtp alone: %v", w)
	}
	// The strict decoder still accepts the old keys.
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	_ = os.WriteFile(path, []byte("mail:\n  transport: smtp\n  host: mx\n  port: 587\n  username: u\n  password: p\n  from: a@b\n  allow_plaintext: true\n"), 0o600)
	got, err := Load(path)
	if err != nil || got.Mail.Transport != "smtp" || got.Mail.Host != "mx" {
		t.Fatalf("%+v %v", got.Mail, err)
	}
}
