package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra/v4/authz"
	"github.com/go-tangra/go-tangra/v4/catalogue"

	"github.com/go-tangra/go-tangra-warden/v4/internal/config"
	"github.com/go-tangra/go-tangra-warden/v4/pkg/wardenmanifest"
)

var placeholderRE = regexp.MustCompile(`\$\{([A-Z][A-Z0-9_]*)\}`)

// tangra-module.yaml is a valid descriptor for this module: its name is the
// registered module name and its routes cover the manifest's prefixes.
func TestCatalogueDescriptor(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "tangra-module.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := catalogue.ParseDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := wardenmanifest.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if d.Module != wardenmanifest.Module || d.DisplayName != m.DisplayName {
		t.Fatalf("descriptor %s/%s, manifest %s/%s", d.Module, d.DisplayName, m.Module, m.DisplayName)
	}
	for _, p := range m.Prefixes {
		covered := false
		for _, r := range d.Routes.Prefixes {
			covered = covered || p == r || strings.HasPrefix(p, r+"/")
		}
		if !covered {
			t.Errorf("manifest prefix %s is outside routes.prefixes %v", p, d.Routes.Prefixes)
		}
	}
}

// The join bundle's templates, rendered with values of the shape the gateway
// fills in (core values, generated passwords, host inputs), are a valid
// production configuration and policy.
func TestJoinBundleRendersToValidProductionConfig(t *testing.T) {
	values := map[string]string{
		"TRUST_DOMAIN": "infra.example.org", "GATEWAY_ISSUER": "https://portal.example.org:8443",
		"LCM_ENROLL_URL": "https://portal.example.org:8443/api/lcm/v1/enroll", "LCM_GRPC": "portal.example.org:9945",
		"GATEWAY_GRPC": "portal.example.org:9643", "AUTH_GRPC": "portal.example.org:9543", "MESH_TENANT_ID": "00000000-0000-0000-0000-000000000001",
		"GEN_PASSWORD_1": strings.Repeat("a", 48), "GEN_PASSWORD_2": strings.Repeat("b", 48), "GEN_PASSWORD_3": strings.Repeat("c", 48),
		"VAULT_ADDR": "https://vault.example.org:8200", "VAULT_MOUNT": "warden", "NOTIFICATION_GRPC": "portal.example.org:9943",
	}
	// Every host input is declared, and the values used here pass its pattern.
	raw, err := os.ReadFile(filepath.Join("..", "..", "tangra-module.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := catalogue.ParseDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[string]string{"MODULE_ADVERTISE_HOST": "warden.example.org", "MODULE_BIND_IP": "10.0.0.5",
		"VAULT_ADDR": values["VAULT_ADDR"], "VAULT_MOUNT": values["VAULT_MOUNT"], "NOTIFICATION_GRPC": values["NOTIFICATION_GRPC"]}
	if len(d.HostInputs) != len(inputs) {
		t.Fatalf("host_inputs %v, test covers %v", d.HostInputs, inputs)
	}
	for _, in := range d.HostInputs {
		if v, ok := inputs[in.Key]; !ok || !regexp.MustCompile(in.Pattern).MatchString(v) {
			t.Fatalf("host input %s: %q", in.Key, v)
		}
	}
	// compose.yaml is interpolated from .env: it may use only known values.
	known := map[string]bool{"MODULE_IMAGE": true, "MODULE_VERSION": true}
	for k := range values {
		known[k] = true
	}
	for k := range inputs {
		known[k] = true
	}
	compose, err := os.ReadFile(filepath.Join("..", "..", "deploy", "bundle", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range placeholderRE.FindAllStringSubmatch(string(compose), -1) {
		if !known[m[1]] {
			t.Errorf("compose.yaml uses %s, which the gateway does not write to .env", m[1])
		}
	}
	dir := t.TempDir()
	for _, name := range []string{"config.yaml", "policy.yaml"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "bundle", name))
		if err != nil {
			t.Fatal(err)
		}
		var missing []string
		rendered := placeholderRE.ReplaceAllStringFunc(string(raw), func(m string) string {
			k := placeholderRE.FindStringSubmatch(m)[1]
			v, ok := values[k]
			if !ok {
				missing = append(missing, k)
			}
			return v
		})
		if len(missing) > 0 {
			t.Fatalf("%s uses placeholders the gateway does not fill: %v", name, missing)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(rendered), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.Load(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("rendered config invalid: %v", err)
	}
	if !cfg.IsProduction() || cfg.Gateway.Issuer != "https://portal.example.org:8443" || !cfg.Enroll.Enabled ||
		cfg.Vault.Address != "https://vault.example.org:8200" || cfg.Discovery.Static["notification"][0] != "portal.example.org:9943" {
		t.Fatalf("%+v %+v %+v", cfg.Gateway, cfg.Enroll, cfg.Vault)
	}
	pol, _ := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	if _, err := authz.Load(bytes.NewReader(pol)); err != nil {
		t.Fatalf("rendered policy invalid: %v", err)
	}
	if !strings.Contains(string(pol), "spiffe://infra.example.org/svc/gateway") {
		t.Fatal(string(pol))
	}
}
