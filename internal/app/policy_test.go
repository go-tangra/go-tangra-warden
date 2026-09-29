package app

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type policyDoc struct {
	Rules []struct {
		ID         string   `yaml:"id"`
		From       []string `yaml:"from"`
		To         []string `yaml:"to"`
		Operations []string `yaml:"operations"`
		Effect     string   `yaml:"effect"`
	} `yaml:"rules"`
}

// TestDefaultPolicySigningRule (signing feature 027): signing may call exactly
// Secrets/Get and Secrets/GetPassword (TSA credentials, on behalf of the user).
func TestDefaultPolicySigningRule(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc policyDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, r := range doc.Rules {
		for _, f := range r.From {
			if !strings.HasSuffix(f, "/svc/signing") {
				continue
			}
			found++
			if r.ID != "signing-tsa-secrets" || r.Effect != "allow" || !reflect.DeepEqual(r.To, []string{"warden"}) ||
				!reflect.DeepEqual(r.From, []string{"spiffe://example.org/svc/signing"}) ||
				!reflect.DeepEqual(r.Operations, []string{"/warden.v1.Secrets/Get", "/warden.v1.Secrets/GetPassword"}) {
				t.Fatalf("signing rule is not exact: %+v", r)
			}
		}
	}
	if found != 1 {
		t.Fatalf("want exactly one rule for svc/signing, got %d", found)
	}
}

// TestDefaultPolicyIPAMRule (ipam feature 024): the policy built into the
// image lets ipam call exactly Secrets/Get and Secrets/GetPassword — the
// metadata and password it needs to use a device's BMC credentials on behalf
// of the signed-in user — and nothing else of warden.
func TestDefaultPolicyIPAMRule(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []struct {
			ID         string   `yaml:"id"`
			From       []string `yaml:"from"`
			To         []string `yaml:"to"`
			Operations []string `yaml:"operations"`
			Effect     string   `yaml:"effect"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, r := range doc.Rules {
		ipam := false
		for _, f := range r.From {
			ipam = ipam || strings.HasSuffix(f, "/svc/ipam")
		}
		if !ipam {
			continue
		}
		found++
		if r.ID != "ipam-bmc-secrets" || r.Effect != "allow" || !reflect.DeepEqual(r.To, []string{"warden"}) ||
			!reflect.DeepEqual(r.From, []string{"spiffe://example.org/svc/ipam"}) ||
			!reflect.DeepEqual(r.Operations, []string{"/warden.v1.Secrets/Get", "/warden.v1.Secrets/GetPassword"}) {
			t.Fatalf("ipam rule is not exact: %+v", r)
		}
	}
	if found != 1 {
		t.Fatalf("want exactly one rule for svc/ipam, got %d", found)
	}
}
