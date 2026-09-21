package contract

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/go-freya/freya/services/gateway/api/schema"
	"github.com/go-freya/freya/services/warden/pkg/wardenmanifest"
)

// TestManifestMatchesContract builds the manifest from the OpenAPI document
// and checks it against contracts/manifest.md and the gateway schema.
func TestManifestMatchesContract(t *testing.T) {
	m, err := wardenmanifest.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if m.Module != "warden" || m.Version != "1.1.0" || len(m.Prefixes) != 2 || len(m.Permissions) != 10 || len(m.Abilities) != 7 || len(m.Nav) != 3 || len(m.Methods) != 3 {
		t.Fatalf("%+v", m)
	}
	byKey := map[string]int{}
	for i, r := range m.Routes {
		byKey[r.Method+" "+r.Path] = i
	}
	check := func(key string, perm string, public bool, body uint64, addr bool) {
		t.Helper()
		i, ok := byKey[key]
		if !ok {
			t.Fatalf("%s missing", key)
		}
		r := m.Routes[i]
		if r.Permission != perm || r.Public != public || r.MaxBodyBytes != body || r.ClientAddress != addr {
			t.Errorf("%s: %+v", key, r)
		}
	}
	check("POST /api/warden/v1/transfer/bitwarden/validate", "transfer:import", false, 16777216, false)
	check("POST /api/warden/v1/transfer/bitwarden/import", "transfer:import", false, 16777216, false)
	check("POST /api/warden/v1/backup/import", "backup:manage", false, 16777216, false)
	check("POST /api/warden/v1/share/open", "", true, 0, true)
	check("GET /warden/share", "", true, 0, false)
	check("GET /api/warden/v1/secrets/{id}/password", "secrets:read", false, 0, false)
	check("POST /api/warden/v1/secrets/{id}/remove", "secrets:delete", false, 0, false)
	for _, r := range m.Routes {
		if r.ClientAddress && r.Path != "/api/warden/v1/share/open" {
			t.Errorf("client address leaks to %s", r.Path)
		}
		if strings.Contains(r.Path, "/transfer/") || strings.Contains(r.Path, "/backup/") {
			if r.Timeout != 120*time.Second {
				t.Errorf("%s: timeout %s", r.Path, r.Timeout)
			}
		} else if r.Timeout != 0 {
			t.Errorf("%s: unexpected timeout", r.Path)
		}
	}
	// Every ability and nav entry requires a declared permission; grants only name declared ones.
	perms := map[string]bool{}
	for _, p := range wardenmanifest.PermissionRefs() {
		perms[p] = true
	}
	for _, a := range m.Abilities {
		if !perms[a.Requires] {
			t.Errorf("ability requires %q", a.Requires)
		}
	}
	for _, n := range m.Nav {
		if !perms[n.Requires] {
			t.Errorf("nav requires %q", n.Requires)
		}
	}
	for role, refs := range wardenmanifest.Grants {
		for _, ref := range refs {
			if !perms[ref] {
				t.Errorf("grant %s → %q", role, ref)
			}
		}
	}
	// The wire form satisfies the gateway's published manifest schema.
	pm, err := m.Proto()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(pm)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema.Manifest))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("manifest.schema.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("manifest.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	// protojson writes uint64 as a string; the gateway converts before validating.
	for _, r := range inst.(map[string]any)["routes"].([]any) {
		rm := r.(map[string]any)
		if v, ok := rm["max_body_bytes"].(string); ok {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			rm["max_body_bytes"] = json.Number(strconv.FormatInt(n, 10))
		}
	}
	if err := s.Validate(inst); err != nil {
		t.Fatalf("manifest refused by the gateway schema: %v", err)
	}
}
