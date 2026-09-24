package contract

import (
	"testing"

	"github.com/go-tangra/go-tangra-warden/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-warden/v4/pkg/wardenmanifest"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
)

// TestOpenAPIDocument proves the contract parses, every operation has an id,
// responses and exactly one protection (a declared permission or public), and
// the mounted route table equals the declared one.
func TestOpenAPIDocument(t *testing.T) {
	doc, err := httpapi.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	perms := map[string]bool{}
	for _, p := range wardenmanifest.PermissionRefs() {
		perms[p] = true
	}
	for p, item := range doc.Paths.Map() {
		for m, op := range item.Operations() {
			if op.OperationID == "" {
				t.Errorf("%s %s: missing operationId", m, p)
			}
			if op.Responses == nil || op.Responses.Len() == 0 {
				t.Errorf("%s %s: no responses", m, p)
			}
			perm, _ := op.Extensions[httpapi.PermissionExtension].(string)
			public, _ := op.Extensions[httpapi.PublicExtension].(bool)
			switch {
			case public && perm != "":
				t.Errorf("%s %s: both public and protected", m, p)
			case !public && !perms[perm]:
				t.Errorf("%s %s: permission %q not in the manifest", m, p, perm)
			}
		}
	}
	s, err := httpapi.NewHandler(testrt.New(t, testutil.MustCA("example.org"), "warden"))
	if err != nil {
		t.Fatal(err)
	}
	declared := httpapi.DeclaredRoutes(doc)
	if len(declared) != len(s.Declared()) {
		t.Fatalf("declared %d mounted %d", len(declared), len(s.Declared()))
	}
	set := map[httpapi.Route]bool{}
	for _, r := range declared {
		set[r] = true
	}
	for _, r := range s.Implemented() {
		if !set[r] {
			t.Errorf("mounted but undeclared: %s", r)
		}
	}
	// Public routes are exactly the two share routes.
	pub := httpapi.PublicRoutes(doc)
	if len(pub) != 2 || !pub[httpapi.Route{Method: "GET", Path: "/warden/share"}] || !pub[httpapi.Route{Method: "POST", Path: "/api/warden/v1/share/open"}] {
		t.Fatalf("public routes: %v", pub)
	}
}
