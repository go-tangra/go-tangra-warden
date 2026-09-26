package wardenmanifest_test

import (
	"slices"
	"testing"

	"github.com/go-tangra/go-tangra-warden/v4/pkg/wardenmanifest"
)

// TestRoles checks the module role set (feature 019, research D9): slugs,
// display names and permissions, all of them warden's own.
func TestRoles(t *testing.T) {
	want := map[string]struct {
		name  string
		perms []string
	}{
		"administrator": {"Warden administrator", wardenmanifest.PermissionRefs()},
		"editor":        {"Warden editor", []string{"secrets:read", "secrets:write", "secrets:share", "folders:manage", "permissions:manage"}},
		"viewer":        {"Warden viewer", []string{"secrets:read"}},
	}
	own := map[string]bool{}
	for _, p := range wardenmanifest.PermissionRefs() {
		own[p] = true
	}
	if len(wardenmanifest.Roles) != len(want) {
		t.Fatalf("%d roles, want %d", len(wardenmanifest.Roles), len(want))
	}
	for _, r := range wardenmanifest.Roles {
		w, ok := want[r.Slug]
		if !ok {
			t.Fatalf("unexpected role %q", r.Slug)
		}
		if r.DisplayName != w.name || r.Description == "" {
			t.Errorf("%s: name %q, description %q", r.Slug, r.DisplayName, r.Description)
		}
		if !slices.Equal(r.Permissions, w.perms) {
			t.Errorf("%s: %v, want %v", r.Slug, r.Permissions, w.perms)
		}
		for _, p := range r.Permissions {
			if !own[p] {
				t.Errorf("%s names %q, not a warden permission", r.Slug, p)
			}
		}
	}
}

// TestRegistration checks the registration sent to auth: module identity,
// every permission, the role set and the built-in grants; auth's rules hold.
func TestRegistration(t *testing.T) {
	reg := wardenmanifest.Registration()
	if err := reg.Validate(); err != nil {
		t.Fatal(err)
	}
	if reg.Module != "warden" || reg.DisplayName != "Warden" || len(reg.Permissions) != len(wardenmanifest.Permissions) || len(reg.Roles) != 3 {
		t.Fatalf("%+v", reg)
	}
	for i, p := range wardenmanifest.Permissions {
		if got := reg.Permissions[i]; got.Resource != p.Resource || got.Action != p.Action || got.Description != p.Description {
			t.Errorf("permission %d: %+v", i, got)
		}
	}
	for _, slug := range []string{"owner", "admin", "member", "auditor", "operator"} {
		if !slices.Equal(reg.BuiltinGrants[slug], wardenmanifest.Grants[slug]) {
			t.Errorf("grant %s: %v", slug, reg.BuiltinGrants[slug])
		}
	}
}
