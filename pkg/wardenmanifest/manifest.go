// Package wardenmanifest declares what the warden module registers with the
// application gateway: routes derived from the embedded OpenAPI document, the
// API permissions, the CASL abilities the shell derives from them, the
// navigation entries and the gRPC methods (contracts/manifest.md). It is
// public so contract tests and the gateway can validate it.
package wardenmanifest

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/go-tangra/go-tangra-portal/sdk/v4/pkg/gatewayclient"
	"github.com/go-tangra/go-tangra-warden/v4/api/openapi"
)

// Module is the registered module name.
const (
	Module      = "warden"
	DisplayName = "Warden"
	Version     = "1.1.0"
	// RemotePrefix is where the module serves its federated remote assets.
	RemotePrefix = "/ui"
)

// OpenAPI operation extensions read by the builder.
const (
	PermissionExtension    = "x-freya-permission"
	PublicExtension        = "x-freya-public"
	BodyLimitExtension     = "x-freya-max-body-bytes"
	ClientAddressExtension = "x-freya-client-address"
	TimeoutExtension       = "x-freya-timeout-seconds"
)

// Permissions the module registers (granted to built-in roles by the auth service).
var Permissions = []gatewayclient.Permission{
	{Resource: "secrets", Action: "read", Description: "Read secrets and reveal passwords the caller is granted"},
	{Resource: "secrets", Action: "write", Description: "Create and change secrets the caller is granted"},
	{Resource: "secrets", Action: "delete", Description: "Delete secrets the caller owns"},
	{Resource: "secrets", Action: "share", Description: "Create external shares of secrets the caller may share"},
	{Resource: "folders", Action: "manage", Description: "Create, move and delete folders the caller is granted"},
	{Resource: "permissions", Action: "manage", Description: "Grant and revoke access on resources the caller may share"},
	{Resource: "transfer", Action: "import", Description: "Import Bitwarden exports"},
	{Resource: "transfer", Action: "export", Description: "Export secrets to Bitwarden format (bulk disclosure)"},
	{Resource: "backup", Action: "manage", Description: "Export and import tenant backups (bulk disclosure with material)"},
	{Resource: "stats", Action: "read", Description: "Read statistics and the audit trail"},
}

// Grants maps built-in role slugs to the permission references they hold
// (research R12); the auth service seeds them on permission registration.
var Grants = map[string][]string{
	"owner":    PermissionRefs(),
	"admin":    PermissionRefs(),
	"member":   {"secrets:read", "secrets:write", "secrets:share", "folders:manage", "permissions:manage"},
	"auditor":  {"stats:read"},
	"operator": {"stats:read"},
}

// Methods are the gRPC methods exposed through the gateway.
var Methods = []gatewayclient.Method{
	{FullMethod: "/warden.v1.Secrets/Get", Permission: "secrets:read"},
	{FullMethod: "/warden.v1.Secrets/GetPassword", Permission: "secrets:read"},
	{FullMethod: "/warden.v1.Secrets/Check", Permission: "secrets:read"},
}

// Abilities are the CASL rules bound to the permissions.
var Abilities = []gatewayclient.Ability{
	{Action: []string{"read", "create", "update", "delete", "share"}, Subject: []string{"Secret"}, Requires: "secrets:read"},
	{Action: []string{"manage"}, Subject: []string{"Folder"}, Requires: "folders:manage"},
	{Action: []string{"manage"}, Subject: []string{"Grant"}, Requires: "permissions:manage"},
	{Action: []string{"import"}, Subject: []string{"Transfer"}, Requires: "transfer:import"},
	{Action: []string{"export"}, Subject: []string{"Transfer"}, Requires: "transfer:export"},
	{Action: []string{"manage"}, Subject: []string{"Backup"}, Requires: "backup:manage"},
	{Action: []string{"read"}, Subject: []string{"Stats", "WardenAudit"}, Requires: "stats:read"},
}

// Nav lists the navigation contributions.
var Nav = []gatewayclient.NavEntry{
	// Folders are managed inside the secrets explorer (two panes: tree, contents).
	{Title: "Secrets", Path: "/warden", Icon: "mdi-key-variant", Order: 100, Requires: "secrets:read"},
	{Title: "Permissions", Path: "/warden/permissions", Icon: "mdi-shield-account-outline", Order: 120, Requires: "permissions:manage"},
	{Title: "Generator", Path: "/warden/generator", Icon: "mdi-dice-multiple-outline", Order: 130, Requires: "secrets:read"},
}

// PermissionRefs lists "resource:action" for every declared permission.
func PermissionRefs() []string {
	out := make([]string, 0, len(Permissions))
	for _, p := range Permissions {
		out = append(out, p.Resource+":"+p.Action)
	}
	return out
}

// Routes derives the gateway routes from the OpenAPI document: every
// operation carries x-freya-permission (one of Permissions) or
// x-freya-public; x-freya-max-body-bytes and x-freya-client-address map to
// the route fields. Undeclared permissions are an error.
func Routes(doc *openapi3.T) ([]gatewayclient.Route, error) {
	known := map[string]bool{}
	for _, p := range PermissionRefs() {
		known[p] = true
	}
	var routes []gatewayclient.Route
	for p, item := range doc.Paths.Map() {
		for m, op := range item.Operations() {
			r := gatewayclient.Route{Method: strings.ToUpper(m), Path: p}
			perm, _ := op.Extensions[PermissionExtension].(string)
			public, _ := op.Extensions[PublicExtension].(bool)
			switch {
			case public && perm != "":
				return nil, fmt.Errorf("wardenmanifest: %s %s is both public and protected", r.Method, p)
			case public:
				r.Public = true
			case perm == "":
				return nil, fmt.Errorf("wardenmanifest: %s %s declares no permission", r.Method, p)
			case !known[perm]:
				return nil, fmt.Errorf("wardenmanifest: %s %s uses undeclared permission %q", r.Method, p, perm)
			default:
				r.Permission = perm
			}
			if v, ok := op.Extensions[BodyLimitExtension]; ok {
				n, ok := v.(float64)
				if !ok || n <= 0 {
					return nil, fmt.Errorf("wardenmanifest: %s %s has a bad body limit", r.Method, p)
				}
				r.MaxBodyBytes = uint64(n)
			}
			if v, ok := op.Extensions[ClientAddressExtension].(bool); ok && v {
				r.ClientAddress = true
			}
			if v, ok := op.Extensions[TimeoutExtension]; ok {
				n, ok := v.(float64)
				if !ok || n <= 0 || n > 600 {
					return nil, fmt.Errorf("wardenmanifest: %s %s has a bad timeout", r.Method, p)
				}
				r.Timeout = time.Duration(n) * time.Second
			}
			routes = append(routes, r)
		}
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Method+" "+routes[i].Path < routes[j].Method+" "+routes[j].Path })
	return routes, nil
}

// Load parses the embedded document.
func Load() (*openapi3.T, error) {
	return openapi3.NewLoader().LoadFromData(openapi.Warden)
}

// Manifest builds the gateway manifest from the embedded OpenAPI document.
func Manifest() (gatewayclient.Manifest, error) {
	doc, err := Load()
	if err != nil {
		return gatewayclient.Manifest{}, err
	}
	routes, err := Routes(doc)
	if err != nil {
		return gatewayclient.Manifest{}, err
	}
	return gatewayclient.Manifest{
		Module: Module, DisplayName: DisplayName, Version: Version,
		Prefixes:    []string{"/api/warden", "/warden/share"},
		Routes:      routes,
		Methods:     Methods,
		Permissions: Permissions,
		Abilities:   Abilities,
		Exposes:     []string{"./routes", "./nav"},
		Nav:         Nav,
	}, nil
}
