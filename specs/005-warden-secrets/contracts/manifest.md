# Gateway manifest (feature 005)

```yaml
module: warden
display_name: Warden
version: 1.1.0
prefixes: ["/api/warden", "/warden/share", "/ui"]      # /ui = federated remote assets (relayed under /m/warden/)
permissions:
  - { resource: secrets,     action: read,   description: "Read secrets and reveal passwords the caller is granted" }
  - { resource: secrets,     action: write,  description: "Create and change secrets the caller is granted" }
  - { resource: secrets,     action: delete, description: "Delete secrets the caller owns" }
  - { resource: secrets,     action: share,  description: "Create external shares of secrets the caller may share" }
  - { resource: folders,     action: manage, description: "Create, move and delete folders the caller is granted" }
  - { resource: permissions, action: manage, description: "Grant and revoke access on resources the caller may share" }
  - { resource: transfer,    action: import, description: "Import Bitwarden exports" }
  - { resource: transfer,    action: export, description: "Export secrets to Bitwarden format (bulk disclosure)" }
  - { resource: backup,      action: manage, description: "Export and import tenant backups (bulk disclosure with material)" }
  - { resource: stats,       action: read,   description: "Read statistics and the audit trail" }
abilities:
  - { action: [read, create, update, delete, share], subject: [Secret], requires: "secrets:read" }   # refined client-side by grants
  - { action: [manage], subject: [Folder], requires: "folders:manage" }
  - { action: [manage], subject: [Grant], requires: "permissions:manage" }
  - { action: [import], subject: [Transfer], requires: "transfer:import" }
  - { action: [export], subject: [Transfer], requires: "transfer:export" }
  - { action: [manage], subject: [Backup], requires: "backup:manage" }
  - { action: [read], subject: [Stats, WardenAudit], requires: "stats:read" }   # subjects are platform-unique (AuditEvent belongs to auth)
nav:
  - { title: Secrets,     path: /warden,             icon: mdi-key-variant,             order: 100, requires: "secrets:read" }
  - { title: Permissions, path: /warden/permissions, icon: mdi-shield-account-outline,  order: 120, requires: "permissions:manage" }
  - { title: Generator,   path: /warden/generator,   icon: mdi-dice-multiple-outline,   order: 130, requires: "secrets:read" }
routes: derived from warden-api.openapi.yaml: every operation carries `x-freya-permission`
        (or `x-freya-public: true` for GET /warden/share and POST /api/warden/v1/share/open);
        transfer and backup routes carry `x-freya-max-body-bytes: 16777216`.
methods:
  - { full_method: /warden.v1.Secrets/Get,         permission: "secrets:read" }
  - { full_method: /warden.v1.Secrets/GetPassword, permission: "secrets:read" }
  - { full_method: /warden.v1.Secrets/Check,       permission: "secrets:read" }
remote: { entry: /m/warden/mf-manifest.json, exposes: ["./routes", "./nav"] }
```

Built-in role grants (research R12): owner/admin all; member `secrets:read`,
`secrets:write`, `secrets:share`, `folders:manage`, `permissions:manage`;
auditor and operator `stats:read`. Warden seeds them itself through
`auth.v1.Authorization/RegisterPermissions` (`builtin_grants`, see
auth-changes.md) at start-up and every five minutes.

## Client address for share policies

The gateway forwards only a hashed client (`X-Gateway-Client`). For CIDR
policies the gateway adds `X-Gateway-Client-Addr` (the client IP, trusted only
from the gateway peer) to requests of routes flagged `x-freya-client-address:
true`; this is a gateway change recorded in `auth-changes.md` §Gateway. Region
policies use the country the gateway resolves from that address when a GeoIP
source is configured; without one, region policies are refused at share
creation ("region policies unavailable").
