# Warden operations

## Configuration (`deploy/dev.yaml`)

| Key | Meaning |
|-----|---------|
| `db.dsn`, `db.migrate_dsn` | application role (no `BYPASSRLS`) and migration role; production requires `sslmode=verify-full` |
| `valkey.*` | rate counters (share opens, lookups); TLS unless `allow_plaintext` |
| `vault.address`, `vault.mount` | Vault URL and KV v2 mount (`warden`); `https` unless `allow_plaintext` (development only); optional `ca_file` |
| `vault.role_id_file` / `vault.secret_id_file` or `vault.role_id_secret` / `vault.secret_id_secret` | AppRole credentials from files (0600) or environment variables named by the `*_secret` keys; exactly one source each |
| `gateway.service`, `gateway.issuer` | gateway service name for discovery and the platform token issuer |
| `share.public_origin`, `share.default_validity_seconds`, `share.default_max_opens` | origin of share links and defaults (1 h, 1 reveal) |
| `mail.transport` | how share links are mailed: `notification` (default; the notification module sends the `warden.share` system template) or `log` (development only, refused in production; logs recipient and template, never the link). `smtp` is read as `notification`. The old relay keys `mail.host`, `port`, `username`, `password`, `from`, `allow_plaintext` are accepted, ignored and named in one start-up warning (dropped in v5) |
| `limits.max_request_bytes` | must be ≥ `limits_warden.transfer_max_bytes` (16 MiB) so Bitwarden and backup uploads pass the Freya HTTP server; the gateway edge needs the same |
| `limits_warden.transfer_max_bytes`, `limits_warden.lookup_rate_per_minute` | upload cap (4–64 MiB) and per-subject rate for share opens |

## Vault

- `deploy/vault-init.sh` (dev) mounts `warden` (KV v2), writes the policy from
  `specs/005-warden-secrets/contracts/vault-layout.md` and creates the AppRole
  `warden`, leaving `deploy/.vault/{role_id,secret_id}` (0600).
- The service logs in at start, renews its token with the Vault lifetime
  watcher and logs in again when renewal ends or fails. Health reports
  `ok | sealed | unreachable | unauthenticated`.
- **AppRole rotation**: create a new secret id (`vault write -f
  auth/approle/role/warden/secret-id`), replace the file (or the environment
  variable) and restart the service; old secret ids can then be destroyed.
  Policy changes take effect on the next login.
- `wardensvc bootstrap` applies migrations, then writes, reads and destroys a
  probe secret under a reserved tenant id and prints the health document; a
  non-zero exit means the vault policy or credentials are wrong.

## Reconciliation and sweeping

- Writes are two-phase: row (version 0) → vault put → version row + current
  version. `Reconcile` (every minute) settles rows older than two minutes
  still at version 0 (adopting vault versions or removing orphans) and rows
  soft-deleted while the vault was down (destroying the material, then the
  row). The health route and `wardensvc bootstrap` never touch tenant data.
- Shares expire by time; the sweeper marks lapsed active shares every minute
  (opens are refused as soon as the time passes regardless).

## Backups

- `POST /api/warden/v1/backup/export[?include_material=true]` writes a JSON
  document of the whole tenant (`backup:manage`); with material it contains
  every password version and seed and must be handled as a secret. Import
  remaps every id, recreates folders in path order, writes material to the
  vault in version order or records `material_missing`, keeps grants and
  reports counts and warnings per entity.
- Moving a warden v3 tenant into v4 (one-off, `wardensvc export-v3` /
  `import-v3`): see [migration-v3.md](migration-v3.md).
- Database backups alone are useless without the vault: the two must be
  restored together, or a warden backup with material used instead.

## Permissions and module roles

Warden registers with the auth service as module `warden` (auth SDK
`authclient.Registration`, feature 019) at start, retrying every 5 s until
auth accepts, and then every five minutes so tenants created later receive
the roles and grants. The registration carries the API permissions, the
module roles and the built-in role grants (owner, admin: everything; member:
secrets:read/write/share, folders:manage, permissions:manage; auditor,
operator: stats:read).

Module roles (locked in auth; administrators assign them or clone them into
custom roles in the auth console):

| Role | Display name | Permissions |
|---|---|---|
| `administrator` | Warden administrator | all ten warden permissions |
| `editor` | Warden editor | secrets:read, secrets:write, secrets:share, folders:manage, permissions:manage |
| `viewer` | Warden viewer | secrets:read |

A role only opens the API; access to individual secrets and folders is still
decided by warden's own grants. Skipped built-in grants (warn) and rejected
roles (error) are logged as `auth registration: ...`.

## Gateway

Allow-list the module (`gatewaysvc bootstrap -allow
"spiffe://example.org/svc/warden=/api/warden,/warden/share,/ui;warden"`), raise
the gateway edge body limit to 16 MiB + slack (`limits.max_request_bytes:
16842752`), and keep `forward.module_timeout` at 30 s: the transfer and backup
routes declare their own 120 s timeout in the manifest.


## Share mail through the notification module (feature 017)

warden has no mail relay of its own. A share link is sent by the notification
module (`notification.v1.Notifier/Send` over the mTLS mesh) as the system
template `warden.share` for the share's tenant, with the share id as the
correlation id. Variables:

| Variable | Content |
|----------|---------|
| `link` | `https://<share.public_origin>/warden/share#<token>`; a **secret** variable, redacted in notification's delivery log and audit |
| `secret_name` | the shared secret's name |
| `expires` | expiry, RFC 1123 in UTC |
| `openings` | the reveal budget |
| `message` | the sender's message; omitted when empty |

- The relay (host, TLS, credentials, sender address) is configured once, in
  notification's `platform_email`; a tenant's own enabled email channel takes
  precedence. The wording of the mail is edited in notification's template
  UI.
- Discovery must resolve `notification`; the notification policy must allow
  `svc/warden` on `Send` (it does by default). warden connects on the first
  share, so it starts and serves everything else while notification is down.
- Only a confirmed delivery creates a share. When notification is
  unreachable, throttled, refuses the send (unknown key, email not
  configured) or the relay fails (temporary or permanent), the share is
  cancelled, audited as `share_created` with outcome `failed` / reason
  `mail_failed`, and the user gets `503 temporarily_unavailable`: the link is
  only ever mailed, so an unsent share could not be opened anyway. warden
  logs the template, tenant, share id and notification's (scrubbed) reason,
  never the link; the failed attempt is in notification's delivery log under
  the same correlation id.
- Upgrading: remove `mail.host` … `mail.allow_plaintext` and set
  `mail.transport: notification`; until then warden starts with one warning
  naming the ignored keys.
