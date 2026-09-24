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
| `mail.*` | SMTP relay for share links (`transport: smtp` or `log`; TLS unless `allow_plaintext`) |
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
- Database backups alone are useless without the vault: the two must be
  restored together, or a warden backup with material used instead.

## Permissions seeding

Warden registers its API permissions and the built-in role grants with the
auth service (`RegisterPermissions` with `builtin_grants`) at start and every
five minutes, so tenants created later receive them. Custom roles can be
given individual permissions in the auth console.

## Gateway

Allow-list the module (`gatewaysvc bootstrap -allow
"spiffe://example.org/svc/warden=/api/warden,/warden/share,/ui;warden"`), raise
the gateway edge body limit to 16 MiB + slack (`limits.max_request_bytes:
16842752`), and keep `forward.module_timeout` at 30 s: the transfer and backup
routes declare their own 120 s timeout in the manifest.


## Notification module (feature 006)

Transactional and share mail is still sent directly by warden's own mailer.
When the notification module is deployed, warden's outbound mail (share links,
invitations relayed on its behalf) can move to `pkg/notifyclient` so that all
tenant mail is delivered, templated and audited in one place. This is a
follow-up, out of scope for feature 005; the notification module already
exposes `Notifier/Send` for it.
