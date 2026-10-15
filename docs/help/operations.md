---
title: Operate warden
summary: Configuration keys and defaults, HashiCorp Vault setup, service policies, backups and fixes for common start-up, vault and share-mail problems.
kind: reference
order: 90
tags: [warden, operations, configuration, vault, policy, troubleshooting]
audience: operator
---
Warden runs as `wardensvc` (image `ghcr.io/go-tangra/go-tangra-warden`, user
uid 10001).

```sh
wardensvc -config /app/config.yaml               # serve; applies migrations (-no-migrate to skip)
wardensvc bootstrap -config /app/config.yaml     # migrate, probe the vault, print health, exit
wardensvc version
```

`wardensvc export-v3` and `import-v3` move a warden v3 tenant into v4 once
(see `docs/migration-v3.md` in the repository).

It needs PostgreSQL/TimescaleDB, Valkey, an existing HashiCorp Vault (not
part of the module bundle), and on the mesh: auth (token keys, revocations,
module registration), the gateway (registration) and notification (share
mail).

## Configuration

YAML; unknown keys are refused. Besides the framework keys (`service_name`,
`trust_domain`, `env`, `identity`, `authz`, `server`, `admin`, `discovery`,
`limits`) warden reads:

| Key | Default | Notes |
|---|---|---|
| `db.dsn` | — | required; application role without `BYPASSRLS`; production needs `sslmode=verify-full` or `verify-ca` |
| `db.migrate_dsn` | `db.dsn` | migration role |
| `db.max_conns` | 16 | |
| `valkey.addresses` | — | required; rate counters for share opens |
| `valkey.username`, `valkey.password`, `valkey.ca_file` | — | TLS |
| `valkey.allow_plaintext` | false | refused in production |
| `vault.address` | — | required, `https://` (plain `http://` only with `vault.allow_plaintext`, refused in production) |
| `vault.mount` | `warden` | KV v2 mount, one path segment |
| `vault.role_id_file`, `vault.secret_id_file` | — | AppRole credentials from files (mode 0600) |
| `vault.role_id_secret`, `vault.secret_id_secret` | — | or the names of environment variables holding them; exactly one source each |
| `vault.ca_file` | — | CA of the vault's certificate |
| `gateway.service` | `gateway` | mesh name of the gateway; the only peer allowed to fetch the help pages |
| `gateway.issuer` | — | required `https://` origin of the platform token issuer |
| `share.public_origin` | — | required `https://` origin, no path; share links point at `<origin>/warden/share` |
| `share.default_validity_seconds` | 3600 | 300–604800; used when an API call gives none |
| `share.default_max_opens` | 1 | 1–10; used when an API call gives none |
| `mail.transport` | `notification` | `notification`, or `log` (development only, refused in production; never delivers links). `smtp` is read as `notification` |
| `limits_warden.transfer_max_bytes` | 16 MiB | 4–64 MiB; Bitwarden and backup uploads. `limits.max_request_bytes` must be at least this |
| `limits_warden.lookup_rate_per_minute` | 120 | share opens per minute, per client address and per link |
| `enroll.*` | — | `enabled`, `enroll_url`, `lcm_grpc`, `tenant_id`, `token_file`, `state_file`, `insecure`: SVID enrollment with lcm |

The old relay keys `mail.host`, `mail.port`, `mail.username`,
`mail.password`, `mail.from` and `mail.allow_plaintext` are accepted but
ignored, with one warning at start. Remove them.

## Vault

Create a KV v2 mount (default `warden`), a policy and an AppRole for warden:

```hcl
path "warden/data/*"         { capabilities = ["create", "read", "update", "delete"] }
path "warden/metadata/*"     { capabilities = ["read", "delete", "list"] }
path "auth/token/renew-self" { capabilities = ["update"] }
```

Material lives at `<mount>/data/<tenant id>/secrets/<secret id>` (one KV
version per password version) and `.../<secret id>/totp`. Warden logs in at
start, renews its token and logs in again when renewal ends.

**Rotating the AppRole secret ID:** create a new one (`vault write -f
auth/approle/role/warden/secret-id`), replace the file or variable, restart
warden, then destroy the old one.

## Service policies

Warden's own policy must let the gateway in. The usual rule covers the
browser API, the share page, health and the help pages
(`GET /docs/v1/bundle`):

```yaml
rules:
  - id: gateway-forwards
    from: ["spiffe://<trust domain>/svc/gateway"]
    to: ["warden"]
    operations: ["*"]
    effect: allow
```

Modules that resolve secret references call warden's gRPC API with the
user's token and get only what they need: ticket
`/warden.v1.Secrets/GetPassword`; ipam and signing `/warden.v1.Secrets/Get`
and `/warden.v1.Secrets/GetPassword`. Those calls still pass warden's
per-secret access check and audit.

Notification's policy must allow `spiffe://<trust domain>/svc/warden` on
`/notification.v1.Notifier/Send` (the default), and discovery must resolve
`notification`.

## Gateway

The gateway serves warden under `/api/warden`, `/warden/share` and the UI
remote. Its edge must accept 16 MiB bodies plus slack
(`limits.max_request_bytes: 16842752`) for imports and backups; those routes
have their own 120 s timeout.

## Background work

- Every minute, the reconciler settles writes interrupted between the
  database and the vault (older than two minutes) and finishes deletes made
  while the vault was down.
- Every minute, the sweeper marks expired shares (an expired link is refused
  at once regardless).
- Every five minutes, warden re-registers its permissions, module roles and
  built-in grants with auth.

## Backups

Database backups are useless without the vault: restore both together, or
use a warden backup with material (**More actions → Backup with material**,
or `POST /api/warden/v1/backup/export?include_material=true`). A backup is
restored with `POST /api/warden/v1/backup/import` (`backup:manage`); the
portal has no button for it. Import gives every object a new ID, recreates
folders, writes material in version order (or marks versions **material
missing**), keeps grants and reports counts and warnings.

## Troubleshooting

**Warden refuses to start with `config: ...`.** The message names the key.
Common: `db.dsn must use sslmode=verify-full (or verify-ca) in production`,
`vault.role_id_file/secret_id_file or vault.role_id_secret/secret_id_secret
must be set`, `share.public_origin must be an https origin without path`,
`limits.max_request_bytes must be at least limits_warden.transfer_max_bytes`.

**Warden refuses to start with `help docs: ...`.** The help pages built into
the binary are invalid. CI catches this with `tangra-docs lint`; rebuild from
a commit that passed CI.

**`wardensvc bootstrap` exits non-zero.** The vault probe failed: wrong
address, CA, AppRole credentials or policy. The printed health shows the
vault as `sealed`, `unreachable` or `unauthenticated`.

**Users see *The vault is unavailable*.** Revealing, saving passwords and
shares fail; names and folders stay readable. Check the health route
(`GET /api/warden/v1/health`, `stats:read`) and the vault. Writes cut off
half-way are repaired by the reconciler once the vault is back.

**Sharing fails with *temporarily unavailable*.** The notification module did
not confirm the mail: it is unreachable, its policy refuses warden, the
`warden.share` template or email channel is not configured, or the relay
failed. The share is cancelled and audited as `share_created` with reason
`mail_failed`. Notification's delivery log holds the attempt under the
share's ID.

**Imports or backups fail with `body_too_large`.** Raise
`limits.max_request_bytes` on the gateway edge and on warden.

**Roles are missing in auth.** Look for `auth registration: ...` in the log.
Warden retries every 5 seconds until auth accepts, then registers every five
minutes.
