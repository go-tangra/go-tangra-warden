# Vault layout (feature 005)

- Mount: `warden` (KV v2). Enabled by `deploy/vault-init.sh` in development and
  by operators in production (`vault secrets enable -path=warden -version=2 kv`).
- Auth: AppRole `warden` bound to policy `warden`:

```hcl
path "warden/data/*"     { capabilities = ["create", "read", "update", "delete"] }
path "warden/metadata/*" { capabilities = ["read", "delete", "list"] }
path "auth/token/renew-self" { capabilities = ["update"] }
```

- Credentials: `vault.role_id_file`, `vault.secret_id_file` (mode 0600) or the
  Freya secrets provider keys `vault.role_id` / `vault.secret_id`; never flags.
- Token: `token_ttl` 1h, `token_max_ttl` 24h; renewed by the client's lifetime
  watcher; re-login on renewal failure; health reports `vault: sealed |
  unreachable | unauthenticated | ok`.
- Paths: `warden/data/<tenant_id>/secrets/<secret_id>` → `{ "password": "..." }`
  (versioned); `warden/data/<tenant_id>/secrets/<secret_id>/totp` → `{ "seed":
  "..." }`. Tenant ids are UUIDs from the verified platform token; the service
  refuses to build a path from any other input.
- Versions: `secret_versions.version` equals the KV version; restore writes a
  new version; delete destroys all versions (`DELETE warden/metadata/...`).
- Reconciliation: at start and every 5 minutes the service lists KV metadata
  for secrets touched in the last 15 minutes and repairs rows/versions (R3).
- Development: `hashicorp/vault` dev server (in-memory, root token `dev-root`),
  `vault-init.sh` creates mount, policy and AppRole and writes
  `deploy/.vault/role_id` and `secret_id` (git-ignored); `vault.allow_plaintext:
  true` in `dev.yaml` only.
