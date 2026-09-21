# Research: Warden Secret Manager

The reference implementation (`/home/jadmin/projects/go-tangra/go-tangra-warden`:
Kratos v2, Ent, HashiCorp Vault KV v2, Redis, Buf, a Vue frontend with
secrets/folders/permissions/generator views) was read for its feature set and
contracts; this plan re-implements the same behaviour on the Freya platform.
No `NEEDS CLARIFICATION` remained after the user's direction to use Vault for
material and TimescaleDB for the references.

## R1. Material in Vault, references in TimescaleDB

**Decision**: every password and TOTP seed is written to HashiCorp Vault KV v2
under `warden/data/<tenant_id>/secrets/<secret_id>` (password, one KV version
per password change) and `.../<secret_id>/totp` (seed, unversioned). The
`secrets` row holds `vault_path` and `current_version`; each `secret_versions`
row holds the KV `version` number, comment, author, time and a `checksum`
(SHA-256 of the password, hex) computed before the write. Reading a version
reads that KV version. Restore reads version N and writes it as a new KV
version (append-only history, matching the spec).

**Rationale**: KV v2 already provides per-path versioning, so the service never
stores or reorders material; the checksum lets the UI show "same as version 2"
and lets restore verify the round trip without exposing the value. Tenant
isolation is a path prefix derived only from the verified tenant id plus a
Vault policy limiting the AppRole to `warden/data/*` and `warden/metadata/*`.

**Alternatives rejected**: encrypting material into the database with the
framework `crypto` envelope (violates the requirement; loses Vault's sealing,
audit and rotation); Vault Transit to encrypt database-stored material
(material still lands in the database); one KV path per version (loses native
version listing and doubles writes).

## R2. Vault client: `github.com/hashicorp/vault/api`

**Decision**: use the official `vault/api` client (`KVv2().Put/Get/GetVersion/
GetVersionsAsList/Delete`), AppRole login with `role_id`/`secret_id` read from
files (`vault.role_id_file`, `vault.secret_id_file`) or the framework secrets
provider, and `api.NewLifetimeWatcher` for token renewal with re-login on
failure. TLS to Vault is required unless `vault.allow_plaintext` (dev; logs a
startup warning, refused in production).

**Justification (Principle VI)**: HashiCorp's own client, actively maintained,
Mozilla-2.0, transitive dependencies are HashiCorp helpers (go-retryablehttp,
go-cleanhttp, hcl) already common in the ecosystem; `vault-client-go` is still
beta and lacks the lifetime watcher; a hand-written HTTP client would
re-implement AppRole, renewal and KV v2 semantics (and be prohibited-adjacent
"custom security code"). Pinned in `go.mod`; `govulncheck` in CI.

**Interface**: `vault.Store` (`PutPassword(ctx, tenant, secret, value) (version
int, error)`, `GetPassword(ctx, tenant, secret, version) (string, error)`,
`DeleteSecret`, `PutTOTP/GetTOTP/DeleteTOTP`, `Health`) with a `Fake` for unit
tests and the real client for integration tests against a Vault dev container
initialised by `deploy/vault-init.sh` (enable KV v2 at `warden`, write the
policy, create the AppRole, emit role_id/secret_id files).

## R3. Two-phase write and orphan handling

**Decision**: create/update password = (1) insert/update the row in a
transaction with `pending_version = N+1`, (2) write to Vault, (3) commit the
version row with the KV version returned; if (2) fails, the transaction is
rolled back and the caller gets `temporarily_unavailable`; if (3) fails after a
successful Vault write, the KV version exists without a row: a sweeper
(`secrets.Reconcile`, every 5 min and at start) compares KV metadata with rows
and either records the missing version (same checksum) or deletes the orphaned
KV version. Delete = mark row deleted (soft, `deleted_at`) + Vault
`DeleteMetadata` (destroys all versions) + hard-delete rows after success;
listings never show soft-deleted rows.

**Rationale**: SC-008 (no partial writes visible), simple recovery without
distributed transactions.

## R4. Access check in SQL (Zanzibar semantics without a second store)

**Decision**: `folders.ancestors uuid[]` is maintained on create/move (all
ancestors, root-first); the check for `(subject S, resource R)` is:

```sql
SELECT max(relation_rank) FROM grants
 WHERE tenant_id = $1
   AND (resource_id = $2 OR resource_id = ANY($3))          -- R and its ancestor folders
   AND ((subject_type = 'user' AND subject_id = $4)
     OR (subject_type = 'role' AND subject_id = ANY($5))     -- caller's effective role slugs
     OR  subject_type = 'tenant')
   AND (expires_at IS NULL OR expires_at > now())
```

with `relation_rank` viewer=1, sharer=2, editor=3, owner=4 and permissions
derived from the relation lattice (owner: read/write/delete/share; editor:
read/write; sharer: read/share; viewer: read). Effective-permissions returns
every matching grant with its source (resource, subject kind). "List accessible
resources" is the inverse query (grants for the caller's subjects → resources
and their subtrees), paged.

**Rationale**: one indexed query per request; roles come from the platform
token (`authclient.Identity.Roles`, effective roles incl. groups after feature
004) so role membership needs no synchronisation; expiry is evaluated at check
time (SR-003); no OpenFGA store to keep in sync (the reference project also
used an in-service engine). Folder moves rewrite `ancestors` of the subtree in
one statement.

**Alternatives rejected**: a second OpenFGA store with contextual tuples for
roles and conditions for expiry (dual writes, more moving parts, harder to
explain sources); computing inheritance recursively per request (N queries).

## R5. Search

**Decision**: `pg_trgm` GIN index on `secrets.search` (a generated column:
name ‖ username ‖ host_url ‖ description ‖ folder path, lower-cased) with
`ILIKE '%q%'`; results are filtered by the accessible-resource set of the
caller (join with the check query) and never include material or metadata
JSON. Ranking: name match first, then path.

**Rationale**: substring search over ≤ 100k rows per tenant is well within a
trigram index; no external search engine.

## R6. Bitwarden import/export

**Decision**: accept the Bitwarden JSON export (`encrypted: false`, `folders[]`,
`items[]` with `type: 1` logins, `login.{username,password,totp,uris[]}`,
`notes`, `fields[]`, `passwordHistory[]`); parse with a bounded decoder
(16 MiB, depth 8, ≤ 50k items), validate every field (lengths, UTF-8, control
characters, URI shape), map folders to a subtree under the chosen target
folder, items to secrets (custom fields → metadata, notes → description,
totp → seed if a valid otpauth/base32), `passwordHistory` → earlier versions
(oldest first, then the current password as the last version). Duplicate
handling compares name within the same target folder: skip / rename `name (n)`
/ overwrite (new version on the existing secret). Export writes the same
document for the secrets the caller may read, including passwords (bulk
disclosure audit with count). The accepted document is described by
`contracts/bitwarden.schema.json` and fuzzed.

## R7. Tenant backup

**Decision**: a JSON document `{module:"warden", schema_version:1, tenant_id,
exported_at, folders[], secrets[], versions[], grants[], shares:[]}`; with
`include_material` the versions carry the password and secrets the seed
(audited as bulk disclosure, requires `backup:manage`). Import remaps every id,
recreates folders in path order, secrets, versions (writing material to Vault
in version order when present; otherwise versions are recorded with their
checksums and marked `material_missing`), grants (subjects kept by id/slug,
unknown users kept as-is: identity is external), and reports counts and
warnings per entity. Size limit 16 MiB.

## R8. External sharing

**Decision**: `shares` row with `token_hash` (SHA-256 of a 32-byte random
token), recipient email, message, `expires_at` (5 min–7 d, default 1 h),
`max_opens` (1–10, default 1), `opens`, optional `cidr`/`region` policy, state.
The link `https://<public origin>/warden/share#<token>` carries the token in
the URL fragment, which browsers never send to any server (so it cannot land
in gateway, proxy or module request logs); `/warden/share` is a public gateway
route served by warden as a minimal HTML page (CSP nonce relayed by the
gateway, `Cache-Control: no-store`) whose script reads the fragment, removes
it from the address bar and POSTs to `/api/warden/v1/share/open` with the
token on user action; each successful open increments `opens`, checks the policy
(client address from `X-Gateway-Client` hash cannot be matched against a CIDR;
the gateway forwards the hashed client, so region/network policies use the
gateway's `X-Forwarded-*` data — the plan keeps the *interface* and evaluates
CIDR only when the gateway forwards the address in a trusted header; see
`contracts/manifest.md`), reveals name/username/host/password and audits the
disclosure with the recipient address. Invalid, expired, exhausted or cancelled
tokens answer a uniform 404 page. Mail goes through an SMTP outbox modelled on
auth's (`internal/mail`, `net/smtp`, TLS required outside dev).

## R9. Password generator

**Decision**: server-side `POST /api/warden/v1/generate` with length 8–128 and
class flags; `crypto/rand` selection with at least one character per chosen
class (rejection sampling, no modulo bias); never audited or logged; the UI
also generates locally for instant feedback with the same rules.

## R10. TOTP

**Decision**: seeds accepted as `otpauth://totp/...` URLs or bare base32;
stored in Vault; `GET .../totp` returns the current code, its period and the
seconds left, computed with `github.com/pquerna/otp/totp` (already vetted by
feature 002); the seed never leaves the service (SR-008).

## R11. Browser API shape and gRPC surface

**Decision**: HTTP JSON under `/api/warden/v1/...` described by
`contracts/warden-api.openapi.yaml`, validated by kin-openapi (like auth), all
routes registered at the gateway with a permission except the share page and
share-open (public). gRPC `warden.v1.Secrets` with `Get`, `GetPassword`,
`Check` for platform services on the Freya channel (verified with
`authclient.KratosMiddleware`, subject to the same Zanzibar check). No
grpc-gateway transcoding: the reference project's REST came from transcoding,
here the platform's browser convention is an OpenAPI document.

## R12. API permissions and built-in role grants

**Decision** (contracts/manifest.md): `secrets:read`, `secrets:write`,
`secrets:delete`, `secrets:share`, `folders:manage`, `permissions:manage`,
`transfer:import`, `transfer:export`, `backup:manage`, `stats:read`. Granted by
the auth service's role seeding through the gateway permission registration:
owner/admin all; member `secrets:read/write/share`, `folders:manage`,
`permissions:manage` (they can only grant what they hold on resources
anyway); auditor `stats:read`; operator `stats:read`. Abilities mirror them
(`manage Secret`, `manage Folder`, `manage Grant`, `import/export Transfer`,
`manage Backup`, `read Stats`). Navigation: "Secrets" (`/warden`), "Folders",
"Permissions", "Generator".

## R13. Auth service additions (contracts/auth-changes.md)

**Decision**: two member-level read endpoints in the auth service so the
permissions UI can pick subjects without admin rights: `GET /api/v1/users?q=`
(public profiles of the caller's tenant, ≤ 20 matches, rate-limited like the
lookup) and `GET /api/v1/roles` (slug + display name of the tenant's roles).
Both are read-only and answer only for the caller's tenant.

## Threat model (STRIDE)

| # | Threat | Category | Control |
|---|--------|----------|---------|
| T1 | Read another tenant's secret by id | Info disclosure | tenant from the verified token; RLS on every table; Vault path derived from tenant; uniform `not_found` |
| T2 | Material leaks via DB, logs, audit, search, backup, errors | Info disclosure | material only in Vault; audit detail guard; redacting logger; search column excludes metadata; material-less backups; marker-corpus scan test |
| T3 | Granting more than held / on resources not owned | Elevation | granter must hold `share` on the resource; relation ≤ granter's; validated relation/expiry |
| T4 | Stale access after revoke/expiry | Elevation | no cache: every request runs the check; expiry evaluated at check time |
| T5 | Vault credential theft or misuse | Spoofing | AppRole from files/secrets provider; token renewed and never logged; Vault policy scoped to `warden/*`; TLS required outside dev |
| T6 | Share link guessing / replay / forwarding | Spoofing / Info | 256-bit random token, stored hashed; open budget; expiry; uniform 404; no-store page; audited disclosures |
| T7 | Malicious import (bomb, deep nesting, injection in names/URLs) | DoS / Tampering | 16 MiB cap, bounded decoder, depth/item limits, field validation, nothing written before validation |
| T8 | TOTP seed disclosure | Info disclosure | seed never returned; only codes; seed stored in Vault |
| T9 | Partial writes during Vault outage | Integrity | two-phase write, rollback, reconciler (R3) |
| T10 | Export/backup as exfiltration | Info disclosure | dedicated permissions, bulk-disclosure audit with counts, rate-limited |
| T11 | Metadata smuggling secrets into search/logs | Info disclosure | metadata never indexed or logged; size-capped |
| T12 | Folder cycle via move | Integrity | ancestor check refuses moving under a descendant |
| T13 | Enumeration via search/list | Info disclosure | results filtered by accessible set before pagination |
