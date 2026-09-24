# Data Model: Warden Secret Manager

TimescaleDB database `warden` (application role `warden_app`, no BYPASSRLS);
every table carries `tenant_id` under a `tenant_isolation` RLS policy like the
auth service. Identifiers are UUIDv7. **No table holds secret material.**

## folders

| column | type | rules |
|--------|------|-------|
| id | uuid PK | |
| tenant_id | uuid | RLS |
| parent_id | uuid null FK folders | null = tenant root level |
| name | text | 1–100 chars, trimmed, no control chars; unique among siblings: `UNIQUE (tenant_id, parent_id, lower(name))` (root: `parent_id IS NULL` partial index) |
| path | text | materialised "/Infra/Databases" for display and search |
| ancestors | uuid[] | every ancestor id root-first; maintained on create/move |
| created_by, updated_by | uuid null | platform user ids |
| created_at, updated_at | timestamptz | |

Index `folders (tenant_id, parent_id)`; GIN on `ancestors` for subtree queries.

## secrets

| column | type | rules |
|--------|------|-------|
| id | uuid PK | |
| tenant_id | uuid | RLS |
| folder_id | uuid null FK folders | null = root |
| name | text | 1–200 |
| username | text | ≤ 200 |
| host_url | text | ≤ 2048, URL shape when non-empty |
| description | text | ≤ 2000 |
| metadata | jsonb | ≤ 16 KiB, never indexed |
| vault_path | text | `<tenant_id>/secrets/<id>` (relative to the mount) |
| current_version | integer | highest committed version |
| has_totp | boolean | |
| search | text (generated) | lower(name ‖ ' ' ‖ username ‖ ' ' ‖ host_url ‖ ' ' ‖ description) — GIN trigram |
| created_by, updated_by | uuid null | |
| created_at, updated_at | timestamptz | |
| deleted_at | timestamptz null | soft-deleted rows are invisible; hard-deleted after Vault destroy |

Index `secrets (tenant_id, folder_id)`; the folder `path` is joined for display.

## secret_versions

| column | type | rules |
|--------|------|-------|
| secret_id | uuid FK secrets ON DELETE CASCADE | |
| tenant_id | uuid | RLS |
| version | integer | KV v2 version number; PK `(secret_id, version)` |
| comment | text | ≤ 500 |
| checksum | text | SHA-256 hex of the password |
| source | text | `create`, `update`, `restore:<n>`, `import`, `overwrite`, `backup` |
| material_missing | boolean | backup imported without material |
| created_by | uuid null | |
| created_at | timestamptz | |

## grants

| column | type | rules |
|--------|------|-------|
| id | uuid PK | |
| tenant_id | uuid | RLS |
| resource_type | text | `folder` \| `secret` |
| resource_id | uuid | |
| subject_type | text | `user` \| `role` \| `tenant` |
| subject_id | text | user id, role slug, or '' for tenant |
| relation | text | `owner` \| `editor` \| `viewer` \| `sharer` |
| granted_by | uuid null | |
| granted_at | timestamptz | |
| expires_at | timestamptz null | |
| UNIQUE | (tenant_id, resource_type, resource_id, subject_type, subject_id) | a re-grant replaces relation and expiry |

Index `grants (tenant_id, resource_id)`, `grants (tenant_id, subject_type, subject_id)`.

Relation lattice: owner ⊃ editor ⊃ viewer; sharer ⊃ viewer. Permissions: owner
{read, write, delete, share}; editor {read, write}; sharer {read, share};
viewer {read}. Effective permission = union over matching grants on the
resource and its ancestors.

## shares

| column | type | rules |
|--------|------|-------|
| id | uuid PK | |
| tenant_id | uuid | RLS |
| secret_id | uuid FK secrets ON DELETE CASCADE | |
| token_hash | text UNIQUE | SHA-256 of the 32-byte link token |
| recipient_email | text | ≤ 254, normalised |
| message | text | ≤ 1000 |
| max_opens, opens | integer | 1–10 / count |
| expires_at | timestamptz | 5 min – 7 d from creation |
| cidr | text null | optional network policy |
| region | text null | optional region policy (ISO 3166-1 alpha-2) |
| state | text | `active` \| `consumed` \| `expired` \| `cancelled` |
| created_by | uuid | |
| created_at | timestamptz | |

Index `shares (tenant_id, created_by, created_at DESC)`.

## warden_audit_events (hypertable, 7-day chunks, 400-day retention)

`ts, tenant_id, event_type, actor_kind (user|service|recipient|system), actor_id,
subject_kind (secret|folder|grant|share|transfer|backup|system), subject_id,
outcome (ok|refused|failed), reason, correlation_id, details jsonb`.

Reads add a derived `subject_name` (secret name, folder path, or the shared
secret's name for shares) while the subject still exists; actors are user ids
that the UI resolves through the auth module's batch profile lookup.

Event types (closed vocabulary): `secret_created`, `secret_read`,
`secret_password_read`, `secret_updated`, `secret_password_updated`,
`secret_version_read`, `secret_restored`, `secret_moved`, `secret_deleted`,
`secret_totp_read`, `secret_totp_set`, `secret_totp_removed`, `folder_created`,
`folder_updated`, `folder_moved`, `folder_deleted`, `grant_created`,
`grant_revoked`, `access_refused`, `transfer_validated`, `transfer_imported`,
`transfer_exported`, `backup_exported`, `backup_imported`, `share_created`,
`share_opened`, `share_cancelled`, `share_refused`, `vault_unavailable`.
Details may carry ids, counts, version numbers and field names; a guard refuses
keys containing `password`, `secret_value`, `seed`, `totp`, `token`, `link`.

## Vault (mount `warden`, KV v2)

| path | content | versions |
|------|---------|----------|
| `warden/data/<tenant_id>/secrets/<secret_id>` | `{ "password": "…" }` | one per password change; `secret_versions.version` = KV version |
| `warden/data/<tenant_id>/secrets/<secret_id>/totp` | `{ "seed": "…" }` | overwritten in place |

AppRole policy: `path "warden/data/*" { capabilities = ["create","read","update","delete"] }`,
`path "warden/metadata/*" { capabilities = ["read","delete","list"] }`, nothing else.

## Derived views

- **Effective permissions**: for (subject set, resource) → `[ {relation, resource_type, resource_id, subject_type, subject_id, expires_at} ]` and the derived `{read, write, delete, share}` booleans.
- **Accessible resources**: for a subject set → resources with the strongest relation and its source, expanded to subtrees, paged.
- **Statistics**: per tenant counts of secrets (total / with TOTP), folders, versions, grants (by relation), shares (by state), plus the last 24 h operation count.

## State transitions

- **Secret**: created (v1) → updated (metadata only) | password changed (v+1) | restored (v+1) | moved → deleted (soft → Vault destroy → hard).
- **Share**: active → consumed (opens == max_opens) | expired (time) | cancelled (sender); all terminal.
- **Grant**: created → replaced (same key) → revoked (deleted); expiry is evaluated, not transitioned.
