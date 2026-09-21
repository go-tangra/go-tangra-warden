# Tasks: Warden Secret Manager

**Input**: Design documents from `/specs/005-warden-secrets/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Tests are MANDATORY (Constitution Principle IV, NON-NEGOTIABLE). Every user story lists its tests before its implementation tasks; tests are written and confirmed failing first. Warden handles secret material, authorization, untrusted import files and public share links: negative security tests, a material-leak scan and fuzz targets for every parser are included.

**Organization**: Tasks are grouped by user story so each story is an independently testable increment.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: US1 keep credentials in folders · US2 share precisely · US3 move credentials in and out · US4 operate and observe · US5 hand a secret to an outsider
- Paths are repository-relative; the service lives in `services/warden/`

## Path Conventions

- Go domain packages under `services/warden/internal/<pkg>` with `<pkg>db/db.go` adapters, HTTP in `internal/httpapi`, gRPC in `internal/grpcapi`, SQL in `internal/store`, migrations in `internal/store/migrations`, in-memory double in `internal/memstore`, Vault client and fake in `internal/vault`
- Federated remote under `services/warden/ui` (Vitest in `ui/tests/unit`, Playwright in `ui/tests/e2e`), embedded with `-tags ui`
- Cross-service changes in `services/auth` and `services/gateway` as listed in `contracts/auth-changes.md`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: module skeleton, contracts in place, dev stack with Vault, CI

- [X] T001 Create the service module skeleton per plan.md (`go.mod` with `replace github.com/go-freya/freya => ../..` and requires on `services/auth` and `services/gateway` pkg paths, `cmd/wardensvc`, `internal/{config,store,memstore,vault,audit,authz,folders,secrets,transfer,share,generator,stats,httpapi,grpcapi,app}`, `pkg/wardenmanifest`, `deploy`, `docs`, `scripts`, `tests/{contract,fuzz,integration}`, `doc.go` per package) in services/warden/
- [X] T002 [P] Copy contracts into the module and generate code: `specs/005-warden-secrets/contracts/warden.v1.proto` → `services/warden/api/proto/warden/v1/warden.proto` (buf.yaml, buf.gen.yaml, `*.pb.go`), `warden-api.openapi.yaml` → `services/warden/api/openapi/warden.yaml` (embedded via `api/openapi/openapi.go`), `bitwarden.schema.json` → `services/warden/api/schema/bitwarden.schema.json` (embedded)
- [X] T003 [P] Makefile mirroring services/auth (lint = vet+staticcheck+gosec, vuln, test, test-integration, cover with `COVERPKG` excluding `api/proto`, `*db`, `store`, `app`, `cmd`, `tests`, `ui`; fuzz; generate; ui-build; redaction-scan; compose-up/down) and `scripts/{coverage-gate.sh (100 % for internal/{authz,vault,share,secrets,generator}), redaction-scan.sh (marker corpus: `WARDEN-MARKER-PW-`, `WARDEN-MARKER-SEED-`, share token prefix)}` in services/warden/Makefile and services/warden/scripts/
- [X] T004 [P] Development stack `services/warden/deploy/{compose.yaml (TimescaleDB with `warden` database + `warden_app` role via init-db.sql, Valkey with `&*` channel ACL, Vault dev server `hashicorp/vault` with root token `dev-root`, Mailpit), vault-init.sh (enable KV v2 at `warden`, write policy from contracts/vault-layout.md, create AppRole `warden`, write deploy/.vault/{role_id,secret_id} mode 0600), dev.yaml (vault.allow_plaintext true, limits.max_request_bytes 16842752, gateway service "gateway"), policy.yaml (gateway → warden.v1.Secrets; warden → auth.v1 Keys/List, Sessions/RevokedSince|Watch; warden → gateway.v1.Registry)}` and `.gitignore` for `deploy/.vault/`
- [X] T005 [P] UI scaffold `services/warden/ui/` copied from the hello module remote / auth console conventions (Vite 8 + Vue 3.5 + Vuetify 4 + vue-router 5 + Pinia 4 + TypeScript 5.9, `@mdi/font`, `@module-federation/vite` exposing `./routes` and `./nav`, `npm run gen:api` from api/openapi/warden.yaml, Vitest + jsdom, Playwright + axe with `testIdAttribute: 'data-test'` and `PW_CHANNEL`) with `package.json`, `vite.config.ts`, `module-federation.config.ts`, `tsconfig*.json`, `src/main.ts` (standalone dev shell), `src/remote/{routes.ts,nav.ts}`
- [X] T006 [P] Dependency justification `services/warden/docs/dependencies.md` (research R2: `github.com/hashicorp/vault/api`; `github.com/pquerna/otp`; frontend list) and `.github/workflows/ci.yml` jobs `warden-service` (lint, vuln, test, cover, fuzz smoke, ui lint/unit/build/audit) and `warden-service-integration` (`-tags integration` with compose incl. Vault, Playwright)
- [X] T007 [P] Root `Makefile` `testca` services list gains `warden`; root `.gitignore` gains `services/*/ui/{node_modules,dist,test-results,playwright-report}` and `services/warden/deploy/.vault/`; root `README.md` and `CHANGELOG.md` mention the module

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: config, schema, Vault client, audit, identity middleware, gateway registration — everything every story needs

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

### Tests (write first)

- [X] T008 [P] Unit tests for `config`: defaults (secure: TLS to Vault required, share defaults 1 h / 1 open, lookup rate), `Validate` (production refuses `vault.allow_plaintext`, missing role/secret id source, weak db sslmode, limits below 16 MiB for transfer), `Warnings` in services/warden/internal/config/config_test.go
- [X] T009 [P] Migration + repository tests (`//go:build integration`): tables from data-model.md under RLS (`tenant_isolation` on folders/secrets/secret_versions/grants/shares/warden_audit_events), hypertable + retention, unique sibling folder names (case-insensitive, root partial index), grants unique key replaces, `search` generated column with trigram index, cross-tenant reads return nothing, app role grants in services/warden/internal/store/migrate_test.go
- [X] T010 [P] Unit tests for `vault` against the fake and an httptest Vault stub: AppRole login, token renewal on TTL, re-login on failure, `PutPassword` returns increasing KV versions, `GetPassword(version)`, `Versions`, `DeleteSecret` destroys metadata, `PutTOTP/GetTOTP/DeleteTOTP`, path derivation refuses non-UUID tenant/secret ids, plaintext refused unless allowed, `Health` states (ok/sealed/unreachable/unauthenticated) in services/warden/internal/vault/vault_test.go
- [X] T011 [P] Unit tests for `audit`: closed vocabulary from data-model.md, required fields, detail guard rejects keys containing `password`, `secret_value`, `seed`, `totp`, `token`, `link` and any string value matching the marker corpus, batching, `Flush` in services/warden/internal/audit/audit_test.go
- [X] T012 [P] Unit tests for `httpapi` skeleton: OpenAPI validation (unknown fields, lengths, uuid params), `{"reason"}` errors only, 5xx → `temporarily_unavailable`, `authclient` middleware on every non-public route (401 without/with forged token, tenant and roles from the token), public share routes exempt, per-route `x-freya-max-body-bytes` honoured, security headers in services/warden/internal/httpapi/server_test.go
- [X] T013 [P] Contract tests: OpenAPI document parses, every declared route mounted and every mounted route declared, every non-public operation carries `x-freya-permission` from the manifest's permission list, proto shapes, manifest builds from the document (routes, permissions, abilities, nav, methods, 16 MiB body on transfer/backup routes, `client_address` on share-open) in services/warden/tests/contract/{openapi_test.go,grpc_test.go,manifest_test.go}
- [X] T014 [P] Integration harness (`//go:build integration`): testcontainers TimescaleDB, Valkey, Vault dev (+ init script equivalent in Go: mount, policy, AppRole), Mailpit; auth built from `../auth` as a subprocess in gateway mode like feature 003's harness; `Env` with `Seed(tenant, user, roles)`, `Token(user)` (platform token minted via auth `Sessions/MintToken` or sign-in + `/api/v1/session/token`), `JSON`, `Raw`, `AuditCount`, `Vault` handle (stop/start), `LastMail`; `TestHarnessBoots` in services/warden/tests/integration/harness_test.go

### Implementation

- [X] T015 Implement `config` (Freya `config.Config` inline + `DB`, `Valkey`, `Vault{Address, Mount, RoleIDFile, SecretIDFile, AllowPlaintext, CAFile}`, `Gateway{Service}`, `Share{PublicOrigin, DefaultValiditySeconds, DefaultMaxOpens}`, `Mail{Transport, Host, Port, Username, Password, From, AllowPlaintext}`, `Limits{TransferMaxBytes, LookupRatePerMinute}`) with `Load/Validate/Warnings` in services/warden/internal/config/config.go
- [X] T016 Migrations `0001_schema.sql` (folders, secrets, secret_versions, grants, shares + indexes + trigram extension + generated search column), `0002_hypertables.sql` (warden_audit_events, retention 400 d), `0003_rls.sql` (policies via `app_tenant_matches`), `0004_grants.sql` (warden_app) and `store.Open/Migrate/Tx(Scope)` copied from the auth pattern in services/warden/internal/store/{store.go,migrations/*.sql}
- [X] T017 Models and repositories: `Folder`, `Secret`, `SecretVersion`, `Grant`, `Share`, `AuditRow` and functions `Insert/Get/List/Update/Delete` per table, `FolderChildren`, `FolderSubtree(ancestors)`, `RewriteAncestors(oldPrefix, newPrefix)`, `SecretsInFolder(paged)`, `SearchSecrets(q, accessibleIDs)`, `VersionsOf`, `GrantsFor(resource + ancestors)`, `GrantsBySubjects`, `AccessibleResources(subjects, paged)`, `ShareByTokenHash`, `Stats(tenant)`, `InsertAuditRows`, `QueryAudit` in services/warden/internal/store/{models.go,repos.go}
- [X] T018 [P] In-memory double `memstore.Store` implementing every repository interface with the same semantics (RLS by tenant argument, sibling uniqueness, ancestors, paging) in services/warden/internal/memstore/memstore.go
- [X] T019 [P] `vault` package: `Client` over `github.com/hashicorp/vault/api` (AppRole login from files/secrets provider, `LifetimeWatcher` renewal, KV v2 `Put/Get/GetVersion/Versions/DeleteMetadata`, path builder `tenant/secrets/id[/totp]` validating UUIDs, TLS config with optional CA, `Health`) and `Fake` (in-memory versions) in services/warden/internal/vault/{vault.go,fake.go}
- [X] T020 [P] `audit` package: `Event`, `EventType` vocabulary, `Writer` (batched, `Flush`), detail guard (forbidden keys + marker patterns → `[REDACTED]`) and `auditdb` inserter/querier in services/warden/internal/audit/{audit.go,query.go,auditdb/db.go}
- [X] T021 `httpapi` skeleton: `Server` with embedded OpenAPI, kin-openapi validation with per-route binary limits (reuse the auth pattern incl. `x-freya-max-body-bytes`), `authclient.Middleware` wrapping every non-public route, `Identity` accessor (`user id`, `tenant`, `roles`), error helpers, `MustHandle`/`Declared`/`Implemented`, security headers, share page HTML with relayed CSP nonce in services/warden/internal/httpapi/{server.go,middleware.go,errors.go}
- [X] T022 [P] `pkg/wardenmanifest`: builds the gateway manifest from the embedded OpenAPI document (`x-freya-permission`, `x-freya-public`, `x-freya-max-body-bytes`, `x-freya-client-address` → `Route.ClientAddress`), permissions, abilities, nav and gRPC methods from contracts/manifest.md in services/warden/pkg/wardenmanifest/manifest.go
- [X] T023 `app.Build`: Freya app, DB, Valkey, Vault client, audit writer, verifier (`authclient` with keys/revocations from the auth service), HTTP + gRPC servers, health (`db`, `vault`), gateway registration with lease renewal (`gatewayclient`), route coverage check (declared == mounted) in services/warden/internal/app/app.go; `cmd/wardensvc/{main.go (run), bootstrap.go (migrate, Vault access check, print AppRole health)}`
- [X] T024 Cross-service (contracts/auth-changes.md §Gateway): `Route.client_address` in `services/gateway/api/proto/gateway/v1/gateway.proto` and `manifest.schema.json` (`x-freya-client-address`), `gatewayclient.Route.ClientAddress`, dispatcher adds `X-Gateway-Client-Addr` for such routes and drops it inbound, unit test in services/gateway/internal/httpapi/dispatch_test.go, contract copies in `specs/003-application-gateway/contracts/` updated
- [X] T025 Cross-service (contracts/auth-changes.md §Auth): `GET /api/v1/users?q=` (member-level public profile search, ≤ 20, rate-limited) and `GET /api/v1/roles` (slug + display name) in services/auth/api/openapi/console.yaml, services/auth/internal/httpapi/profile.go (search) and services/auth/internal/httpapi/roles.go (list), store `SearchProfiles`, handler tests in services/auth/internal/httpapi/profile_test.go; console `gen:api` regenerated

**Checkpoint**: `wardensvc bootstrap` migrates and reaches Vault; the service registers with the gateway; every route answers 401/403 correctly with no handler yet

---

## Phase 3: User Story 1 - Keep Credentials in Folders (Priority: P1) 🎯 MVP

**Goal**: folders tree, secrets CRUD with material in Vault, versions and restore, move, search, TOTP codes; creator becomes owner; everything audited; material never leaves Vault except to the caller.

**Independent Test**: create "Infra/Databases", create "prod-db", search "db", reveal, change the password twice with comments, list 3 versions, restore v1 (→ v4), move to "Infra", delete; scan database dumps, audit rows and logs for the marker password: zero hits.

### Tests for User Story 1 (MANDATORY) ⚠️

- [X] T026 [P] [US1] Unit tests for `folders`: create (name rules, sibling uniqueness, ancestors/path), rename, move (cycle refused, subtree ancestors/paths rewritten), delete (non-empty refused unless recursive; recursive collects secret ids), tree (bounded 10k), creator gets an owner grant, audit per operation in services/warden/internal/folders/folders_test.go
- [X] T027 [P] [US1] Unit tests for `secrets` with the memstore and `vault.Fake`: create writes Vault then the version row (checksum, source `create`), Vault failure → `ErrVaultUnavailable` and no rows; update metadata (no version); password change (version n+1, comment); reveal current/specific version audited with the version; versions listing has no material; restore creates n+1 with the old value and source `restore:<n>`; move (folder path follows); delete destroys Vault versions then rows; search excludes material and filters by accessible ids; TOTP set (otpauth URL and base32 validated), code computed, seed never returned, remove; two-phase failure after Vault write marks for reconcile; `Reconcile` repairs/deletes orphans in services/warden/internal/secrets/secrets_test.go
- [X] T028 [P] [US1] Unit tests for `authz` needed by US1: creator-owner grant, `Check(subjects, resource, permission)` with the relation lattice over ancestors, expired grants ignored, tenant grants, cross-tenant resource → not found in services/warden/internal/authz/check_test.go
- [X] T029 [P] [US1] Fuzz targets `FuzzFolderName`, `FuzzSecretInput` (name/username/host/description/metadata size), `FuzzTotpSeed` (otpauth/base32 parser never panics, invalid refused), `FuzzPathBuilder` (Vault path never escapes the tenant prefix) in services/warden/tests/fuzz/inputs_fuzz_test.go
- [X] T030 [P] [US1] Handler tests: every folder and secret route (schema refusals, 401/403 by permission, 404 cross-tenant, 409 sibling name, 503 `vault_unavailable`), reveal audited, `Secret` JSON never contains `password`/`totp`, paging in services/warden/internal/httpapi/{folders_test.go,secrets_test.go}
- [X] T031 [P] [US1] gRPC tests for `warden.v1.Secrets` `Get`/`GetPassword`/`Check` (service identity + platform token required, Zanzibar check applied, audit) in services/warden/internal/grpcapi/secrets_test.go
- [X] T032 [P] [US1] Integration `TestSecrets`, `TestFolders`, `TestVersions`, `TestSearch`, `TestTotp` against real Vault + TimescaleDB through the harness (quickstart §3), plus `TestMaterialNeverLeaks`: after the flows, dump every table, audit rows and captured logs and assert the marker corpus is absent (SC-005) in services/warden/tests/integration/{secrets_test.go,leak_scan_test.go}
- [X] T033 [P] [US1] UI unit tests: secrets store (list/search/create/reveal/versions/restore), folder tree store, `SecretDrawer` (validation, password hidden until reveal, copy), `VersionDrawer` (restore confirmation) in services/warden/ui/tests/unit/{secrets.spec.ts,folders.spec.ts}

### Implementation for User Story 1

- [X] T034 [US1] `authz` core: `Subjects(identity)` (user id, effective role slugs, tenant), `Check`, `Permissions(relation)`, relation lattice, `ancestorsOf(resource)` via the store, creator-owner helper in services/warden/internal/authz/{authz.go,check.go} and services/warden/internal/authz/authzdb/db.go
- [X] T035 [US1] `folders` service (create/rename/move/delete/tree/children with permission checks: write on parent to create, write on folder to rename/move/delete, read to list; audit) in services/warden/internal/folders/folders.go and services/warden/internal/folders/foldersdb/db.go
- [X] T036 [US1] `secrets` service (create/get/update/reveal/updatePassword/versions/restore/move/delete/search/totp set|code|remove; two-phase Vault write; checksum; `Reconcile` sweeper; audit per operation incl. `secret_password_read` with version) in services/warden/internal/secrets/{secrets.go,totp.go,reconcile.go} and services/warden/internal/secrets/secretsdb/db.go
- [X] T037 [US1] HTTP handlers for folders and secrets routes (contracts/warden-api.openapi.yaml §folders, §secrets) with `Permissions` embedded in responses in services/warden/internal/httpapi/{folders.go,secrets.go}; wire in services/warden/internal/app/app.go
- [X] T038 [P] [US1] gRPC `warden.v1.Secrets` server (`Get`, `GetPassword`, `Check`) with `authclient.KratosMiddleware` in services/warden/internal/grpcapi/secrets.go; registration in app.go
- [X] T039 [P] [US1] UI: `src/api/client.ts` (CSRF from cookie, `{reason}` errors), `src/stores/{secrets.ts,folders.ts}`, views `secrets/index.vue` (folder tree sidebar + paged list + search + `data-test` hooks), `components/{SecretDrawer.vue (create/edit, reveal with audit notice, copy, TOTP code with countdown), VersionDrawer.vue (list, view version password on demand, restore), FolderTree.vue (create/rename/move/delete with recursive confirmation)}`, `views/folders/index.vue`; CASL abilities from the shell (`can('update','Secret')` + per-item `permissions`) in services/warden/ui/src/
- [X] T040 [US1] Playwright: `secrets.spec.ts` through the gateway (sign in with the TOTP helper from the shell suite, create folder + secret, reveal, change password, versions, restore, move, delete, axe) in services/warden/ui/tests/e2e/secrets.spec.ts

**Checkpoint**: credentials can be stored, versioned, restored, found and used; material only in Vault

---

## Phase 4: User Story 2 - Share Precisely (Priority: P1)

**Goal**: grants on folders/secrets to users, roles or the tenant with expiry, inherited down the tree; grant/revoke/list/check/accessible/effective; granter bounded by own relation.

**Independent Test**: Viewer on "Infra" to role `ops` until tomorrow; an `ops` member (through a group) reads a secret three levels deep but cannot write; an Editor on the secret writes but cannot share; after expiry the `ops` member is refused; effective-permissions explains each outcome.

### Tests for User Story 2 (MANDATORY) ⚠️

- [X] T041 [P] [US2] Unit tests for `authz` grants: `Grant` requires share on the resource and relation ≤ granter's; re-grant replaces; `Revoke`; `ListGrants(resource)` includes ancestor grants with source; `Effective(subjects, resource)`; `Accessible(subjects, permission, paged)` expands subtrees and reports strongest relation + source; role subjects match any of the caller's roles; expiry boundary (clock injected); cross-tenant not found; refusals audited in services/warden/internal/authz/grants_test.go
- [X] T042 [P] [US2] Handler tests for `/api/warden/v1/grants*` and `/api/warden/v1/access/*` (schema: relation/subject enums, expiry in the past refused, 403 no share / above own relation, 404 cross-tenant) in services/warden/internal/httpapi/grants_test.go
- [X] T043 [P] [US2] Integration `TestAccess`: the owner/editor/viewer/sharer × read/write/delete/share matrix on a secret and three folder levels; role grant held through an auth group (feature 004) works; tenant grant; expiry (harness clock or 1-second expiry); revoke enforced on the next request (SC-004); every grant/refusal audited (SC-009); cross-tenant 404 (SC-003) in services/warden/tests/integration/access_test.go
- [X] T044 [P] [US2] UI unit tests: permissions store, `PermissionDrawer` (subject picker via auth `GET /api/v1/users?q=` and `GET /api/v1/roles`, relation select, expiry, granter-bound relation options), effective view rendering sources in services/warden/ui/tests/unit/permissions.spec.ts

### Implementation for User Story 2

- [X] T045 [US2] `authz` grants: `Grant`, `Revoke`, `ListGrants`, `Effective`, `Accessible` with audit in services/warden/internal/authz/grants.go (+ authzdb)
- [X] T046 [US2] HTTP handlers for grants and access routes in services/warden/internal/httpapi/grants.go; wire in app.go
- [X] T047 [P] [US2] UI: `stores/permissions.ts`, `views/permissions/index.vue` (resource picker from the tree, grants table with source and expiry, revoke), `components/PermissionDrawer.vue` (grant form with subject search), "Share access" action in `SecretDrawer.vue`, effective-permissions panel in services/warden/ui/src/
- [X] T048 [US2] Playwright: `permissions.spec.ts` (grant Viewer to a role on a folder, verify as another user via a second browser, revoke, axe) in services/warden/ui/tests/e2e/permissions.spec.ts

**Checkpoint**: sharing inside the tenant is precise, inherited, expiring and audited

---

## Phase 5: User Story 3 - Move Credentials In and Out (Priority: P2)

**Goal**: Bitwarden validate/import/export with duplicate handling and history; tenant backup export/import with id remapping.

**Independent Test**: validate a 20-item/3-folder Bitwarden file with two collisions, import with rename, export and re-validate, backup with material into an empty tenant and compare.

### Tests for User Story 3 (MANDATORY) ⚠️

- [X] T049 [P] [US3] Unit tests for `transfer/bitwarden`: parse (bounded decoder, size/depth/item limits), validate report (counts, collisions per folder, problems per index, non-login types skipped), folder mapping under target, item mapping (fields → metadata, notes → description, totp validated, uris[0] → host), password history → versions oldest first, duplicate skip/rename (`name (n)`)/overwrite (new version), export document round-trips in services/warden/internal/transfer/bitwarden_test.go
- [X] T050 [P] [US3] Unit tests for `transfer/backup`: export with/without material (versions carry passwords only with material), import remaps ids, recreates in path order, versions in order (material → Vault; missing → `material_missing`), grants kept, report per entity, unknown schema version refused in services/warden/internal/transfer/backup_test.go
- [X] T051 [P] [US3] Fuzz `FuzzBitwarden` (seeded with testdata: sample, empty, nested, huge names, non-login items, broken totp) and `FuzzBackup` — never panic, never allocate beyond limits, invalid → error in services/warden/tests/fuzz/transfer_fuzz_test.go; fixtures generated by services/warden/tests/testdata/bitwarden/gen.go
- [X] T052 [P] [US3] Handler tests: transfer/backup routes require `transfer:import|export`/`backup:manage`, 413 above 16 MiB, validate writes nothing, export/backup-with-material audited as bulk disclosure with counts in services/warden/internal/httpapi/transfer_test.go
- [X] T053 [P] [US3] Integration `TestBitwarden` (5,000-item file: validate < 10 s, import < 60 s, report correct; SC-006), `TestBackup` (with material into an empty tenant reproduces folders/secrets/versions/grants; SC-007) in services/warden/tests/integration/transfer_test.go
- [X] T054 [P] [US3] UI unit tests: `BitwardenImportDialog` (file pick, validate step shows counts/collisions, duplicate strategy, import report), export/backup buttons gated by abilities in services/warden/ui/tests/unit/transfer.spec.ts

### Implementation for User Story 3

- [X] T055 [US3] `transfer` package: `bitwarden.go` (Parse, Validate, Import with strategy, Export), `backup.go` (Export, Import), bounded JSON decoding helpers, audit `transfer_*`/`backup_*` in services/warden/internal/transfer/{bitwarden.go,backup.go,decode.go} and services/warden/internal/transfer/transferdb/db.go
- [X] T056 [US3] HTTP handlers for transfer and backup routes (streamed JSON responses for export) in services/warden/internal/httpapi/transfer.go; wire in app.go
- [X] T057 [P] [US3] UI: `components/BitwardenImportDialog.vue`, export and backup actions in `views/secrets/index.vue`, download helper in services/warden/ui/src/
- [X] T058 [US3] Playwright: `transfer.spec.ts` (validate + import the sample with rename, export downloads a file) in services/warden/ui/tests/e2e/transfer.spec.ts

**Checkpoint**: migration in and out works; backups restore

---

## Phase 6: User Story 4 - Operate and Observe (Priority: P2)

**Goal**: health incl. Vault, per-tenant statistics, audit trail, password generator.

**Independent Test**: stop Vault → health reports it, reveal answers `vault_unavailable` within 2 s, listings work; start Vault → recovers; statistics match; audit filters work; generator honours classes.

### Tests for User Story 4 (MANDATORY) ⚠️

- [X] T059 [P] [US4] Unit tests for `generator` (length bounds, at least one char per chosen class, no class → error, uniform selection via injected reader, never logged) and `stats` (counts per tenant) in services/warden/internal/generator/generator_test.go and services/warden/internal/stats/stats_test.go
- [X] T060 [P] [US4] Fuzz `FuzzGenerator` (options never panic; output always satisfies the request) in services/warden/tests/fuzz/generator_fuzz_test.go
- [X] T061 [P] [US4] Handler tests: `/generate` (schema bounds, not audited), `/stats` and `/audit` (require `stats:read`, filters, paging, details never carry material), `/health` states in services/warden/internal/httpapi/ops_test.go
- [X] T062 [P] [US4] Integration `TestVaultOutage` (stop container: material ops → 503 within 2 s, no partial rows; restart: recover; reconciler repairs an orphan created by killing the service between Vault write and commit), `TestStats`, `TestAudit`, `TestGenerator` in services/warden/tests/integration/ops_test.go
- [X] T063 [P] [US4] UI unit tests: generator view (options, copy, local generation matches server rules), stats card, audit table filters in services/warden/ui/tests/unit/ops.spec.ts

### Implementation for User Story 4

- [X] T064 [P] [US4] `generator` and `stats` packages in services/warden/internal/generator/generator.go and services/warden/internal/stats/stats.go (+ statsdb)
- [X] T065 [US4] HTTP handlers `generatePassword`, `stats`, `auditTrail`, `health` (db ping, vault health) in services/warden/internal/httpapi/ops.go; wire in app.go; health also on the Freya admin listener
- [X] T066 [P] [US4] UI: `views/generator/index.vue`, stats card and audit table on `views/secrets/index.vue` (abilities `read Stats`) in services/warden/ui/src/
- [X] T067 [US4] Playwright: `ops.spec.ts` (generator, stats visible to admin, hidden from member) in services/warden/ui/tests/e2e/ops.spec.ts

**Checkpoint**: the service is operable and observable

---

## Phase 7: User Story 5 - Hand a Secret to an Outsider (Priority: P3)

**Goal**: email shares with hashed tokens, validity, open budget, CIDR/region policy; public disclosure page; list and cancel.

**Independent Test**: 1-hour single-use share; recipient opens once and sees the password; second open 404; expired/cancelled 404; Viewer cannot share; audit records creation and disclosure.

### Tests for User Story 5 (MANDATORY) ⚠️

- [X] T068 [P] [US5] Unit tests for `share`: create requires share permission, token 32 random bytes → base64url (43 chars) stored only as SHA-256, policy bounds (validity, opens), mail queued with the link and never logged, `Open` (hash lookup, state/expiry/budget/CIDR checks, increments opens atomically, marks consumed, discloses once per open, audits with recipient), uniform `ErrNotFound` for every refusal, `Cancel`, `List(mine)`, expiry sweep in services/warden/internal/share/share_test.go
- [X] T069 [P] [US5] Fuzz `FuzzShareToken` (parser accepts only 43-char base64url; hashing constant-length) in services/warden/tests/fuzz/share_fuzz_test.go
- [X] T070 [P] [US5] Handler tests: `/secrets/{id}/shares` (403 without share), `/shares/{id}/cancel`, public `/warden/share` page (token in the URL fragment) (no-store, CSP nonce from `X-CSP-Nonce`, no material in HTML), `/share/open` (uniform 404, client address from `X-Gateway-Client-Addr` only), rate limit on open in services/warden/internal/httpapi/share_test.go
- [X] T071 [P] [US5] Integration `TestShare` (mail in Mailpit, first open discloses and audits, second 404, expired 404, cancelled 404, CIDR mismatch 404, token absent from DB/logs) in services/warden/tests/integration/share_test.go
- [X] T072 [P] [US5] UI unit tests: share dialog (policies, defaults), my-shares list with cancel in services/warden/ui/tests/unit/share.spec.ts

### Implementation for User Story 5

- [X] T073 [US5] `share` package (create/open/cancel/list, token generation + hashing, policies, sweeper) and `mail` outbox (`net/smtp`, TLS outside dev, template with the link) in services/warden/internal/share/{share.go,mail.go} and services/warden/internal/share/sharedb/db.go
- [X] T074 [US5] HTTP handlers for share routes and the public page (embedded HTML template) in services/warden/internal/httpapi/share.go; wire in app.go
- [X] T075 [P] [US5] UI: `components/ShareDialog.vue` and "Shared links" panel in `SecretDrawer.vue` in services/warden/ui/src/
- [X] T076 [US5] Playwright: `share.spec.ts` (create share, open the link from Mailpit in a fresh context, see the secret once, second open refused) in services/warden/ui/tests/e2e/share.spec.ts

**Checkpoint**: all five stories complete

---

## Phase 8: Polish & Cross-Cutting Concerns

- [X] T077 [P] Docs: `services/warden/docs/{security-model.md (material boundary, Zanzibar check, shares, STRIDE from research.md), operations.md (Vault setup, AppRole rotation, reconciliation, backups, config keys, raised body limit), dependencies.md}`, `services/warden/README.md` (layout, run, gates, moving to its own repository); gateway `docs/module-guide.md` gains the `client_address` route flag; auth docs mention the member lookups; `CHANGELOG.md`
- [X] T078 [P] Redaction/material scan `services/warden/scripts/redaction-scan.sh` run over the integration capture (marker corpus, `token=`, `otpauth://`) and wired into `make redaction-scan` and CI
- [X] T079 [P] Performance check in services/warden/tests/integration/perf_test.go: reveal p95 < 300 ms and 1,000-secret listing < 500 ms on the reference box (SC-002); results recorded in specs/005-warden-secrets/quickstart-results.md
- [X] T080 [P] Security review checklist mapping threats T1–T13 of research.md to tests in specs/005-warden-secrets/checklists/security-review.md
- [X] T081 Run quickstart.md §1–§8 on the live platform stack (gateway allow-list entry for `spiffe://example.org/svc/warden`, warden registered, shell shows the four entries) and record results in specs/005-warden-secrets/quickstart-results.md
- [X] T082 Code cleanup and refactoring pass (no behaviour change; tests stay green) across services/warden and the auth/gateway touch-points

---

## Dependencies & Execution Order

- **Phase 1 → Phase 2 → stories**: skeleton and contracts first; every story needs config, schema, Vault client, audit, the HTTP skeleton with identity middleware, and the manifest.
- **US1 (secrets & folders)** depends on Phase 2 and on the `authz` core (T034, built inside US1 since the creator-owner grant and read/write checks are needed from the first secret).
- **US2 (grants)** depends on US1's `authz` core (T034) and the tree; it can start once T034–T035 exist, in parallel with the rest of US1.
- **US3 (transfer)** depends on US1 (secrets service) and US2 (grants in backups). **US4 (ops)** depends on Phase 2 only (generator, stats, health) plus US1 for the outage test. **US5 (shares)** depends on US1 (reveal) and US2 (share permission).
- Cross-service tasks T024 (gateway) and T025 (auth) are independent of warden code and can run first.

```
Setup (T001–T007)
  └─ Foundational (T008–T025)
       ├─ US1 secrets & folders (T026–T040) ─┬─ US2 grants (T041–T048) ─┬─ US3 transfer (T049–T058)
       │                                     │                           └─ US5 shares (T068–T076)
       └─ US4 ops (T059–T067, outage test after US1)
       └─ Polish (T077–T082) after all stories
```

## Parallel Execution Examples

- **Setup**: T002–T007 in parallel after T001.
- **Foundational tests**: T008–T014 together; then T015 → T016 → T017; T018, T019, T020, T022, T024, T025 alongside T017; T021 after T020; T023 last.
- **US1**: T026–T033 together; T034 → T035 → T036 → T037; T038 and T039 alongside T037; T040 last.
- **US2**: T041–T044 together; T045 → T046; T047 alongside T046; T048 last.
- **US3/US4/US5** follow the same test-first shape; US4's implementation (T064–T066) can run alongside US2.

## Implementation Strategy

- **MVP = Phase 1 + Phase 2 + US1**: a working, audited credential store with material in Vault, demonstrable in the shell.
- **Increment 2 = US2**: precise sharing inside the tenant.
- **Increment 3 = US3 + US4**: migration, backups, operations.
- **Increment 4 = US5**: external shares.
- Keep the two cross-service changes (T024, T025) minimal and covered by their own tests so the auth and gateway suites stay green.
