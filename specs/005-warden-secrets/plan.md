# Implementation Plan: Warden Secret Manager

**Branch**: `005-warden-secrets` | **Date**: 2026-09-16 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/005-warden-secrets/spec.md`; user
direction for this plan: *"use vault as secret storage and timescale for path
reference"* — secret material lives in HashiCorp Vault KV v2, and the service's
own records (TimescaleDB) hold the Vault path/version references, never the
material.

## Summary

`services/warden` is a new Freya platform module (same shape as
`services/auth`, `services/gateway`, and the hello example): a Go service on the
Freya mTLS channel that registers with the application gateway, verifies the
platform token forwarded by the gateway with `pkg/authclient`, stores folder,
secret, version, grant, share and audit rows in TimescaleDB, and stores every
password and TOTP seed in HashiCorp Vault KV v2 under a per-tenant prefix the
service derives from the verified tenant. Password versions map one-to-one to
KV v2 versions; restore writes the old value as a new version. Zanzibar-style
access (Owner/Editor/Viewer/Sharer on folders and secrets, to users, roles or
the tenant, with expiry, inherited down the tree) is evaluated in one indexed
SQL query over the resource's ancestor chain and the caller's subjects (user id,
effective role slugs from the platform token, tenant); no second policy store.
The browser API is an OpenAPI document validated by kin-openapi (as in auth), a
small `warden.v1` gRPC surface serves other platform services, and the UI is a
Vue 3 + Vuetify Module Federation remote composed by the shell. Bitwarden
import/export, tenant backups, statistics, health (including Vault), a
server-side password generator and external email shares with hashed,
policy-bound links complete the reference feature set.

## Technical Context

**Language/Version**: Go 1.26 (service), TypeScript 5 / Vue 3 / Vuetify 4 (remote)

**Primary Dependencies**: Freya framework (transport, identity, audit, config), `services/auth/pkg/authclient` (token verification), `services/gateway/pkg/gatewayclient` (registration, manifest), pgx + goose (TimescaleDB), kin-openapi (request validation), `github.com/hashicorp/vault/api` (KV v2 + AppRole + token renewal — research R2), `github.com/pquerna/otp` (TOTP codes, already used by auth), Module Federation runtime (UI). No ORM.

**Storage**: TimescaleDB (`warden` database, `warden_app` role, RLS per tenant): `folders`, `secrets`, `secret_versions`, `grants`, `shares`, `warden_audit_events` (hypertable). HashiCorp Vault KV v2 mount `warden`: `warden/data/<tenant_id>/secrets/<secret_id>` (password, versioned) and `.../<secret_id>/totp` (seed). Valkey: rate limits and share-open counters only.

**Testing**: Go unit (memstore double, fake Vault), contract (OpenAPI ↔ routes, proto, manifest), fuzz (Bitwarden parser, backup parser, folder path parser, share token, password generator), integration (testcontainers: TimescaleDB, Valkey, **Vault dev server** with AppRole, auth as a subprocess like feature 003's harness), Vitest, Playwright + axe through the gateway.

**Target Platform**: Linux server; evergreen browsers through the platform shell.

**Project Type**: web service + federated remote (platform module).

**Performance Goals**: reveal/read version p95 < 300 ms with Vault healthy (SC-002); list 1,000 secrets < 500 ms; permission check is one SQL query (< 5 ms) executed once per request; 5,000-item Bitwarden import < 60 s (SC-006).

**Constraints**: material never in DB/logs/audit/search/backups-without-material (SR-001, scanned); tenant-derived Vault paths (SR-002); Vault outage fails closed for material, metadata keeps working (SC-008); upload/download ≤ 16 MiB (route-level `x-freya-max-body-bytes`, service `limits.max_request_bytes` raised accordingly, documented); share links ≥ 128 bits, stored hashed (SR-005).

**Scale/Scope**: tenants up to 100k secrets and 10k folders; paged listings (100 per page); ~35 HTTP endpoints, 1 gRPC service (3 methods), 5 UI views, 6 tables, 1 Vault mount.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- [x] **I. Secure by Default**: Vault is required (no "database fallback"), AppRole credentials from files/secrets provider, TLS to Vault required outside dev (`vault.allow_plaintext` opt-out logs a warning), shares default to 1 hour / 1 open, exports and backups-with-material require dedicated permissions, no public route except the share disclosure page (capability-protected). PASS
- [x] **II. Zero Trust**: gateway → warden over mTLS; every route/method declared in the manifest with a permission; the platform token is verified with `authclient` middleware before handlers; gRPC methods policed by `policy.yaml`; Vault reached with the service's own AppRole token; tenant from the verified token only. PASS
- [x] **III. Boundary Validation**: OpenAPI schemas with lengths/patterns and `additionalProperties: false`; kin-openapi validation; Bitwarden/backup files parsed with size and depth bounds and validated field by field; path params are UUIDs; proto messages validated in handlers (small surface). PASS
- [x] **IV. Test-First**: tests listed before implementation per story; negative tests for cross-tenant, escalation, expired grants, share replay, malicious imports; fuzz for every parser; material-leak scan; `internal/authz`, `internal/vault`, `internal/share`, `internal/secrets` (material paths) at 100 %. PASS
- [x] **V. Observability**: audit hypertable with closed vocabulary; every material read audited with version; refusals audited; the framework's redacting logger plus warden's own detail guard (keys `password`, `seed`, `totp`, `link`, `token` never in details); correlation ids from the gateway; health/metrics on the admin listener only. PASS
- [x] **VI. Supply Chain**: new modules `github.com/hashicorp/vault/api` (research R2) and `github.com/pquerna/otp` (already vetted in auth); everything else already in the tree; `govulncheck` in CI; no cryptography beyond stdlib (`crypto/rand`, `crypto/sha256`) and the framework's `crypto`. PASS
- [x] **VII. Simplicity**: one SQL access check instead of a second policy store; KV v2 native versioning instead of a home-made version store; no ORM; sharing implemented in-service (no separate sharing service); device/MAC share policies dropped. Complexity Tracking records the 16 MiB body override. PASS
- [x] **Threat Model**: STRIDE table in research.md §Threat model. PASS

Post-design re-check (after Phase 1): unchanged, all PASS.

## Project Structure

### Documentation (this feature)

```text
specs/005-warden-secrets/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── warden-api.openapi.yaml     # browser API (through the gateway)
│   ├── warden.v1.proto             # service-to-service gRPC
│   ├── manifest.md                 # gateway manifest: prefixes, permissions, abilities, nav
│   ├── vault-layout.md             # KV v2 paths, AppRole policy, versions
│   ├── auth-changes.md             # member-level user/role lookup endpoints in the auth service
│   └── bitwarden.schema.json       # accepted import document
└── tasks.md
```

### Source Code (repository root)

```text
services/warden/
├── go.mod                          # replace github.com/go-freya/freya => ../..; requires services/auth, services/gateway (pkg only)
├── cmd/wardensvc/{main.go,bootstrap.go}   # run; bootstrap creates DB schema and verifies Vault access
├── api/
│   ├── openapi/{warden.yaml,openapi.go}   # embedded contract
│   ├── proto/warden/v1/{warden.proto,*.pb.go}
│   └── schema/bitwarden.schema.json
├── internal/
│   ├── config/                     # Config{Freya inline, DB, Valkey, Vault{Address, Mount, RoleIDFile, SecretIDFile, AllowPlaintext, CAFile}, Gateway, Share{PublicOrigin, Mail}, Limits}
│   ├── store/                      # pgx repos, migrations/000{1..3}_*.sql, RLS, hypertable
│   ├── memstore/                   # in-memory Store double for unit tests
│   ├── vault/                      # KV v2 client: Put/Get(version)/Delete/Versions, AppRole login + LifetimeWatcher, fake for tests
│   ├── audit/                      # writer + closed vocabulary + detail guard
│   ├── authz/                      # Zanzibar check: subjects from identity, ancestor chain, relation lattice, grant/revoke/list/effective
│   ├── folders/                    # tree, move (cycle check), delete (recursive), path maintenance
│   ├── secrets/                    # create/get/reveal/update/password/versions/restore/move/delete/search/totp; two-phase write with Vault
│   ├── transfer/                   # bitwarden.go (parse, validate, import, export), backup.go
│   ├── share/                      # create/open/cancel/list, token hashing, policies, mail
│   ├── generator/                  # password generator
│   ├── stats/                      # counts per tenant
│   ├── httpapi/                    # OpenAPI-validated handlers, authclient middleware, share page
│   ├── grpcapi/                    # warden.v1 Secrets service
│   └── app/                        # wiring, gateway registration, health
├── pkg/wardenmanifest/             # gateway manifest (routes from the OpenAPI doc, permissions, abilities, nav)
├── ui/                             # Vue 3 + Vuetify remote (module-federation.config.ts exposes ./routes, ./nav)
│   ├── src/{api,stores,views/{secrets,folders,permissions,generator},components,remote}
│   └── tests/{unit,e2e}
├── deploy/{compose.yaml (TimescaleDB, Valkey, Vault dev + AppRole init), init-db.sql, vault-init.sh, dev.yaml, policy.yaml}
├── docs/{security-model.md,operations.md,dependencies.md}
├── scripts/{coverage-gate.sh,redaction-scan.sh}
├── Makefile
└── tests/{contract,fuzz,integration}
```

**Structure Decision**: mirror `services/auth` (domain packages under `internal/`, `*db` adapters next to them, `memstore` double, embedded OpenAPI, `pkg/<module>manifest`), and the hello example for gateway registration and token verification. The UI lives in `ui/` (not `console/`) and is embedded with `-tags ui` like the hello module.

## Complexity Tracking

| Item | Why Needed | Simpler Alternative Rejected Because |
|------|------------|-------------------------------------|
| Request body limit 16 MiB on `/api/warden/v1/transfer/*` and `/backup/import` (service `limits.max_request_bytes` raised to match, gateway route `max_body_bytes`) | Bitwarden exports and tenant backups of a few thousand items exceed 1 MiB | chunked upload would add a session/upload state machine for no security gain; the limit is per-route in the manifest and JSON handlers keep the 64 KiB cap |
| Two stores (TimescaleDB + Vault) with a two-phase write | the spec requires material outside the database | storing material encrypted in the database would satisfy "never plaintext" but not the requirement; Vault also gives versioning, sealing and audit for free |
