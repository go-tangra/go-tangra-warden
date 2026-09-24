# services/warden — tenant credential vault

A tenant-scoped secret and credential manager built on the Freya framework
and composed into the platform shell as a federated remote. Secrets (name,
username, password, host, description, free-form metadata, optional TOTP
seed) live in an unlimited-depth folder tree; **passwords and seeds are
stored only in HashiCorp Vault** (KV v2, one path per tenant and secret,
AppRole authentication) while TimescaleDB holds metadata, version references
and checksums. Access is Zanzibar-style (owner / editor / viewer / sharer on
folders or secrets, to users, roles or the tenant, with expiry, inherited down
the tree). Every operation is audited; material never reaches the database,
the audit trail, logs, search or backups taken without material.

Design: `specs/005-warden-secrets/` (spec, plan, research, data model,
contracts, quickstart). Security model: [`docs/security-model.md`](docs/security-model.md).
Operations: [`docs/operations.md`](docs/operations.md). Dependencies:
[`docs/dependencies.md`](docs/dependencies.md).

## Layout

| Path | Purpose |
|------|---------|
| `cmd/wardensvc` | service binary (`run`, `bootstrap`: migrate, vault probe, health) |
| `internal/app` | wiring: config → Freya → store, cache, vault, audit → verifier → HTTP/gRPC → gateway lease, permission seeding, reconciler, share sweeper |
| `internal/authz` | Zanzibar evaluation (check, effective, accessible, grants) — 100 % covered |
| `internal/secrets`, `internal/folders` | secret and folder services (two-phase vault writes, versions, restore, search, TOTP, reconciliation) |
| `internal/share` | external e-mail shares (hashed tokens, budgets, CIDR policy, sweeper, SMTP) — 100 % covered |
| `internal/transfer` | Bitwarden validate/import/export and tenant backups |
| `internal/vault` | KV v2 client with AppRole login and token renewal, plus an in-memory fake — 100 % covered |
| `internal/generator`, `internal/stats`, `internal/audit`, `internal/cache` | password generator (100 %), statistics, audit vocabulary and detail guard, rate counters |
| `internal/repo`, `internal/repo/repodb`, `internal/store`, `internal/memstore` | repository interface, SQL binding (RLS, goose migrations) and in-memory double |
| `internal/httpapi`, `internal/grpcapi` | browser API (OpenAPI-validated, platform token verified with `authclient`) and `warden.v1.Secrets` |
| `pkg/wardenmanifest` | gateway manifest built from the OpenAPI document (routes, permissions, abilities, nav, gRPC methods) |
| `ui` | Vue 3 + Vuetify federated remote (`./routes`, `./nav`) served under `/ui/`, relayed at `/m/warden/` |
| `api/openapi`, `api/proto`, `api/schema` | contracts (`warden.yaml`, `warden.v1`, Bitwarden schema) |
| `tests/{contract,fuzz,integration,testdata}` | contract tests, fuzz targets, testcontainers suite (gateway + auth subprocesses, warden in-process) |

## Run

```sh
# platform: gateway + auth (services/gateway/deploy/compose.yaml, both services running in gateway mode)
make compose-up                      # TimescaleDB :5433, Valkey :6380, Vault dev :8200, Mailpit :8026; runs deploy/vault-init.sh
go run ./cmd/wardensvc bootstrap -config deploy/dev.yaml    # migrations, vault probe, health
go run ./cmd/wardensvc -config deploy/dev.yaml              # registers with the gateway
cd ui && npm ci && npm run build     # then: go run -tags ui ./cmd/wardensvc … to embed the remote
```

The gateway must allow-list the module (`gatewaysvc bootstrap -allow
"spiffe://example.org/svc/warden=/api/warden,/warden/share,/ui;warden"`) and
its edge must accept 16 MiB bodies for transfers (`limits.max_request_bytes:
16842752`). Warden seeds its permissions and built-in role grants with the
auth service at start (owner/admin everything; member secrets read/write/share,
folders and permissions; auditor/operator stats).

## Gates

`make lint` (vet, staticcheck, gosec), `make vuln`, `make test`, `make cover`
(≥ 80 % overall, 100 % for `internal/{authz,vault,share,secrets,generator}`),
`make fuzz`, `make test-integration` (Docker), `make redaction-scan` (marker
corpus over the captured suite), `cd ui && npm run lint && npm run test:unit
&& npm run build`, `make e2e` (Playwright through the gateway).

## Moving to its own repository

The module depends on the framework and on `services/auth/pkg/authclient`
and `services/gateway/pkg/gatewayclient` through `replace` directives in
`go.mod`; drop them and pin published versions. The integration harness builds
the sibling services from `../auth` and `../gateway`; point it at released
binaries or images instead. Nothing else reaches into sibling modules.
