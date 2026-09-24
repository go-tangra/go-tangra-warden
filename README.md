# go-tangra-warden

Tenant credential vault for the
[go-tangra v4 platform](https://github.com/go-tangra/go-tangra).

Secrets (name, username, password, host, description, free-form metadata,
optional TOTP seed) live in an unlimited-depth folder tree. **Passwords and seeds
are stored only in HashiCorp Vault** (KV v2, one path per tenant and secret,
AppRole authentication); TimescaleDB holds metadata, version references and
checksums. Access is Zanzibar-style (owner / editor / viewer / sharer on folders
or secrets, granted to users, roles or the tenant, with expiry, inherited down
the tree). External e-mail shares, a password generator, Bitwarden import/export
and tenant backups complete the operator surface. Every operation is audited;
material never reaches the database, the audit trail, logs, search or backups
taken without material.

Security model: [`docs/security-model.md`](docs/security-model.md).
Operations: [`docs/operations.md`](docs/operations.md).
Dependencies: [`docs/dependencies.md`](docs/dependencies.md).
Design history: `specs/005-warden-secrets`.

## Place in the platform

```
go-tangra/go-tangra          platform module + @go-tangra/ui kit
        |
go-tangra-auth  <---->  go-tangra-portal (gateway)  <---->  go-tangra-warden
                              |                               ^
                         go-tangra-lcm (SVIDs)        ipam, ticket, dns (warden sdk)
```

- Built on `github.com/go-tangra/go-tangra/v4` (mTLS transports, identity,
  service policy, audit, observability).
- Verifies platform tokens and seeds its permissions and built-in role grants
  with the auth SDK (`github.com/go-tangra/go-tangra-auth/sdk/v4`).
- Registers with the gateway through the portal SDK
  (`github.com/go-tangra/go-tangra-portal/sdk/v4`), which fronts the browser API,
  the public share route and the federated UI remote.
- Enrolls for its workload identity with lcm (`github.com/go-tangra/go-tangra-lcm/sdk/v4`).

## Modules in this repository

| Module | Path | Consumers |
|---|---|---|
| `github.com/go-tangra/go-tangra-warden/v4` | `/` | the service (`cmd/wardensvc`) and `pkg/wardenmanifest` |
| `github.com/go-tangra/go-tangra-warden/sdk/v4` | `sdk/` | other services: the `warden.v1` protobuf API (secret references resolved over mTLS) |

The service builds against the in-repo SDK through
`replace github.com/go-tangra/go-tangra-warden/sdk/v4 => ./sdk`. Consumers use the
SDK's published `sdk/vX.Y.Z` tag.

## Layout

| Path | Purpose |
|------|---------|
| `cmd/wardensvc` | service binary (serve, `bootstrap`: migrate, vault probe, health; `version`) |
| `internal/app` | wiring: config, platform, store, cache, vault, audit, HTTP/gRPC, gateway lease, permission seeding, reconciler, share sweeper |
| `internal/authz` | Zanzibar evaluation (check, effective, accessible, grants) |
| `internal/secrets`, `internal/folders` | secret and folder services (two-phase vault writes, versions, restore, search, TOTP, reconciliation) |
| `internal/share` | external e-mail shares (hashed tokens, budgets, CIDR policy, sweeper, SMTP) |
| `internal/transfer` | Bitwarden validate/import/export and tenant backups |
| `internal/vault` | KV v2 client with AppRole login and token renewal, plus an in-memory fake |
| `internal/...` | generator, statistics, audit vocabulary, rate counters, repository and SQL bindings (RLS, goose migrations) |
| `pkg/wardenmanifest` | gateway manifest built from the OpenAPI document |
| `ui` | Vue 3 + FlyonUI federated remote on `@go-tangra/ui` |
| `api/openapi`, `api/schema`, `sdk/api/proto` | contracts (`warden.yaml`, Bitwarden schema, `warden.v1`) |
| `deploy` | compose stack (TimescaleDB, Valkey, Vault dev, Mailpit), dev configuration, policy, `vault-init.sh` |
| `tests/{contract,fuzz,integration,testdata}` | contract, fuzz and Docker-backed integration suites |

## Build and test

You need Go 1.26, Node 22, Docker (for integration tests and the image), and a
GitHub token with `read:packages` to install `@go-tangra/ui` from GitHub Packages.

```bash
go build ./... && go vet ./... && go test -race ./...
(cd sdk && go vet ./... && go test -race ./...)
(cd sdk && buf lint)
make test-integration                     # -tags integration, needs Docker
make lint cover fuzz redaction-scan vuln

cd ui
export NODE_AUTH_TOKEN=$(gh auth token)   # ui/.npmrc only references this variable
npm ci && npm run lint && npm run test:unit && npm run build
```

The unit coverage gate requires at least 80 % overall and 100 % for
`internal/{authz,vault,share,secrets,generator}`. Generated code, SQL bindings
and wiring are covered by the integration suite instead.

The integration harness starts real auth and gateway processes. It still builds
them from sibling checkouts (`../auth`, `../gateway`, as in the former monorepo
layout); point it at released binaries or images before running it standalone.

## Run locally

```bash
make compose-up                           # TimescaleDB :5433, Valkey :6380, Vault dev :8200, Mailpit; runs deploy/vault-init.sh
go run ./cmd/wardensvc bootstrap -config deploy/dev.yaml
go run -tags ui ./cmd/wardensvc -config deploy/dev.yaml  # after the ui build
```

The gateway must allow-list the module
(`spiffe://example.org/svc/warden=/api/warden,/warden/share,/ui;warden`) and its
edge must accept 16 MiB bodies for transfers (`limits.max_request_bytes: 16842752`).

## Container image

The image is `ghcr.io/go-tangra/go-tangra-warden`, built by `.github/workflows/ci.yaml`.
It carries `wardensvc` with the embedded UI remote.

```bash
docker buildx build --secret id=npm_token,env=NODE_AUTH_TOKEN \
  --build-arg APP_VERSION=4.0.0 -t go-tangra-warden:dev .
docker run --rm go-tangra-warden:dev version
```

The image runs `wardensvc -config deploy/dev.yaml` as user `app` (uid 10001).
Deployments mount their own configuration and the Vault AppRole credentials
(`vault.role_id_file` / `vault.secret_id_file`); `deploy/.vault` is never copied
into the image.

## Versioning

- Service releases are tagged `vX.Y.Z`. CI publishes the image as `X.Y.Z`,
  `X.Y`, `X` and `sha-<short>`. There is no `latest` tag.
- The SDK is released separately with `sdk/vX.Y.Z` tags. These tags never build an image.
- v4.0.0 rebuilds the service on the go-tangra v4 platform. The v3 line stays on
  the `v3` branch and its `v3.x` tags.
