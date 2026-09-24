# Dependencies

Every direct dependency is justified here (Constitution VI). Versions are pinned by `go.sum` / `package-lock.json`; `govulncheck` and `npm audit --audit-level=high` run in CI.

| Dependency | Version | Purpose | Alternatives rejected | Maintenance |
|------------|---------|---------|-----------------------|-------------|
| `github.com/go-tangra/go-tangra/v4` | local (`replace ../..`) | mTLS transports, identity, service policy, audit, observability | — | this repository |
| `github.com/go-tangra/go-tangra-auth/v4` (`pkg/authclient`) | local | verification of the platform token forwarded by the gateway | re-implementing JWT/revocation checks | this repository |
| `github.com/go-tangra/go-tangra-portal/v4` (`pkg/gatewayclient`) | local | registration with the application gateway, manifest types | — | this repository |
| `github.com/hashicorp/vault/api` + `api/auth/approle` | v1.22 / v0.12 | KV v2 reads/writes, AppRole login, token lifetime watcher (research R2) | `vault-client-go` (beta, no lifetime watcher), hand-written HTTP client (custom security code) | HashiCorp, active |
| `github.com/pquerna/otp` | v1.5 | TOTP codes from stored seeds (RFC 6238) | hand-rolled | Active; already vetted by the auth service |
| `github.com/jackc/pgx/v5` | v5.11 | TimescaleDB driver and pool | database/sql + lib/pq | Active |
| `github.com/pressly/goose/v3` | v3.28 | embedded SQL migrations | golang-migrate | Active |
| `github.com/valkey-io/valkey-go` | v1.0 | rate limits and share-open counters | go-redis | Active |
| `github.com/getkin/kin-openapi` | v0.149 | OpenAPI parsing and request validation for the browser API | manual validation per handler | Active |
| `github.com/testcontainers/testcontainers-go` (test only) | v0.44 | TimescaleDB, Valkey, OpenFGA, Vault, Mailpit containers for the integration suite (plus `github.com/moby/moby/client` to pause Vault) | docker compose from tests | Active |
| `github.com/golang-jwt/jwt/v5` (test only) | v5 | minting platform tokens in handler tests | — | Active |
| `github.com/santhosh-tekuri/jsonschema/v6` (test only) | v6 | validating the manifest against the gateway schema in contract tests | — | Active |

UI (pinned by `package-lock.json`): vue 3.5, vuetify 4, vue-router 5, pinia 4, @casl/ability 7 + @casl/vue 3 (abilities from the shell), @mdi/font 7 (icon webfont, bundled), vite 8, typescript 5.9, vitest 5, @playwright/test 1.63 + @axe-core/playwright, openapi-typescript, @module-federation/vite.

## Advisories

None open. `make vuln` runs `govulncheck ./...`.
