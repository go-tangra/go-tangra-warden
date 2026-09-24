# Quickstart — Warden Secret Manager

Validates the feature end-to-end on the platform stack (auth in gateway mode +
gateway with the shell + warden), with a Vault dev server. Contracts are in
[contracts/](contracts/), entities in [data-model.md](data-model.md).

## Prerequisites

Go 1.26, Node 22, Docker with compose; test CA from `make testca` with
`-services auth,gateway,hello,warden`; the auth and gateway changes in
`contracts/auth-changes.md` applied.

## 1. Stack and gates

```bash
make -C services/warden compose-up      # TimescaleDB (warden db), Valkey, Vault dev + AppRole init (deploy/.vault/{role_id,secret_id})
make -C services/warden lint vuln cover fuzz   # vet, staticcheck, gosec, govulncheck, coverage gate (100 % on internal/{authz,vault,share,secrets}), fuzz corpus
(cd services/warden/ui && npm ci && npm run lint && npm run test:unit && npm run build:remote)
go test ./services/warden/tests/contract/...   # OpenAPI ↔ routes, manifest, proto
```

## 2. Start and register

```bash
(cd services/warden && go run ./cmd/wardensvc bootstrap -config deploy/dev.yaml)   # migrations, Vault access check
(cd services/gateway && go run ./cmd/gatewaysvc bootstrap -config deploy/dev.yaml -allow spiffe://example.org/svc/warden=/api/warden,/warden/share)
(cd services/warden && go run -tags ui ./cmd/wardensvc -config deploy/dev.yaml)
```

Expected: gateway log `registration_accepted module=warden`; the shell shows
**Secrets** (explorer: folder pane + contents), **Permissions**, **Generator** for a tenant admin
(auth seeds `secrets:*`, `folders:manage`, … to the built-in roles on start);
`GET /api/warden/v1/health` reports `vault: ok`.

## 3. Keep credentials in folders (US1)

```bash
go test -tags integration ./services/warden/tests/integration -run 'TestSecrets|TestFolders|TestVersions|TestSearch|TestTotp' -v
```

Covers: create/read/reveal/update/password change/versions/restore/move/delete
against a real Vault; the password never appears in the database, audit rows
or logs (marker corpus scan); tree of depth 5; move refuses cycles; recursive
delete; search filtered by access; TOTP code from an otpauth seed.

Manual, in the shell: **Secrets → New** in a folder, reveal (audited),
change the password twice with comments, open **Versions**, restore v1, move
the secret in the tree.

## 4. Share precisely (US2)

```bash
go test -tags integration ./services/warden/tests/integration -run 'TestAccess' -v
```

Covers: owner/editor/viewer/sharer matrix on a secret and through three folder
levels; role grants through groups (feature 004); tenant-wide grants; expiry
(clock advanced); granter cannot exceed own relation; cross-tenant 404;
accessible-resources and effective-permissions with sources; every grant and
refusal audited (SC-003, SC-004, SC-009).

Manual: **Permissions**: grant Viewer on "Infra" to role `ops` until tomorrow;
sign in as an `ops` member: read but not edit; **Effective** explains why.

## 5. Move credentials in and out (US3)

```bash
go test -tags integration ./services/warden/tests/integration -run 'TestBitwarden|TestBackup' -v
go test ./services/warden/tests/fuzz -run xxx -fuzz FuzzBitwarden -fuzztime 60s
```

Covers: validate reports counts/collisions/problems and writes nothing;
skip/rename/overwrite; password history → versions; export and re-validate;
5,000-item file under the budgets (SC-006); backup with/without material,
import into an empty tenant reproduces everything (SC-007); oversized and
malformed files refused.

Manual: **Secrets → Import**: pick the sample export in
`services/warden/tests/testdata/bitwarden/sample.json`, validate, import with
"rename".

## 6. Operate and observe (US4)

```bash
go test -tags integration ./services/warden/tests/integration -run 'TestVaultOutage|TestStats|TestAudit|TestGenerator' -v
```

Covers: Vault stopped → reveal/create answer `vault_unavailable` within 2 s,
listings work, no partial rows; reconciler repairs an orphaned KV version;
statistics match; audit filters; generator class guarantees and distribution.

Manual: `docker stop` the Vault container, reveal a password (error banner),
start it, reveal again; **Generator** with symbols on.

## 7. Hand a secret to an outsider (US5)

```bash
go test -tags integration ./services/warden/tests/integration -run 'TestShare' -v
```

Covers: 1-hour single-use share; mail in Mailpit with the link; first open
discloses and audits; second open 404; expired/cancelled 404; Viewer cannot
share; token never stored or logged in clear.

Manual: share a secret with your Mailpit address, open the link from
http://localhost:8025, see the secret once.

## 8. Platform surfaces

```bash
(cd services/warden/ui && E2E_OPERATOR_EMAIL=... E2E_OPERATOR_PASSWORD=... PW_CHANNEL=chrome npx playwright test)
```

Expected: the remote composes in the shell without reload; abilities hide
what the caller lacks; axe reports no serious or critical issues (SC-010).
