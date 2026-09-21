# Security Review Checklist: Warden secrets

**Purpose**: map every threat of research.md's STRIDE table to the mitigation in code and the test that proves it
**Created**: 2026-09-16
**Feature**: [spec.md](../spec.md) · [research.md](../research.md) §Threats

| Threat | Mitigation (code) | Proof (tests) | Status |
|--------|-------------------|---------------|--------|
| T1 read another tenant's secret by id | tenant from the platform token (`httpapi.Caller`), RLS (`0003_rls.sql`, `store.Tx(Scope)`), vault path from the tenant id (`vault.Path`), uniform `not_found` (`authz.locate`) | `store.TestMigrateSchemaAndRLS`, `authz.TestCheckLattice` (cross-tenant), `httpapi` 404 cases, integration `TestAccess` (SC-003) | ✓ |
| T2 material leaks via DB, logs, audit, search, backup, errors | material only in Vault (`secrets`, `transfer`), audit detail guard (`audit.guard`), `vault.mapErr` redaction, generated search column excludes metadata, material-less backups | `audit.TestRowRedaction`, `secrets` `noMarkers` in every test, `ScanForMaterial` in every integration test, `make redaction-scan`, `httpapi` "no material in listings" (SC-005) | ✓ |
| T3 granting more than held / on foreign resources | `authz.Grant` requires `share` and relation ≤ granter's; input validated | `authz.TestGrantRevokeList`, `httpapi.TestGrantRoutes`, `TestAccess` matrix (sharer grants viewer only) | ✓ |
| T4 stale access after revoke/expiry | no decision cache; `authz.evaluate` filters expiry per request | `authz` expiry boundary tests, `TestAccess` (revoke then refuse; 3 s expiry) (SC-004) | ✓ |
| T5 vault credential theft/misuse | AppRole from 0600 files or env, token renewed by the lifetime watcher and never logged, policy scoped to `warden/*`, TLS unless `allow_plaintext` (refused in production by `config.Validate`) | `vault.TestClientRefusals`, `TestTokenRenewalAndRelogin`, `config_test` production refusals, `wardensvc bootstrap` probe | ✓ |
| T6 share link guessing/replay/forwarding | 256-bit token, SHA-256 at rest, budget + expiry + state, uniform 404, `no-store` page, rate limit per address and token, token in the URL fragment | `share.TestOpen`, `FuzzShareToken`, `httpapi.TestShareRoutes` (rate limit), integration `TestShare` (second open 404, spoofed address) | ✓ |
| T7 malicious import | `transfer.DecodeBounded` (16 MiB, depth 8, 50k items, 10k folders), per-field validation, validate writes nothing | `transfer.TestDecodeBounds`, `FuzzBitwarden`, `FuzzBackup`, `httpapi.TestTransferRoutes` (413, encrypted, malformed) | ✓ |
| T8 TOTP seed disclosure | seed stored in Vault only; `secrets.TOTPCode` returns codes; views never carry it | `secrets.TestMoveDeleteTOTP`, `httpapi.TestSecretRoutes` (no `totp` in any representation), `FuzzTotpSeed` | ✓ |
| T9 partial writes during a vault outage | two-phase write with rollback of the row, `Reconcile` for interrupted commits and deletes | `secrets.TestVaultFailuresOnCreate`, `TestReconcile`, integration `TestOps/VaultOutage` (no partial row) and `Reconciler` | ✓ |
| T10 export/backup as exfiltration | `transfer:export` / `backup:manage` permissions at the gateway, bulk-disclosure audit with counts, 120 s route timeout | `transfer.TestExportBitwarden`, `TestBackupExportImport` (audit details), `httpapi.TestTransferRoutes` | ✓ |
| T11 metadata smuggling into search/logs | metadata never indexed (`search` column) nor audited; 16 KiB cap | `secrets` validation tests, `store.TestMigrateSchemaAndRLS` (search by host only), `FuzzSecretInput` | ✓ |
| T12 folder cycle via move | `folders.Move` ancestor check | `folders.TestRenameMoveDelete`, `httpapi.TestFolderRoutes` (409) | ✓ |
| T13 enumeration via search/list | results filtered by the readable scope before paging (`secrets.readableScope`, `List` under folder or root check) | `secrets.TestListAndSearch` (bob scope), `httpapi.TestSecretRoutes` (bob search empty) | ✓ |
| Gateway header spoofing (`X-Gateway-Client-Addr`) | gateway strips every inbound `X-Gateway-*` header and sets the address only on flagged routes | gateway `TestForwardingHeaderPolicy`, `TestDispatchClientAddress`, integration `TestShare` spoof case | ✓ |
| Contract drift (route without handler, undeclared route) | `Server.Handle` refuses undeclared routes; `app.CheckRoutes` at start; manifest built from the document | `tests/contract`, `httpapi.TestDeclaredRoutesMountedAndAuthenticated` | ✓ |

## Residual risks

- Region share policies are refused until a GeoIP source exists (documented in
  contracts/manifest.md).
- The share page relies on the gateway relaying the CSP nonce; without it the
  inline script does not run and the recipient sees only the static page.
- A Vault dev server loses everything on restart; production must run a
  persistent, unsealed cluster with TLS.
