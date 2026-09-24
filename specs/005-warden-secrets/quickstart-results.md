# Quickstart results — Warden Secret Manager

Run on 2026-09-16 against the local platform stack: gateway (shell) and auth in
gateway mode rebuilt with this feature's changes, the platform containers from
`services/gateway/deploy/compose.yaml` (TimescaleDB, Valkey, OpenFGA, Mailpit)
plus warden's own containers from `services/warden/deploy/compose.yaml`
(TimescaleDB :5433, Valkey :6380, Mailpit :8026) and a Vault dev server :8200
initialised by `deploy/vault-init.sh`; warden started with `-tags ui` (embedded
remote) and registered through the gateway allow-list.

| § | Scenario | Result |
|---|----------|--------|
| 1 | Gates: `make lint` (vet, staticcheck, gosec) clean; `make vuln` no reachable vulnerabilities; `make cover` total 92.6 % with `internal/{authz,vault,share,secrets,generator}` at 100 %; every fuzz target (`FuzzFolderName`, `FuzzSecretInput`, `FuzzTotpSeed`, `FuzzPathBuilder`, `FuzzBitwarden`, `FuzzBackup`, `FuzzGenerator`, `FuzzShareToken`) clean; UI `npm run lint`, 31 unit tests, `npm run build`; contract tests (OpenAPI ↔ routes, manifest against the gateway schema, proto) | ✅ |
| 2 | `wardensvc bootstrap` migrated, probed the vault (`vault_probe: ok`) and reported `db: ok, vault: ok`; `gatewaysvc bootstrap -allow …/svc/warden=/api/warden,/warden/share,/ui;warden`; warden registered (`gateway lease registered=true`), the remote is relayed at `/m/warden/mf-manifest.json`, `/warden/share` answers the public page; the shell module list carries **Secrets, Folders, Permissions, Generator** for the operator; `GET /api/warden/v1/health` → `vault: ok`; permission seeding with built-in grants succeeded on start (no retry logged) | ✅ |
| 3 | `TestSecrets` (folders, secrets, versions ×3 + restore → v4, search incl. folder path and material never searchable, move, TOTP set/code/remove, vault outage → `vault_unavailable` with metadata readable, delete destroys material, leak scan of every table + audit + gateway/auth/warden logs); Playwright `secrets.spec.ts` through the gateway (create, reveal hidden until click, TOTP code, two rotations, versions, restore v1 → v4, move to root, delete, axe no critical) | ✅ |
| 4 | `TestAccess` (owner/editor/viewer/sharer × read/write/delete/share on a secret three levels deep, tenant grant, revoke enforced on the next request, role grant through an auth group with a 3 s expiry, cross-tenant 404, grants/refusals audited); Playwright `permissions.spec.ts` (grant viewer to a role on a folder, second browser sees the grant with its source, revoke) | ✅ |
| 5 | `TestBitwarden`: 5,000-item file validated in well under 10 s and imported in 27.8 s (budget 60 s; SC-006), export re-validates clean; `TestBackup`: backup with material into an empty tenant reproduces folders, secrets, versions, seeds and grants (SC-007); plain backups carry no material; Playwright `transfer.spec.ts` (validate 20 items / 0 collisions, import with rename, folders appear in the tree, export downloads 20 items) | ✅ |
| 6 | `TestOps`: Vault paused → reveal/create `vault_unavailable` in ≈ 10 s (client timeout with one retry), no partial row, listings and health (`degraded`, `vault: unreachable`, `db: ok`) keep working; recovery; reconciler adopts an interrupted write; stats; audit filters; generator bounds and classes; Playwright `ops.spec.ts` (service and local generators, stats card, audit table) | ✅ |
| 7 | `TestShare`: mail in Mailpit with the link, first open discloses (recipient audited), second 404, expired/cancelled/CIDR-mismatch 404, spoofed `X-Gateway-Client-Addr` dropped by the gateway, tokens absent from every table, audit row and log; Playwright `share.spec.ts` (share from the drawer, link from Mailpit opened in a fresh context, password revealed once, second open refused, share shown consumed) | ✅ |
| 8 | `TestPerformance` (SC-002): reveal p95 10.9 ms (median 6.4 ms), 1,000-secret listing 139 ms through the gateway on the 4-core workstation; full Playwright suite 5/5 with axe reporting no critical issues | ✅ |

`make redaction-scan` over the whole integration capture: 0 matches for
`WARDEN-MARKER-PW-`, `WARDEN-MARKER-SEED-`, `/warden/share[/#]<token>`,
`otpauth://`, PEM and JWT patterns (SC-005).

## Notes

- **Share links moved to the URL fragment** (`/warden/share#<token>`): the
  first integration run found the token in the gateway's request log because
  it travelled in the path. Browsers never send the fragment, so no server,
  proxy or log sees it; the public page reads it, removes it from the address
  bar and posts it on user action. Contracts and research R8 updated.
- **Listing performance**: the first measurement of the 1,000-secret listing was
  2.4 s because permissions were evaluated per row; listings now read the
  caller's grants once and combine them with the folder decision (139 ms).
- **Transfer routes** declare a 120 s gateway timeout (`x-freya-timeout-seconds`);
  the default 30 s module timeout was too short for a 5,000-item import.
- **Auth `RegisterPermissions` gained `builtin_grants`** so warden seeds its
  role grants itself (the gateway registers permissions without grants);
  the ability subject for the audit trail is `WardenAudit` because ability
  subjects are platform-unique and `AuditEvent` belongs to auth.
- **Pre-existing issues fixed on the way**: the redaction-scan scripts of auth,
  gateway and warden exited 1 on a clean capture (`grep -c` with no match under
  `set -o pipefail`); the platform Valkey container predated the `&*` channel
  ACL and made the rebuilt gateway log `NOPERM` every second (recreated from the
  current compose file); the gateway dev config's `limits.max_request_bytes`
  raised to 16 MiB + slack for transfer uploads.
- Running warden's compose file next to the gateway's with the legacy
  `docker-compose` v1 clashed on the shared project name `deploy` and stopped
  the platform containers; the Makefile now passes `-p warden`.
- Playwright needs `PW_CHANNEL=chrome` on this workstation (bundled browsers
  are not installed for the pinned Playwright version); the operator for the
  e2e run was created with `authsvc bootstrap -operator-email ops3@example.org`.
