# Warden security model

## Material boundary

- Passwords and TOTP seeds exist in exactly one place: HashiCorp Vault KV v2
  under `warden/data/<tenant_id>/secrets/<secret_id>` (one KV version per
  password version) and `…/<secret_id>/totp`. The path builder accepts only
  UUIDs for both ids, so no input can escape the tenant prefix.
- The database stores metadata, the vault path, version numbers, SHA-256
  checksums and comments. The generated `search` column covers name,
  username, host and description only; metadata is never indexed.
- Material appears in exactly these API answers: password reveal (audited with
  the version), share open (audited with the recipient), Bitwarden export and
  backup with material (both audited as bulk disclosures with counts), and the
  generator (never stored, never audited).
- The audit detail guard refuses keys containing `password`, `secret_value`,
  `seed`, `totp`, `token`, `link` and any string matching the marker corpus
  (`WARDEN-MARKER-*`, share links, `otpauth://`, PEM, JWT). The integration
  suite uses marker passwords everywhere and, after every flow, dumps every
  table, the audit hypertable and the captured logs and asserts the markers
  are absent (`ScanForMaterial`, `make redaction-scan`).
- Vault outages fail closed: material operations answer `vault_unavailable`
  within the client timeout; metadata stays readable; a write interrupted
  after the vault put is settled by the reconciler (adopt the vault versions
  or remove the orphan row); a delete interrupted before the vault destroy
  leaves the row hidden until the reconciler finishes.

## Identity and tenancy

- Browsers reach warden only through the application gateway, which verifies
  the session and forwards a short-lived platform token. Every non-public
  route runs `authclient` verification (keys and revocation feed from the
  auth service); the tenant and the effective roles (direct and through
  groups) come from the token, never from the request.
- Database access runs under row-level security: each transaction sets
  `app.tenant_id`; only the reconciler, the share sweeper and the public
  share lookup run in system scope. A foreign resource is indistinguishable
  from a missing one (`not_found`).

## Authorization (Zanzibar-style)

- Relations: owner (read, write, delete, share), editor (read, write), viewer
  (read), sharer (read, share), granted on a folder or a secret to a user, a
  role or the whole tenant, optionally expiring. Grants on folders are
  inherited by every descendant; the strongest relation wins and permissions
  are the union.
- One evaluation loads the resource and its ancestor chain and the grants on
  those ids; the decision is computed in memory from the caller's subjects.
  Creating a folder or a secret grants the creator `owner`.
- Granting requires `share` on the resource and never above the granter's
  own strongest relation; listing grants requires `share`; effective
  permissions are always readable (they describe the caller). Every refusal is
  audited (`access_refused` with the permission).
- The gateway enforces the API permission of each route first
  (`secrets:read` … `stats:read`, seeded to built-in roles by warden itself).

## External shares

- A share is a 256-bit random token stored only as its SHA-256; the link
  `https://<origin>/warden/share#<token>` keeps the token in the URL fragment,
  so no server, proxy or request log ever sees it. The public page carries no
  token and no material; its inline script (allowed by the gateway CSP through
  the relayed nonce) reads the fragment, removes it from the address bar and
  posts it to `/api/warden/v1/share/open` on user action.
- Policies: validity 5 min – 7 d, 1 – 10 reveals, optional CIDR evaluated
  against the client address the gateway relays in `X-Gateway-Client-Addr`
  only on that route (inbound copies are dropped); region policies are
  refused until a GeoIP source exists. Every refusal (bad, unknown, expired,
  exhausted, cancelled, policy) is a uniform `not_found`, audited as
  `share_refused`; disclosure happens only after the atomic open increment.
  Opens are rate-limited per client address and per token.
- The link leaves warden only through the notification module (mesh mTLS,
  system template `warden.share`, key namespace `warden.*`), as a secret
  variable that notification redacts in its delivery log and audit. warden's
  own logs, errors and the development log sink carry the recipient and the
  template, never the link. A share whose mail was not confirmed as sent is
  cancelled at once.

## Threats (research.md STRIDE table) and where they are tested

| Threat | Mitigation | Tests |
|--------|------------|-------|
| T1 cross-tenant access | RLS + tenant from the token + uniform 404 | store `TestMigrateSchemaAndRLS`, authz cross-tenant cases, integration `TestAccess` |
| T2 material leaks | vault-only material, detail guard, redacting sink, marker scan | audit guard tests, `noMarkers` in secrets tests, `ScanForMaterial` in every integration test, `make redaction-scan` |
| T3 privilege escalation via grants | granter bound to own relation, share required | authz `TestGrantRevokeList`, handler `TestGrantRoutes`, `TestAccess` matrix |
| T4 stale access after revoke/expiry | no decision cache; expiry evaluated per request | authz expiry tests, `TestAccess` (revoke and 3-second expiry) |
| T5 vault outage | fail closed, no partial rows, reconciler | secrets `TestVaultFailuresOnCreate`, `TestReconcile`, integration `TestOps/VaultOutage` |
| T6 share token guessing / replay | 256-bit token, hash at rest, budget, rate limit | share tests, `FuzzShareToken`, `TestShareRoutes` rate limit |
| T7 share link in logs | fragment transport | `TestShare` leak scan of gateway/auth/warden logs |
| T8 malicious import documents | bounded decoder (16 MiB, depth 8, 50k items), per-field validation | `TestDecodeBounds`, `FuzzBitwarden`, `FuzzBackup`, handler 413 tests |
| T9 TOTP seed misuse | seed never returned; codes computed server-side; otpauth/base32 validated | `TestNormalizeSeed`, `FuzzTotpSeed`, drawer tests |
| T10 export as exfiltration | dedicated permissions, bulk-disclosure audit with counts | transfer tests, `TestTransferRoutes` |
| T11 weak generated passwords | crypto/rand, rejection sampling, class guarantee | generator tests, `FuzzGenerator` |
| T12 forged platform tokens / spoofed gateway headers | authclient verification, `X-Gateway-*` stripped by the gateway | httpapi `TestDeclaredRoutesMountedAndAuthenticated`, gateway `TestDispatchClientAddress`, `TestShare` spoof case |
| T13 contract drift | every declared route must have a handler; manifest built from the document | `CheckRoutes` at start, contract tests |
