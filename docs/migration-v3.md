# Migrating warden v3 data into warden v4

One-off runbook for the production host: move the v3 warden tenant (portal
Postgres `gwa` + v3 Vault) into the v4 warden of the `freya-stack` compose
project, keeping folder trees, every password version Vault still holds,
TOTP authenticators, grants, original timestamps and authors.

The two stacks live on separate Docker networks and **both Vaults answer to
the name `vault`**, so no single process may reach both. The migration is
therefore two subcommands of the v4 `wardensvc` image, run as two separate
one-off containers:

| step | network | reads | writes |
|------|---------|-------|--------|
| `wardensvc export-v3` | `portal_app-tier` (v3) | v3 Postgres in one `READ ONLY` transaction, v3 Vault (AppRole, read calls only) | a sealed bundle + a one-time key file |
| `wardensvc import-v3` | `freya-stack` (v4) | the bundle (decrypted in memory only), `users.csv` | v4 warden database and Vault |

The bundle is JSON → gzip → AES-256-GCM under a random 32-byte key; the key
is written to its own file. Both files are created mode 0600 and never
overwritten. Neither command prints or logs passwords, TOTP seeds, links or
the key; reports carry counts, folder/secret paths and e-mail addresses.

## What is and is not migrated

Migrated:

- folders (tree, names, created/updated time and author);
- secrets: name, username, URL, description, metadata, created/updated time
  and authors; **every version Vault still holds, with its original version
  number**, comment, time and author (v4 version source `migration-v3`).
  Versions Vault no longer has (KV keeps at most 10; destroyed or deleted
  ones) are recorded as `material_missing` and stay unreadable;
- TOTP: the v3 `otpauth://` URL is stored in v4's canonical form (secret,
  algorithm, digits 6/8, period 15–120 s, issuer are kept); a URL v4 does not
  accept is reported and the secret is imported without it;
- grants: users (mapped by e-mail), roles (through `-role-map`), the tenant
  subject (`all` → v4 tenant grant); relations 1:1; expiry and the original
  grant time and granter. Duplicate (resource, subject) rows keep the
  strongest relation. The importing operator is **not** made owner of
  anything.

Not migrated: **share links**, **audit logs**, folder descriptions (v4 has
none), the v3 `ARCHIVED` status (such secrets become ordinary secrets; they
are counted in the report), `DELETED` secrets (unless `-include-deleted`),
expired or deleted permission rows, grants of v3 users that have no v4
account (reported per e-mail), roles missing from `-role-map` (reported).
Authors without a v4 account are attributed to `-actor-email`.

`import-v3` is **not idempotent**: it refuses a v4 tenant that already has
secrets (`-allow-existing` overrides; folders with the same name are then
merged and their existing grants left alone).

## Prerequisites

- The v4 stack runs from `/srv/portal-v4` (compose project `freya-stack`) with
  a warden image that contains `export-v3`/`import-v3`.
- Your operator account exists in v4 auth (its e-mail is `-actor-email`), and
  every v3 user that should keep access has been invited to v4 with the same
  e-mail address.
- You know the v4 role that replaces each v3 role used in grants (see step 2).
- Work as root on the host (`sudo -i`); every file below is secret.

```sh
sudo -i
set -eu
umask 077
W=/root/warden-migration
install -d -m 0700 -o root -g root "$W"
IMG=$(docker inspect --format '{{.Config.Image}}' freya-stack-warden-1)
echo "$IMG"
T4=00000000-0000-0000-0000-000000000001        # v4 platform tenant
ACTOR=operator@example.org                        # your v4 e-mail
ROLEMAP='platform:admin=admin,1=admin'            # v3 role → v4 role (step 2)
```

## 1. v3 connection details

The v3 DSN is the `data.database.source` value of the portal's warden
configuration. Extract it into a root-only file and make sure no `${...}`
placeholder is left (replace them with the real values if there are):

```sh
sed -n 's/^[[:space:]]*source:[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}[[:space:]]*$/\1/p' \
  /srv/portal/configs/warden/data.yaml | head -1 > "$W/v3.dsn"
grep -c '\${' "$W/v3.dsn" || true      # must print 0
```

The host in the DSN must resolve on `portal_app-tier` (the compose service
name of `portal-postgres-1`, e.g. `postgres`). The AppRole credentials of
v3 warden are the files `role_id` and `secret_id` in the docker volume
`portal_vault-credentials`; the v3 Vault (`portal-vault-1`) is reached as
`http://vault:8200` on that network.

## 2. Inspect roles and counts in v3

```sh
docker exec portal-postgres-1 psql -U postgres -d gwa -c "
  SELECT subject_type, subject_id, count(*) FROM warden_permissions
  WHERE delete_time IS NULL AND subject_type <> 'SUBJECT_TYPE_USER' GROUP BY 1, 2 ORDER BY 1, 2;"
docker exec portal-postgres-1 psql -U postgres -d gwa -c "
  SELECT (SELECT count(*) FROM warden_folders WHERE delete_time IS NULL AND coalesce(tenant_id,0)=0) AS folders,
         (SELECT count(*) FROM warden_secrets WHERE delete_time IS NULL AND coalesce(tenant_id,0)=0
            AND status <> 'SECRET_STATUS_DELETED') AS secrets,
         (SELECT count(*) FROM warden_permissions WHERE delete_time IS NULL AND coalesce(tenant_id,0)=0
            AND (expires_at IS NULL OR expires_at > now())) AS permissions;"
```

Role subjects are role codes (`platform:admin`); a numeric id (`1`) is
resolved to its code by the export when `sys_roles` still has it, and the
role map accepts either form. Production uses `platform:admin` (and one row
with the numeric id `1`): `ROLEMAP='platform:admin=admin,1=admin'`.

## 3. Rehearsal (optional, v3 still live)

Run steps 5–7 once with v3 running and only `-dry-run`, read the report,
fix what it lists in v3 (folder names > 100 characters or containing `/`,
secret names > 200, metadata > 16 KiB, missing v4 users), then shred the
rehearsal bundle and key (step 10) before the real run.

## 4. Freeze v3

```sh
docker stop portal-warden-service-1
```

From here on nobody can change v3 secrets; the portal UI's warden pages stop
working. Nothing else in v3 is touched.

## 5. Export (v3 network)

```sh
docker run --rm --network portal_app-tier --user 0:0 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v portal_vault-credentials:/vault-credentials:ro \
  -v "$W":/migration \
  "$IMG" export-v3 \
    -dsn-file /migration/v3.dsn \
    -vault-addr http://vault:8200 -allow-plaintext -mount secret \
    -role-id-file /vault-credentials/role_id -secret-id-file /vault-credentials/secret_id \
    -tenant 0 \
    -out /migration/v3.bundle -key-out /migration/v3.key \
  | tee "$W/export-summary.json"
ls -l "$W"          # v3.bundle and v3.key: -rw------- root
```

The summary lists folders, secrets by status, versions and
`versions_missing`, `checksum_mismatches` (a password Vault returned whose
sha256 differs from `warden_secret_versions.checksum` — investigate before
importing), `authenticators`/`authenticators_missing`, grants and warnings.
The export fails as a whole on any database or Vault error.

## 6. v4 users

```sh
cd /srv/portal-v4
docker compose -p freya-stack exec -T timescaledb psql -U postgres -d auth -At \
  -c "\copy (SELECT lower(email), id FROM users WHERE tenant_id = '$T4') TO STDOUT CSV" \
  > "$W/users.csv"
wc -l "$W/users.csv"; grep -ci "^$ACTOR," "$W/users.csv"     # the actor must be listed
```

## 7. Dry run (v4 network)

```sh
cd /srv/portal-v4
docker compose -p freya-stack run --rm --no-deps -v "$W":/migration:ro warden import-v3 \
  -config deploy/container.yaml \
  -in /migration/v3.bundle -key-file /migration/v3.key -users /migration/users.csv \
  -tenant "$T4" -role-map "$ROLEMAP" -actor-email "$ACTOR" -dry-run \
  | tee "$W/dry-run.json"; echo "exit ${PIPESTATUS[0]}"
```

Nothing is written. The report has two parts:

- `mapping`: `unmapped_users` (e-mail → grants that would be skipped),
  `unmapped_roles`, `grants_without_email`, `authors_attributed_to_actor`,
  `archived_secrets`, `folder_descriptions_dropped`,
  `export_checksum_mismatches`, `export_warnings`;
- `import`: per entity `created` / `skipped` / `failed` (folders skipped =
  merged into a same-named folder; versions skipped = `material_missing`;
  grants skipped = duplicates, expired, on resources not imported),
  `authenticators`, `resources_without_owner`, `name_conflicts`,
  `validation_failures`, `warnings`.

Exit status 1 means validation failures; fix them (in v3, then re-export) or
accept the listed losses. If the target tenant already has secrets the
command stops with `target tenant already has secrets`.

## 8. Import

Optionally snapshot the v4 warden database first:
`docker compose -p freya-stack exec -T timescaledb pg_dump -U postgres -Fc warden > "$W/warden-before.dump"`.

```sh
cd /srv/portal-v4
docker compose -p freya-stack run --rm --no-deps -v "$W":/migration:ro warden import-v3 \
  -config deploy/container.yaml \
  -in /migration/v3.bundle -key-file /migration/v3.key -users /migration/users.csv \
  -tenant "$T4" -role-map "$ROLEMAP" -actor-email "$ACTOR" \
  | tee "$W/import.json"; echo "exit ${PIPESTATUS[0]}"
```

Each secret is written to Vault first, then its row and versions in one
transaction; a failure removes that secret's material again and is listed.
After each secret the stored current password is read back and its sha256
compared with the v3 checksum: `import.verified` should equal
`import.secrets.created` and `checksum_mismatches` should be empty. One
`migration_imported` audit event records the counts. The running v4 warden
does not need to be stopped.

## 9. Verify

```sh
cd /srv/portal-v4
docker compose -p freya-stack exec -T timescaledb psql -U postgres -d warden -c "
  SELECT (SELECT count(*) FROM folders WHERE tenant_id = '$T4') AS folders,
         (SELECT count(*) FROM secrets WHERE tenant_id = '$T4' AND deleted_at IS NULL) AS secrets,
         (SELECT count(*) FROM secrets WHERE tenant_id = '$T4' AND has_totp) AS totp,
         (SELECT count(*) FROM secret_versions WHERE tenant_id = '$T4' AND source = 'migration-v3') AS versions,
         (SELECT count(*) FROM secret_versions WHERE tenant_id = '$T4' AND material_missing) AS versions_missing;"
docker compose -p freya-stack exec -T timescaledb psql -U postgres -d warden -c "
  SELECT subject_type, relation, count(*) FROM grants WHERE tenant_id = '$T4' GROUP BY 1, 2 ORDER BY 1, 2;"
docker compose -p freya-stack exec -T timescaledb psql -U postgres -d warden -c "
  SELECT min(created_at), max(updated_at) FROM secrets WHERE tenant_id = '$T4';"
docker compose -p freya-stack exec -T timescaledb psql -U postgres -d warden -c "
  SELECT ts, actor_id, outcome, details FROM warden_audit_events WHERE event_type = 'migration_imported';"
```

Compare with the export summary (step 5) and the v3 counts (step 2). Then
sign in to the v4 console as two or three different users and check a few
secrets: folder placement, reveal of the current password and of an older
version, a TOTP code against the v3 authenticator, and the sharing tab.

## 10. Destroy the bundle and the key

The bundle is useless without the key; shred the key first.

```sh
shred -u "$W/v3.key" "$W/v3.bundle" "$W/v3.dsn" "$W/users.csv"
rm -f "$W"/*.json "$W/warden-before.dump"      # after you no longer need them
rmdir "$W"
```

(`shred` gives no guarantee on journaling or copy-on-write file systems;
destroying the key is what protects the bundle.)

Keep v3 frozen; decommission it on the normal schedule once v4 is accepted.

## Rollback

v3 is never written to: the export uses a read-only transaction and read
calls on Vault. To go back, restart it:

```sh
docker start portal-warden-service-1
```

To undo a v4 import (the target tenant was empty before), restore the dump
taken in step 8, or delete the imported rows and their material:

```sh
cd /srv/portal-v4
docker compose -p freya-stack exec -T timescaledb psql -U postgres -d warden -At \
  -c "SELECT id FROM secrets WHERE tenant_id = '$T4'" > "$W/imported-ids"
# with a v4 Vault token allowed to delete under the warden mount, for each id:
#   vault kv metadata delete -mount=warden "$T4/secrets/<id>"
#   vault kv metadata delete -mount=warden "$T4/secrets/<id>/totp"
docker compose -p freya-stack exec -T timescaledb psql -U postgres -d warden -c "
  BEGIN;
  DELETE FROM grants  WHERE tenant_id = '$T4';
  DELETE FROM secrets WHERE tenant_id = '$T4';
  DELETE FROM folders WHERE tenant_id = '$T4';
  COMMIT;"
```

Then fix the cause and repeat from step 5 with a new bundle (the export
refuses to overwrite existing files).
