---
title: Reference
summary: Secret, version, folder and share fields and limits, access levels, permissions and roles, export and backup, statistics and audit events.
kind: reference
order: 60
tags: [warden, reference, limits, permissions, roles, audit]
---
## Secret fields

| Field | Limit | Notes |
|---|---|---|
| Name | 1–200 characters | required |
| Username | 200 | |
| Password | 1–4096 | required on create; stored only in the vault |
| Host URL | 2048 | shown as a link when it starts with `http://` or `https://` |
| Description | 2000 | |
| Metadata | JSON object, 16 KiB | custom fields; never searched |
| TOTP seed | `otpauth://totp/...` URI or base32 | stored only in the vault; never shown again |
| Folder | | empty means **Root** |
| Version | | the current password version, starting at 1 |

Search terms are at most 200 characters and match name, username, host,
description and folder path.

## Versions

Every password change, restore or overwriting import adds a version. A
version has its number, a comment (up to 500 characters) or its source, its
creation time, and **material missing** when the vault holds no password for
it. Versions are never edited or removed, except when the whole secret is
deleted.

## Folders

Names are 1–100 characters without `/`, unique among siblings
(case-insensitive). The tree may be as deep as needed.

## Access levels

| Level | Read | Change | Delete | Share and grant |
|---|:-:|:-:|:-:|:-:|
| `owner` | yes | yes | yes | yes |
| `editor` | yes | yes | no | no |
| `viewer` | yes | no | no | no |
| `sharer` | yes | no | no | yes |

Grants go to a user, a role or the tenant, on a folder (inherited by
everything inside) or a secret, optionally with an expiry. You may grant at
most your own strongest level. Details: [access and grants](guides/access.md).

## Shares

| Setting | Values |
|---|---|
| Validity | 1 hour, 1 day or 7 days in the portal (API: 5 minutes to 7 days) |
| Reveals allowed | 1–10 |
| Allowed network | optional CIDR, for example `203.0.113.0/24` |
| Message | optional, up to 1000 characters |

States: `active`, `consumed` (no reveals left), `expired`, `cancelled`.
Opening a link is rate-limited per client address and per link.

## Permissions and roles

Your role opens the API; grants then decide which folders and secrets you
reach.

| Permission | Allows |
|---|---|
| `secrets:read` | browse, search, reveal, one-time codes, versions, generator |
| `secrets:write` | create secrets, change details and passwords, restore, set or remove TOTP |
| `secrets:delete` | delete secrets you own |
| `secrets:share` | send and cancel email shares |
| `folders:manage` | create, rename, move and delete folders |
| `permissions:manage` | list, grant and revoke access; the Permissions page |
| `transfer:import` | import Bitwarden exports |
| `transfer:export` | export to Bitwarden format, with passwords |
| `backup:manage` | export and import tenant backups |
| `stats:read` | statistics, the audit trail and the health route |

| Role | Permissions |
|---|---|
| Warden administrator | all ten |
| Warden editor | `secrets:read`, `secrets:write`, `secrets:share`, `folders:manage`, `permissions:manage` |
| Warden viewer | `secrets:read` |

The platform's built-in roles get: owner and admin, all ten; member, the same
as Warden editor; auditor and operator, `stats:read`.

## Export and backup

From **More actions** on the Secrets page:

| Action | Needs | Contains |
|---|---|---|
| Export to Bitwarden | `transfer:export` | the secrets you can read in the selected folder and below (or everywhere at **Root**), with their passwords |
| Backup (no material) | `backup:manage` | the whole tenant: folders, secrets, versions and grants, without passwords or seeds |
| Backup with material | `backup:manage` | the same, with every password version and seed |

Exports with passwords are recorded as bulk disclosures. Treat the files as
secrets. Imports of Bitwarden files and their size limit (16 MiB) are covered
in [the Bitwarden example](examples/bitwarden-move.md).

## Statistics and audit trail

With `stats:read`, the Secrets page shows the number of secrets, secrets with
a one-time code, folders, versions, operations in the last 24 hours, and the
grants and shares by kind. **Show audit trail** lists events newest first,
filtered by **Event type**, **Actor** (user ID), **From** and **To**. Without
a start date it shows the last 7 days; a range covers at most 90 days.

Event types: `secret_created`, `secret_read`, `secret_password_read`,
`secret_updated`, `secret_password_updated`, `secret_version_read`,
`secret_restored`, `secret_moved`, `secret_deleted`, `secret_totp_read`,
`secret_totp_set`, `secret_totp_removed`, `folder_created`,
`folder_updated`, `folder_moved`, `folder_deleted`, `grant_created`,
`grant_revoked`, `access_refused`, `transfer_validated`,
`transfer_imported`, `transfer_exported`, `backup_exported`,
`backup_imported`, `share_created`, `share_opened`, `share_cancelled`,
`share_refused`, `vault_unavailable`, `migration_imported`.

Audit details never contain passwords, seeds or share links.
