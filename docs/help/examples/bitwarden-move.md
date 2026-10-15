---
title: "Example: move a team from Bitwarden"
summary: Import a team's Bitwarden export into its own folder, check it before anything is written, then give the team's role access to the folder.
kind: example
order: 50
tags: [warden, example, bitwarden, import, folders, grants]
requires: transfer:import
---
**Goal.** The operations team keeps its credentials in Bitwarden. They should
move into warden, into a folder `Operations`, and everyone with the
platform role *Operations* should be able to read and change them.

**You need** the *Warden administrator* role (it carries `transfer:import`
and `permissions:manage`).

## 1. Export from Bitwarden

In Bitwarden, export the vault as **JSON**, **without** a password
(unencrypted). Warden refuses encrypted exports and files larger than
16 MiB.

The file contains every password in clear text: keep it on your machine
only for the duration of the move.

## 2. Create the target folder

On **Warden → Secrets**, select **Root**, click **New folder** and create
`Operations`. Keep it selected.

## 3. Validate the export

1. Open **More actions → Import from Bitwarden**.
2. Pick the file under **Export file**. **Import into** is already set to
   the `Operations` folder.
3. Click **Validate**.

Nothing is written yet. The summary shows the number of **Folders** and
**Logins** found, the **Name collisions** with secrets already in the target,
and the **Problems** (items that will not import, with the reason, such as
`missing password`). Warnings list what is imported only in part, for
example a card or note (only logins are imported) or a one-time code seed
warden does not recognise.

## 4. Import

Under **When a name already exists in the folder**, choose:

| Choice | Effect on a name that already exists (case-insensitive) |
|---|---|
| Skip | the existing secret is kept; the item is not imported |
| Rename | the item is imported as `name (2)`, `name (3)`, ... |
| Overwrite (new version) | the existing secret gets the item's details and its password as a new version |

Click **Import**. The result reads, for example, *41 created, 2 renamed,
0 skipped, 0 overwritten, 0 failed*.

How Bitwarden fields land in warden:

| Bitwarden | Warden |
|---|---|
| folder | a folder inside `Operations`, created if needed |
| name | name |
| login username | username |
| login password | password |
| password history | older versions, oldest first |
| first login URI | host URL |
| notes | description |
| custom fields, favourite | metadata |
| TOTP | one-time code seed |

## 5. Give the team access

1. Open **Warden → Permissions** and pick `Operations`.
2. Click **Manage folder access**.
3. Choose the role *Operations* under **User or role**, **Permission**
   `editor`, and click **Grant**.

Everyone with that role can now read and change every secret in
`Operations` and its subfolders. To let them share by email too, grant
`owner` instead, or `sharer` for read-and-share only.

The grant decides which secrets they reach; to open warden at all, members
also need a warden role such as *Warden editor* (assigned in the auth
console).

## 6. Clean up

Delete the export file. The import is recorded in the audit trail as
`transfer_imported` with its counts.
