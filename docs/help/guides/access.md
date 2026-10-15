---
title: Give access to folders and secrets
summary: Organise secrets in folders and grant users, roles or the whole tenant owner, editor, viewer or sharer access, with optional expiry.
kind: guide
order: 30
tags: [warden, folders, grants, access, permissions]
requires: permissions:manage
---
Every folder and secret has its own access list. A **grant** gives one
subject one level of access:

| Level | Read | Change | Delete | Share and grant |
|---|:-:|:-:|:-:|:-:|
| `owner` | yes | yes | yes | yes |
| `editor` | yes | yes | no | no |
| `viewer` | yes | no | no | no |
| `sharer` | yes | no | no | yes |

The subject is a **user**, a **role** (everyone holding that role, also
through groups) or **everyone in the tenant**. A grant can expire at a date
you choose.

## How access adds up

- A grant on a folder applies to every subfolder and secret inside it, at
  any depth.
- When several grants apply (on the secret, on its folders, to you, to your
  roles, to the tenant), the strongest wins.
- Whoever creates a folder or a secret becomes its `owner`.
- A revoked or expired grant stops working at once.

Grants work on top of your role. *Warden viewer* can only read, whatever
grants say; *Warden editor* can change, share and grant, but only where a
grant allows it.

## Organise folders

On **Warden → Secrets**, the buttons in the header of the folder pane act on
the selected folder:

- **New folder**: needs write access to the selected folder (anyone with
  folder management may create at **Root**).
- **Rename** and **Move**: need write access. A folder cannot move into
  itself or one of its own subfolders.
- **Delete**: needs `owner` access. A folder that still holds folders or
  secrets is only deleted when you tick **Also delete every subfolder and
  secret inside**; their passwords are destroyed in the vault.

Two folders with the same parent cannot have the same name.

## Grant access

1. Open **Warden → Permissions**.
2. Pick a folder in **Pick a resource**. The table lists its secrets with
   **Your permissions** on each.
3. Click **Manage folder access** for the folder, or **Manage** on a secret's
   row. (From a secret's view on the Secrets page, **Share access** opens the
   same drawer.)
4. The drawer lists the current grants, including those inherited from
   parent folders. Choose a **User or role** (or everyone in the tenant), a
   **Permission** and, optionally, **Expires (optional)**, then click
   **Grant**.

You can grant only where you have `owner` or `sharer` access, and never a
level above your own: a `sharer` can grant `viewer` or `sharer`, not
`editor`. Without share access the drawer says *You need the share
permission to grant access here.*

## Revoke access

Open the same drawer and click **Revoke** on the grant. Revoking a grant
inherited from a parent folder needs share access on that folder.

Every grant, revocation and refused attempt is recorded in the audit trail.
