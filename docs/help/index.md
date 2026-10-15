---
title: Warden
summary: The team password vault. Keep passwords and one-time codes in folders, decide who can read, edit or share each one, and send a password to someone outside the platform with a one-time link.
kind: guide
order: 0
tags: [warden, secrets, passwords, overview]
---
Warden is the platform's password vault. A **secret** holds a name, a
username, a password, a host URL, a description, optional custom fields and
an optional one-time code (TOTP). Secrets live in a tree of **folders**.

Passwords and one-time code seeds are stored only in HashiCorp Vault. The
database keeps the rest (names, usernames, hosts, versions), so search and
lists never touch a password. Every reveal, change and share is recorded in
the audit trail.

## Concepts

- **Secret**: one credential. Changing its password creates a new
  **version**; older versions stay readable and can be restored.
- **Folder**: a container for secrets and other folders, as deep as you
  need. Access granted on a folder applies to everything inside it.
- **Grant**: access to one folder or secret for a user, a role or the whole
  tenant, as `owner`, `editor`, `viewer` or `sharer`, optionally until a date.
  Whoever creates a folder or a secret becomes its owner.
- **Share**: a link mailed to an email address that reveals the current
  password a limited number of times, for a limited time. The recipient does
  not need an account.

Two layers decide what you can do. Your **role** (for example *Warden
editor*) opens parts of the module, such as creating secrets or managing
folders. **Grants** then decide which folders and secrets you can actually
read, change, delete or share. See [access and grants](guides/access.md).

## Pages in the portal

| Page | Shows | Needs |
|---|---|---|
| Secrets | the folder tree, the secrets in the selected folder, search; statistics and the audit trail for auditors | `secrets:read` |
| Permissions | every folder and secret with your permissions on it; grant and revoke access | `permissions:manage` |
| Generator | a password generator | `secrets:read` |

## Where to go next

- [Get started](getting-started.md): create a folder and your first secret.
- [Work with secrets](guides/secrets.md): reveal, copy, versions, one-time codes, the generator.
- [Give access to folders and secrets](guides/access.md)
- [Share a password by email](guides/shares.md)
- [Example: move a team from Bitwarden](examples/bitwarden-move.md)
- [Reference](reference.md): fields, relations, states, limits, permissions and roles.
