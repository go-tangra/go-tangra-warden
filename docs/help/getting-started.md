---
title: Get started
summary: Create a folder, save your first secret in it and reveal its password.
kind: guide
order: 10
tags: [warden, getting-started, secrets, folders]
requires: secrets:write
---
This walk-through creates a folder, saves a secret in it and reveals the
password. You need the *Warden editor* or *Warden administrator* role (or a
role with `secrets:write` and `folders:manage`).

## 1. Create a folder

1. Open **Warden → Secrets**. The left pane shows the folder tree under
   **Root**.
2. With **Root** selected, click the **New folder** button (folder with a
   plus) in the pane's header.
3. Enter a name, for example `Network`, and click **Create**. Folder names
   cannot contain `/`.

The new folder is selected. You are its owner.

## 2. Save a secret

1. Click **New secret**.
2. Fill in the form:
   - **Name**: `core-switch admin` (required).
   - **Username**: `admin`.
   - **Password**: required. Use [the generator](guides/secrets.md#generate-a-password)
     if you need a new one.
   - **Host URL**: `https://core-switch.example.com`.
   - **Folder** is already set to `Network`.
   - **Description**, **Metadata (JSON)** and **TOTP seed** are optional.
3. Click **Create**.

The drawer closes onto the secret's view. The secret appears in the folder
with version 1.

## 3. Reveal the password

In the secret's view, click the eye icon next to **Password** to show it, or
the copy icon to copy it without showing it. Both are recorded in the audit
trail. The value is dropped when you close the drawer.

## Next steps

- [Give a colleague or a role access to the folder](guides/access.md)
- [Change the password, restore a version, add a one-time code](guides/secrets.md)
