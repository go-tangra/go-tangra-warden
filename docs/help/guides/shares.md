---
title: Share a password by email
summary: Mail a one-time link that reveals a secret's password to someone without an account, limited in time, in reveals and optionally to a network; follow and cancel your links.
kind: guide
order: 40
tags: [warden, shares, email, links]
requires: secrets:share
---
A share sends a link to an email address. Whoever opens it can reveal the
secret's current password a limited number of times, until the link
expires. The recipient does not need a platform account.

You need `owner` or `sharer` access to the secret, and a role with
`secrets:share` (*Warden editor* or *Warden administrator*).

## Send a link

1. Open the secret on **Warden → Secrets**.
2. Under **Shared links**, click **Share by email**.
3. Fill in:
   - **Recipient email** (required).
   - **Message (optional)**: shown to the recipient with the password.
   - **Valid for**: 1 hour, 1 day or 7 days.
   - **Reveals allowed**: 1 to 10.
   - **Allowed network (CIDR, optional)**, for example `203.0.113.0/24`:
     the link only works from addresses in that network.
4. Click **Send link**.

The link is mailed by the platform's notification module and is never shown
to you, so nobody else can copy it from the portal. If the mail cannot be
sent, no share is created and you get an error; try again later.

## What the recipient sees

The mail carries the link, the secret's name, the expiry, the number of
reveals and your message (its wording is the `warden.share` template in the
notification module). The link opens a **Shared credential** page with
a **Reveal** button. Revealing shows the name, username, host, password and
the reveals left. Each reveal uses one from the budget.

If the link was cancelled, has expired, has no reveals left or is opened
from outside the allowed network, the page only says *This link is not valid
any more.*

## Follow and cancel your links

**Shared links** in the secret's view lists the links you created for that
secret, newest first:

| Column | Meaning |
|---|---|
| Recipient | the email address |
| State | `active`, `consumed` (no reveals left), `expired` or `cancelled` |
| Reveals | used / allowed |
| Until | the expiry, and the allowed network if any |
| Created | when you sent it |

Click **Cancel** on an `active` link to stop it at once.

Creating, opening, cancelling and refusing a link are all recorded in the
audit trail.
