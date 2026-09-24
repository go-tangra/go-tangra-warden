# Feature Specification: Warden Secret Manager

**Feature Branch**: `005-warden-secrets`

**Created**: 2026-09-16

**Status**: Draft

**Input**: User description: "Create a new service under services/ named warden (like services/auth and services/gateway; it will later move to its own repository), replicating the functionality of /home/jadmin/projects/go-tangra/go-tangra-warden as a Freya platform module: a tenant-scoped secret and credential manager. Secrets (name, username, password, host URL, description, free-form metadata, optional TOTP seed) are organised in a hierarchical folder tree of unlimited depth; passwords and TOTP seeds are stored in HashiCorp Vault (KV v2, per-tenant path, AppRole authentication), never in the database, and every password change creates a version with a comment and checksum that can be listed, inspected and restored. Access is Zanzibar-style: Owner (read, write, delete, share), Editor (read, write), Viewer (read), Sharer (read, share) granted on secrets or folders to users, roles or the whole tenant, with optional expiry, inherited down the folder hierarchy; the API offers grant, revoke, list, check, list-accessible-resources and effective-permissions. Also: full-text search over secrets, move secrets and folders, folder tree retrieval, TOTP code generation for a secret, a password generator, Bitwarden JSON import (validate first; duplicate handling skip/rename/overwrite) and export, tenant backup export/import, statistics (total/active secrets, folders, permissions), system health including Vault reachability, and sharing a secret with an external recipient by email through a time-limited link with policies. Creator/updater tracking and an audit trail on every operation. It registers with the application gateway (routes, API permissions such as secrets:read/write/delete/share, folders:manage, permissions:manage, transfer:import/export, plus CASL abilities) and ships its UI as a Module Federation remote (secrets list with drawer editor and version history, folder tree, permissions manager, password generator, Bitwarden import dialog) composed by the platform shell; user identity, tenant, roles and groups come from the auth service."

## Overview

Warden is the platform's credential vault: a place where the people of a tenant
keep passwords, logins and one-time-code seeds for the systems they operate,
organised in folders, shared with exactly the colleagues who need them, and
never visible to anyone else, including platform operators and the service's
own database. It is a platform module like every other: it registers with the
application gateway (feature 003), takes who-you-are, your tenant, your roles
and your groups from the authentication service (features 002 and 004), and
shows its screens inside the platform shell.

Five kinds of people use it: **members** who store and use credentials,
**folder owners** who organise and share them, **tenant administrators** who
grant access broadly, import and export, and take backups, **platform
operators** who watch health and statistics without ever reading a secret, and
**external recipients** who receive a single secret through a time-limited
link.

The secret *material* (passwords, one-time-code seeds) lives in a dedicated
secrets vault, one compartment per tenant; the service's own records hold only
names, locations, owners and history metadata. Every change to a password is a
new version that can be inspected and restored. Every operation is audited.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Keep Credentials in Folders (Priority: P1)

A member creates a secret with a name, username, password, host address,
description and any extra fields, places it in a folder (folders nest to any
depth), finds it again by browsing the tree or searching, reveals the password
when needed, edits it, moves it between folders, and deletes it. Every password
change is kept as a version with a comment; the member can see the version
history, look at an old version, and restore it.

**Why this priority**: Storing and retrieving credentials safely is the whole
point; without it nothing else matters.

**Independent Test**: Create a folder tree "Infra / Databases", create a secret
in it, search for it by name, reveal the password, change the password twice
with comments, list three versions, restore the first, move the secret to
"Infra", delete it. The password is never visible in the service's own records,
listings or logs.

**Acceptance Scenarios**:

1. **Given** a signed-in member of tenant "acme", **When** they create a secret
   "prod-db" with username, password, host, description and metadata in folder
   "Infra/Databases", **Then** the secret appears in that folder with version 1,
   the creator is recorded, and the creation is audited.
2. **Given** a secret they may read, **When** they open it, **Then** they see
   every field except the password; **When** they reveal the password, **Then**
   it is returned to them alone and the reveal is audited.
3. **Given** a secret they may write, **When** they change the password with a
   comment, **Then** version 2 exists with that comment, a checksum and the
   author; the previous version stays retrievable.
4. **Given** three versions, **When** they restore version 1, **Then** a new
   version 4 is created with version 1's password (history is append-only) and
   the restore is audited.
5. **Given** folders "Infra" and "Infra/Databases", **When** they move the
   secret to "Infra" or move "Databases" under "Legacy", **Then** the folder
   path shown for the secret follows, and inherited access follows the new
   location.
6. **Given** secrets named "prod-db", "staging-db" and "mail relay", **When**
   they search "db", **Then** the two database secrets are returned, only among
   the secrets they may read.
7. **Given** a secret with a one-time-code seed, **When** they ask for the
   current code, **Then** they receive a six-digit code valid for the current
   window; the seed itself is never returned.
8. **Given** a deleted secret, **When** anyone asks for it, its password or its
   versions, **Then** it is not found.

---

### User Story 2 - Share Precisely (Priority: P1)

A folder owner grants access to a colleague, a role or the whole tenant on a
folder or a single secret as Owner, Editor, Viewer or Sharer, optionally until a
date; access granted on a folder applies to everything inside it, at any depth.
Owners and Sharers can share; Editors can change; Viewers can only read.
Anyone can see what they have access to and why; administrators can see who
has access to what and revoke it.

**Why this priority**: A credential store without precise, auditable sharing is
a liability, not a tool.

**Independent Test**: Grant Viewer on folder "Infra" to role "ops" until
tomorrow; a member holding "ops" can read a secret three folders deep but not
change it; an Editor on the secret itself can change it but not share it; after
the expiry the "ops" member is refused; the effective-permissions view explains
each outcome.

**Acceptance Scenarios**:

1. **Given** an Owner of folder "Infra", **When** they grant Editor on it to
   user Dana, **Then** Dana can read and write every secret under "Infra" at
   any depth, cannot delete or share them, and the grant is audited.
2. **Given** a Viewer grant to role "ops" on a folder, **When** a member holding
   "ops" (directly or through a group) opens a secret inside, **Then** they can
   read but not write, delete or share it.
3. **Given** a grant to the whole tenant, **When** any member of the tenant
   asks, **Then** they hold that relation; members of other tenants never do.
4. **Given** a grant with an expiry, **When** the expiry passes, **Then** the
   access stops without any further action and the grant is shown as expired.
5. **Given** a member with no grant on a secret or any ancestor folder,
   **When** they try to read it, **Then** they are refused and the refusal is
   audited.
6. **Given** a member, **When** they ask which resources they can access,
   **Then** they receive every folder and secret they hold any relation on,
   with the strongest relation and its source (direct, via folder, via role,
   via tenant).
7. **Given** a Sharer (not Owner) on a secret, **When** they try to grant
   Owner, **Then** they are refused: nobody grants more than they hold.
8. **Given** an Owner, **When** they revoke a grant, **Then** the subject loses
   the access on their next request and the revocation is audited.

---

### User Story 3 - Move Credentials In and Out (Priority: P2)

A tenant administrator brings an existing password collection into Warden by
importing a Bitwarden export: they validate the file first (item and folder
counts, problems, duplicates), choose how duplicates are treated (skip, rename,
overwrite), then import into a chosen folder. They can also export the
tenant's secrets they may read to the Bitwarden format, and take a full tenant
backup (with or without secret material) that can be imported back, for
example into a new tenant.

**Why this priority**: Adoption depends on painless migration; recovery
depends on backups. Both build on stories 1 and 2.

**Independent Test**: Validate a Bitwarden file with 20 items and 3 folders,
two of which collide with existing names; import with "rename"; the tree shows
the folders and 20 secrets, two renamed; export to Bitwarden and re-validate
the result; take a backup including secrets, import it into an empty tenant,
and find identical folders, secrets and versions.

**Acceptance Scenarios**:

1. **Given** an administrator with a Bitwarden export, **When** they validate
   it, **Then** they see the number of items and folders, the items that
   collide with existing secrets, and every unreadable entry, and nothing is
   changed.
2. **Given** duplicate handling "skip" / "rename" / "overwrite", **When** they
   import, **Then** colliding items are respectively left untouched, imported
   as "name (1)", or replaced (creating a new version of the existing secret);
   the result reports counts per outcome and every skipped or failed item.
3. **Given** an import file whose password history is present, **When** it is
   imported, **Then** the history becomes earlier versions of the secret.
4. **Given** an administrator, **When** they export to Bitwarden, **Then** the
   file contains folders and the secrets they may read, with passwords, and
   the export is audited as a bulk disclosure.
5. **Given** an administrator, **When** they take a backup without secret
   material, **Then** the archive holds folders, secrets' metadata, versions'
   metadata and permissions but no passwords or seeds; with secret material,
   passwords and seeds are included and the backup is audited as a bulk
   disclosure.
6. **Given** a backup, **When** it is imported into a tenant, **Then** folders,
   secrets, versions and permissions are recreated, identifiers are remapped,
   and the result lists counts and warnings per entity type.

---

### User Story 4 - Operate and Observe (Priority: P2)

A platform operator checks that Warden is healthy and can reach the secrets
vault, and sees tenant statistics: secrets, folders, grants, recent activity.
A tenant administrator sees the same statistics for their own tenant and
reviews the audit trail: who created, read, changed, shared, exported or
deleted what, and when. A member uses the built-in password generator to
create strong passwords with chosen length and character classes.

**Why this priority**: Needed for running the service and for compliance, but
the store works without it.

**Independent Test**: Stop the secrets vault; health reports it unreachable
and secret creation is refused with a clear temporary error while listings
still work; restart it; health recovers. Statistics match the counts in the
tree. The audit view shows the day's operations with actor and outcome.

**Acceptance Scenarios**:

1. **Given** the secrets vault is unreachable, **When** health is checked,
   **Then** it reports the vault as unavailable; **When** a member reveals or
   changes a password, **Then** they get a temporary-unavailability answer and
   nothing is lost or half-written.
2. **Given** an operator, **When** they ask for statistics, **Then** they see
   totals of secrets, folders and grants per tenant and never any secret
   content or name.
3. **Given** an administrator, **When** they open the audit trail, **Then**
   every operation of their tenant is listed with actor, subject, outcome and
   time, filterable by type, actor and period.
4. **Given** a member, **When** they generate a password of length 24 with
   symbols, **Then** they receive one that meets the request and can copy it
   into a secret.

---

### User Story 5 - Hand a Secret to an Outsider (Priority: P3)

A member who may share a secret sends it to someone outside the platform: they
enter the recipient's email, an optional message and policies (how long the
link lives, how many times it may be opened, from which network or region).
The recipient receives a link, opens it while the policies allow, sees the
secret once, and the disclosure is audited. The sender can see and cancel
outstanding shares.

**Why this priority**: Useful and requested, but a convenience on top of the
core store.

**Independent Test**: Share a secret with a 1-hour, single-use link; the
recipient opens it once and sees the password; a second open is refused; after
one hour a fresh link is refused; the sender's share list shows the share as
consumed, and the audit trail records creation and disclosure.

**Acceptance Scenarios**:

1. **Given** a Sharer on a secret, **When** they create a share for an email
   with a validity of one hour and a single use, **Then** the recipient gets a
   message with a link and the share is audited with the recipient address.
2. **Given** the link, **When** the recipient opens it within the policy,
   **Then** they see the secret's name, username, host and password once and
   the disclosure is audited; **When** they open it again, **Then** they are
   refused.
3. **Given** an expired or cancelled share, **When** the link is opened,
   **Then** it is refused without revealing whether the secret exists.
4. **Given** a Viewer (not Sharer/Owner) on a secret, **When** they try to
   create a share, **Then** they are refused.

---

### Edge Cases

- A folder is deleted while it still contains secrets or subfolders: refused
  unless the caller asks to delete recursively; recursive deletion removes
  everything beneath and audits each secret.
- A folder is moved under one of its own descendants: refused.
- Two secrets with the same name in one folder: allowed (names are labels, not
  keys); search and Bitwarden duplicate handling compare within the same
  folder.
- A grant is given twice to the same subject on the same resource: the later
  one replaces the earlier (relation and expiry updated), one grant remains.
- The subject of a grant is deactivated or leaves the tenant: the grant stays
  but has no effect (identity comes from the authentication service on every
  check).
- The secrets vault accepts a write but the service's record cannot be saved:
  the write is rolled back or marked orphaned and cleaned up; the caller gets a
  temporary error and no dangling version is shown.
- Very large tenants (100k secrets): listings are paged; the tree is fetched
  per level or as a whole for up to 10k folders.
- A Bitwarden import file over the size limit or malformed: refused at
  validation with the reason; nothing is imported.
- Metadata contains something that looks like a password: stored as given (it
  is the user's data) but never indexed for search and never logged.
- A one-time-code seed that is not a valid seed: refused at input.
- Two members restore different versions concurrently: both restores create
  versions in order; the last one wins as current, both are audited.

## Requirements *(mandatory)*

### Functional Requirements

**Secrets and folders**

- **FR-001**: Members MUST be able to create, read, update, move and delete
  secrets with name (1–200 characters), username (≤ 200), password (≤ 4096),
  host URL (≤ 2048), description (≤ 2000), free-form metadata (≤ 16 KiB) and an
  optional one-time-code seed, within a folder or at the tenant root.
- **FR-002**: Passwords and one-time-code seeds MUST be stored only in the
  secrets vault, in a compartment per tenant; the service's own records MUST
  hold no secret material, including in search indexes, version records,
  backups without secret material, and audit events.
- **FR-003**: Every password change (create, update, restore, import,
  overwrite) MUST create a new version with a monotonically increasing number,
  optional comment, author, time and a checksum of the password; versions are
  append-only; the current version is the highest.
- **FR-004**: Members MUST be able to list versions (metadata only), read one
  version's password (audited), and restore a version (which creates a new
  current version).
- **FR-005**: Folders MUST form a tree of unlimited depth under a tenant root;
  names are 1–100 characters and unique among siblings; folders can be
  created, renamed, moved (never under themselves) and deleted (recursively
  only on request); the tree can be fetched whole or per level.
- **FR-006**: Members MUST be able to search secrets by name, username, host,
  description and folder path; results MUST contain only secrets the caller may
  read and never passwords or seeds.
- **FR-007**: Members MUST be able to obtain the current one-time code of a
  secret holding a seed (read access), set or replace the seed (write access)
  and remove it; the seed is never returned.
- **FR-008**: A password generator MUST produce passwords of a chosen length
  (8–128) and character classes (lower, upper, digits, symbols) with at least
  one of each chosen class, using cryptographically strong randomness; it is
  stateless and audited as nothing.

**Access control**

- **FR-009**: Access MUST be expressed as grants of one relation (Owner:
  read, write, delete, share; Editor: read, write; Viewer: read; Sharer: read,
  share) on one resource (folder or secret) to one subject (user, role, or the
  whole tenant), with an optional expiry.
- **FR-010**: A grant on a folder MUST apply to every folder and secret
  beneath it at any depth; a subject's permission on a resource is the union
  of every unexpired grant on the resource and its ancestors held directly,
  through any of the subject's roles (including roles held through groups),
  or through the tenant.
- **FR-011**: The creator of a secret or folder MUST become its Owner.
- **FR-012**: Only holders of `share` on a resource MAY grant or revoke on it,
  and MUST NOT grant a relation stronger than their own.
- **FR-013**: The service MUST answer permission checks, list the grants on a
  resource, list the resources a subject may access with the strongest
  relation and its source, and explain a subject's effective permissions on a
  resource.
- **FR-014**: Every read of secret material, every write, delete, move, grant,
  revoke, import, export, backup, share and disclosure MUST be audited with
  actor, subject, outcome and time; refusals MUST be audited too.

**Transfer**

- **FR-015**: Administrators MUST be able to validate a Bitwarden export
  (counts, collisions, problems) without changes, then import it into a chosen
  folder with duplicate handling skip, rename or overwrite; password history
  becomes versions; the result reports counts and per-item failures.
- **FR-016**: Administrators MUST be able to export the secrets they may read
  to the Bitwarden format; bulk disclosures (export, backup with material) MUST
  be audited as such.
- **FR-017**: Administrators MUST be able to export a tenant backup with or
  without secret material and import one into a tenant with identifier
  remapping and a per-entity report.

**Platform integration**

- **FR-018**: Warden MUST register with the application gateway as a module
  with its routes and API permissions (`secrets:read`, `secrets:write`,
  `secrets:delete`, `secrets:share`, `folders:manage`, `permissions:manage`,
  `transfer:import`, `transfer:export`, `backup:manage`, `stats:read`) and
  matching UI abilities, and its UI as a federated remote with navigation
  entries; identity, tenant, roles and groups come from the platform.
- **FR-019**: API permissions gate entry to an operation; the Zanzibar grants
  decide which resources the operation may touch. Both must allow.
- **FR-020**: Operators MUST be able to check health (service, database,
  secrets vault reachability) and read per-tenant statistics; administrators
  see their own tenant's statistics and audit trail.

**Sharing**

- **FR-021**: Holders of `share` on a secret MUST be able to create a share
  for an external email with a message and policies (validity 5 minutes to 7
  days, maximum opens 1–10, optional network/region restriction); the
  recipient receives a link; opening it within policy discloses name, username,
  host and password once per open and is audited; outside policy it is refused
  uniformly. Senders can list and cancel their shares.

### Security Requirements *(mandatory — Constitution: Development Workflow)*

- **Trust boundaries crossed**: public ingress through the gateway (browser,
  external share recipients, import files); service-to-service channel
  (auth service for identity and decisions, gateway registration); the
  secrets vault (out-of-process store of the material); database.
- **Data classification**: secret material (passwords, seeds, share links):
  highest; credential metadata (names, usernames, hosts, descriptions,
  metadata): confidential; grants and audit: access-control data.
- **Authentication/Authorization**: every request carries a platform identity
  (session through the gateway or bearer token) verified with the auth
  service; API permissions from the gateway manifest gate operations; Zanzibar
  grants gate resources; the vault is reached only with the service's own
  role credential, scoped to a mount the service owns; share links are
  unguessable capabilities bound to their policies.
- **Threat scenarios**: reading another tenant's secrets by id; escalation by
  granting more than held; leaking material through search, listings, logs,
  audit, backups or error bodies; vault credential theft; share link
  guessing or replay; malicious import files (size, depth, injection into
  names/URLs); TOTP seed disclosure; stale access after revocation or
  expiry; export as an exfiltration channel.
- **SR-001**: Secret material MUST never be written to the database, logs,
  audit details, search indexes, metrics, error bodies or backups taken
  without material; automated scans MUST prove it.
- **SR-002**: Every resource access MUST be checked against the caller's
  tenant first and answered `not_found` for other tenants; vault paths MUST be
  derived from the verified tenant, never from input.
- **SR-003**: Grants MUST be bounded by the granter's own relation; relation
  and expiry MUST be validated; expired grants MUST have no effect at check
  time.
- **SR-004**: Reads of secret material MUST be individually audited with the
  version read; bulk disclosures (export, backup with material) MUST be
  audited with counts and require an explicit `transfer:export` /
  `backup:manage` permission.
- **SR-005**: Share links MUST carry at least 128 bits of entropy, be
  single-use per open budget, expire by policy, be stored only hashed, and
  answer uniformly when invalid; the disclosure page MUST not be cached and
  MUST be audited.
- **SR-006**: Import files MUST be size-limited (16 MiB), parsed with a
  bounded decoder, and validated field by field (lengths, URL shape, UTF-8, no
  control characters); nothing is written until validation passes.
- **SR-007**: The vault credential MUST be loaded from files or the secrets
  provider, never from flags or logs; tokens MUST be renewed automatically;
  vault outages MUST fail closed for material and never expose partial
  writes.
- **SR-008**: One-time codes MUST be computed server-side from the stored seed
  with the seed never leaving the vault boundary except into the service's
  memory for the computation.

### Key Entities

- **Secret**: name, username, host URL, description, metadata, folder,
  current version number, has-seed flag, creator, updater, times; the material
  is referenced, not stored.
- **Secret Version**: version number, comment, checksum, author, time; points
  at the vault entry of that version.
- **Folder**: name, parent, path, creator, times.
- **Grant**: resource (folder or secret), subject (user, role, tenant),
  relation, granter, time, optional expiry.
- **Share**: secret, recipient email, message, policies, open budget and
  count, expiry, creator, state (active, consumed, expired, cancelled),
  link (hashed).
- **Audit Event**: actor, tenant, operation, subject, outcome, reason, time,
  correlation id, details (never material).
- **Import/Export Report**: counts per outcome, per-item problems, warnings.
- **Statistics**: per tenant: secrets, folders, grants, versions, shares.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A member can create a folder, add a secret and reveal its
  password in under one minute through the shell.
- **SC-002**: Revealing a password or reading a version takes under 300 ms at
  the 95th percentile with the vault healthy; listings of 1,000 secrets under
  500 ms.
- **SC-003**: 100% of cross-tenant reads, writes, grants and share opens in
  the test suite are refused as not found.
- **SC-004**: 100% of grant, revoke and expiry changes are enforced on the
  next request; no stale access longer than one second.
- **SC-005**: Zero occurrences of passwords, seeds or share links in the
  database, logs, audit records, metrics, search index or material-less
  backups across the test run (automated scan with a marker corpus).
- **SC-006**: A 5,000-item Bitwarden export validates in under 10 s and
  imports in under 60 s with a correct per-outcome report.
- **SC-007**: A backup taken with material and imported into an empty tenant
  reproduces 100% of folders, secrets, versions and grants.
- **SC-008**: With the vault unreachable, 100% of material operations answer
  a temporary error within 2 s and no partial writes remain; metadata
  operations keep working.
- **SC-009**: Every operation produces exactly one audit event with the
  correct actor and outcome; refusals included.
- **SC-010**: The module's screens have no serious or critical accessibility
  violations.

## Assumptions

- Tenants, users, roles and groups are those of the authentication service;
  Warden never manages identities. A "role" subject is an auth role slug; a
  subject holds it directly or through a group.
- The platform's existing API permission model (registered at the gateway,
  granted through auth roles) gates operations; Warden's own grants gate
  resources. Tenant owners/admins receive every Warden API permission by
  default; members receive `secrets:read`, `secrets:write`, `secrets:share`
  and `folders:manage` so they can build their own trees, subject to grants.
- The secrets vault is HashiCorp Vault KV v2 reachable from the service with an
  AppRole credential; one mount, one path prefix per tenant. Development runs a
  local Vault in dev mode.
- Password versions are kept indefinitely; a later feature may add retention.
- Full-text search is by substring/prefix over metadata fields of readable
  secrets; ranking and stemming are out of scope.
- The password generator runs server-side so its randomness quality is
  uniform; the UI may also generate locally.
- External sharing sends email through the platform's mail transport (as the
  auth service does); the disclosure page is served by Warden through the
  gateway as a public route protected only by the link capability.
- Region/network share policies are evaluated from the client address seen by
  the gateway; device/MAC policies of the reference project are out of scope.
- Backups and Bitwarden files are exchanged as downloads/uploads through the
  browser, up to 16 MiB.
- The reference project's separate "sharing service" is not replicated;
  Warden implements sharing itself.
