-- +goose Up
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Folder tree. ancestors holds every ancestor id root-first; path is display only.
CREATE TABLE folders (
  id         uuid PRIMARY KEY,
  tenant_id  uuid NOT NULL,
  parent_id  uuid REFERENCES folders(id) ON DELETE CASCADE,
  name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  path       text NOT NULL,
  ancestors  uuid[] NOT NULL DEFAULT '{}',
  created_by uuid,
  updated_by uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX folders_sibling_name ON folders (tenant_id, parent_id, lower(name)) WHERE parent_id IS NOT NULL;
CREATE UNIQUE INDEX folders_root_name ON folders (tenant_id, lower(name)) WHERE parent_id IS NULL;
CREATE INDEX folders_tenant_parent ON folders (tenant_id, parent_id);
CREATE INDEX folders_ancestors ON folders USING gin (ancestors);

-- Secrets: metadata and the vault reference only.
CREATE TABLE secrets (
  id              uuid PRIMARY KEY,
  tenant_id       uuid NOT NULL,
  folder_id       uuid REFERENCES folders(id) ON DELETE RESTRICT,
  name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  username        text NOT NULL DEFAULT '' CHECK (length(username) <= 200),
  host_url        text NOT NULL DEFAULT '' CHECK (length(host_url) <= 2048),
  description     text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
  metadata        jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (pg_column_size(metadata) <= 16384),
  vault_path      text NOT NULL,
  current_version integer NOT NULL DEFAULT 0,
  has_totp        boolean NOT NULL DEFAULT false,
  search          text GENERATED ALWAYS AS (lower(name || ' ' || username || ' ' || host_url || ' ' || description)) STORED,
  created_by      uuid,
  updated_by      uuid,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  deleted_at      timestamptz
);
CREATE INDEX secrets_tenant_folder ON secrets (tenant_id, folder_id) WHERE deleted_at IS NULL;
CREATE INDEX secrets_search ON secrets USING gin (search gin_trgm_ops);

-- One row per KV v2 version.
CREATE TABLE secret_versions (
  secret_id        uuid NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  tenant_id        uuid NOT NULL,
  version          integer NOT NULL,
  comment          text NOT NULL DEFAULT '' CHECK (length(comment) <= 500),
  checksum         text NOT NULL,
  source           text NOT NULL,
  material_missing boolean NOT NULL DEFAULT false,
  created_by       uuid,
  created_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (secret_id, version)
);

-- Zanzibar-style grants.
CREATE TABLE grants (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL,
  resource_type text NOT NULL CHECK (resource_type IN ('folder','secret')),
  resource_id   uuid NOT NULL,
  subject_type  text NOT NULL CHECK (subject_type IN ('user','role','tenant')),
  subject_id    text NOT NULL DEFAULT '',
  relation      text NOT NULL CHECK (relation IN ('owner','editor','viewer','sharer')),
  granted_by    uuid,
  granted_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz,
  UNIQUE (tenant_id, resource_type, resource_id, subject_type, subject_id)
);
CREATE INDEX grants_resource ON grants (tenant_id, resource_id);
CREATE INDEX grants_subject ON grants (tenant_id, subject_type, subject_id);

-- External shares: the link token is stored hashed only.
CREATE TABLE shares (
  id              uuid PRIMARY KEY,
  tenant_id       uuid NOT NULL,
  secret_id       uuid NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  token_hash      text NOT NULL UNIQUE,
  recipient_email text NOT NULL CHECK (length(recipient_email) <= 254),
  message         text NOT NULL DEFAULT '' CHECK (length(message) <= 1000),
  max_opens       integer NOT NULL CHECK (max_opens BETWEEN 1 AND 10),
  opens           integer NOT NULL DEFAULT 0,
  expires_at      timestamptz NOT NULL,
  cidr            text,
  region          text,
  state           text NOT NULL CHECK (state IN ('active','consumed','expired','cancelled')),
  created_by      uuid NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX shares_creator ON shares (tenant_id, created_by, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS shares, grants, secret_versions, secrets, folders;
