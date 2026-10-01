-- +goose Up
-- Index-backed list sorting (go-tangra specs/032-server-side-tables perf.md):
-- with listquery v4.3.1, NotNull fields order without NULLS LAST, so one
-- ascending btree ending in the id tie-breaker serves both directions
-- (forward and backward scans).
--
-- A folder's live secrets by created_at / updated_at (by name:
-- secrets_folder_name, 0005). secrets_tenant_created (0005) has neither the
-- folder nor the id tie-breaker, so no page could use it; it is replaced.
CREATE INDEX IF NOT EXISTS secrets_folder_created ON secrets (tenant_id, folder_id, created_at, id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS secrets_folder_updated ON secrets (tenant_id, folder_id, updated_at, id) WHERE deleted_at IS NULL;
DROP INDEX IF EXISTS secrets_tenant_created;
-- The root's live secrets: "folder_id IS NULL" is an index condition but not
-- a constant the planner can drop from the index order, so the root page
-- gets partial indexes without the folder column.
CREATE INDEX IF NOT EXISTS secrets_root_name ON secrets (tenant_id, lower(name), id) WHERE deleted_at IS NULL AND folder_id IS NULL;
CREATE INDEX IF NOT EXISTS secrets_root_created ON secrets (tenant_id, created_at, id) WHERE deleted_at IS NULL AND folder_id IS NULL;
CREATE INDEX IF NOT EXISTS secrets_root_updated ON secrets (tenant_id, updated_at, id) WHERE deleted_at IS NULL AND folder_id IS NULL;

-- Shares of a secret, newest first by default: the page filters tenant,
-- secret and creator; shares_creator (tenant_id, created_by, created_at DESC)
-- has no secret_id and no id, so every page sorted.
CREATE INDEX IF NOT EXISTS shares_secret_creator_created ON shares (tenant_id, secret_id, created_by, created_at, id);

-- +goose Down
DROP INDEX IF EXISTS shares_secret_creator_created;
DROP INDEX IF EXISTS secrets_root_updated;
DROP INDEX IF EXISTS secrets_root_created;
DROP INDEX IF EXISTS secrets_root_name;
CREATE INDEX IF NOT EXISTS secrets_tenant_created ON secrets (tenant_id, created_at);
DROP INDEX IF EXISTS secrets_folder_updated;
DROP INDEX IF EXISTS secrets_folder_created;
