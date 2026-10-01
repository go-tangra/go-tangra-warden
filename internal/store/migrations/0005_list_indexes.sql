-- +goose Up
-- Server-side paging and sorting (go-tangra specs/032-server-side-tables):
-- the folder view pages a folder's live secrets by name with the id
-- tie-breaker; created_at sorts the tenant's secrets newest first. The audit
-- hypertable already has (tenant_id, ts DESC).
CREATE INDEX IF NOT EXISTS secrets_folder_name ON secrets (tenant_id, folder_id, lower(name), id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS secrets_tenant_created ON secrets (tenant_id, created_at);

-- +goose Down
DROP INDEX IF EXISTS secrets_tenant_created;
DROP INDEX IF EXISTS secrets_folder_name;
