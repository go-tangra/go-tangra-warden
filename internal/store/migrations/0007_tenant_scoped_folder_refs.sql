-- +goose Up
-- A secret's folder and a folder's parent must belong to the same tenant.
-- The column FKs of 0001 reference folders(id) alone, which a folder of
-- another tenant satisfies (FK checks do not see RLS); these composite FKs
-- make the tenant boundary a database invariant. The service and store
-- already check the target, in the same statement as the move.
ALTER TABLE folders ADD CONSTRAINT folders_tenant_id_key UNIQUE (tenant_id, id);
ALTER TABLE folders ADD CONSTRAINT folders_parent_same_tenant
  FOREIGN KEY (tenant_id, parent_id) REFERENCES folders (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE secrets ADD CONSTRAINT secrets_folder_same_tenant
  FOREIGN KEY (tenant_id, folder_id) REFERENCES folders (tenant_id, id) ON DELETE RESTRICT;

-- +goose Down
ALTER TABLE secrets DROP CONSTRAINT IF EXISTS secrets_folder_same_tenant;
ALTER TABLE folders DROP CONSTRAINT IF EXISTS folders_parent_same_tenant;
ALTER TABLE folders DROP CONSTRAINT IF EXISTS folders_tenant_id_key;
