-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'warden_app') THEN
    GRANT USAGE ON SCHEMA public TO warden_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO warden_app;
    REVOKE UPDATE, DELETE ON warden_audit_events FROM warden_app;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
SELECT 1;
