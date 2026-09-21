-- +goose Up
CREATE TABLE warden_audit_events (
  ts             timestamptz NOT NULL,
  tenant_id      uuid NOT NULL,
  event_type     text NOT NULL,
  actor_kind     text NOT NULL CHECK (actor_kind IN ('user','service','recipient','system')),
  actor_id       text NOT NULL DEFAULT '',
  subject_kind   text NOT NULL DEFAULT '',
  subject_id     text NOT NULL DEFAULT '',
  outcome        text NOT NULL CHECK (outcome IN ('ok','refused','failed')),
  reason         text NOT NULL DEFAULT '',
  correlation_id text NOT NULL DEFAULT '',
  details        jsonb NOT NULL DEFAULT '{}'::jsonb
);
SELECT create_hypertable('warden_audit_events', 'ts', chunk_time_interval => INTERVAL '7 days');
CREATE INDEX warden_audit_tenant_ts ON warden_audit_events (tenant_id, ts DESC);
CREATE INDEX warden_audit_type_ts ON warden_audit_events (tenant_id, event_type, ts DESC);
SELECT add_retention_policy('warden_audit_events', INTERVAL '400 days');

-- +goose Down
DROP TABLE IF EXISTS warden_audit_events;
