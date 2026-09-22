-- Append-only audit events. Nothing updates or deletes these rows: the audit
-- log is an integrity record, not a working table.
--
-- `detail` is jsonb so callers can carry structured, non-credential context
-- (client_id, request_id, ...) without a schema migration per field.

CREATE TABLE audit_events (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL,
    action      text        NOT NULL,
    subject     text        NOT NULL DEFAULT '',
    provider    text        NOT NULL DEFAULT '',
    outcome     text        NOT NULL,
    detail      jsonb       NOT NULL DEFAULT '{}'::jsonb
);

-- The two query shapes an audit review actually needs: "everything about this
-- subject, newest first" and "every occurrence of this action, newest first".
CREATE INDEX audit_events_subject_time_idx
    ON audit_events (subject, occurred_at DESC);
CREATE INDEX audit_events_action_time_idx
    ON audit_events (action, occurred_at DESC);
