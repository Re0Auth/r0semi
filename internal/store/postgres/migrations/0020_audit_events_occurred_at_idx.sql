-- +goose Up
--
-- The audit read API accepts a time window on its own
-- (`GET /v1/admin/audit?since=…&until=…`): internal/store/postgres/auditread.go
-- adds `occurred_at >= $` / `< $` with no other filter. Migration 0007 created
-- `(subject, occurred_at DESC)` and `(action, occurred_at DESC)`, so a query that
-- names neither a subject nor an action had no index to range-scan and fell back to
-- a sequential scan of the whole log — a table that grows without bound.
--
-- The primary key still orders the common "newest first, page by id" pull, so a
-- window near the tail is answered by walking the id index. This index is for the
-- other case: a historical window far from the tail, where that walk would have to
-- traverse every later row before reaching the first match.

CREATE INDEX audit_events_time_idx ON audit_events (occurred_at);

-- +goose Down
DROP INDEX IF EXISTS audit_events_time_idx;
