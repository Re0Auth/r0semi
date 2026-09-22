-- +goose Up
--
-- The administrative lifecycle of a registered client. Existing rows predate the
-- concept and are in use, so they default to active rather than being silently
-- disabled by the migration.
--
-- 'suspended' is not a second kind of "not found": the registry reports such a
-- client as unknown, so an operator's decision is indistinguishable from a client
-- id that never existed.

ALTER TABLE oauth_clients
    ADD COLUMN status text NOT NULL DEFAULT 'active';

-- +goose Down
ALTER TABLE oauth_clients DROP COLUMN status;
