-- +goose Up
--
-- oidc_devices is swept by deadline (postgres.DB.SweepExpired) but had no index
-- on expires_at, so that delete was a sequential scan on a table that grows with
-- every device flow. Every other swept table has one: 0008 created them next to
-- the tables themselves, and 0012 added the two that were missing then — this one
-- was missed.
--
-- The sweep runs every fifteen minutes, so the cost is a table scan every fifteen
-- minutes for the life of the deployment, on the same connection pool as live
-- traffic.

CREATE INDEX oidc_devices_expires_idx ON oidc_devices (expires_at);

-- +goose Down
DROP INDEX IF EXISTS oidc_devices_expires_idx;
