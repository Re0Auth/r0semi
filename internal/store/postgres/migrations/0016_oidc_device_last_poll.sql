-- +goose Up
--
-- RFC 8628 §3.5: a device that polls faster than the interval the authorization
-- response advertised is told to slow down. Without a record of the last poll
-- the store answered authorization_pending for every request, so a buggy or
-- hostile client could hammer the token endpoint and the audit trail showed
-- nothing different.
--
-- last_poll is nullable: NULL means "never polled", which is the honest state of
-- a freshly issued device authorization and lets the first poll through.
--
-- The store's GetDeviceAuthorizatonState compares it against the advertised
-- interval and answers context.DeadlineExceeded when a poll is too soon; the
-- library maps that to the slow_down error.

ALTER TABLE oidc_devices ADD COLUMN last_poll timestamptz;

-- +goose Down
ALTER TABLE oidc_devices DROP COLUMN IF EXISTS last_poll;
