-- +goose Up
--
-- A leading index for the device tables' `denied` predicate.
--
-- OIDCStore.DenyDevice (oidc.go) writes
--
--     UPDATE oidc_devices SET denied = true
--      WHERE upper(replace(user_code, '-', '')) = upper(replace($1, '-', ''))
--        AND denied = false
--
-- and ApproveDevice adds the same `denied = false` to the pending condition it
-- claims on. The canonicalised user code half is served by 0008's unique
-- expression index; the boolean state column had no index of its own, so the
-- predicate-index guard (z21migrationsschemaintegrity/predicate_index_test.go,
-- which derives the target set from the Go source rather than a hand list) read
-- the statement's only plain-column predicate — `denied` — as unindexed.
--
-- The pending-device predicates are `denied = false`, frequently together with
-- an `expires_at` deadline, so a leading `denied` column gives the planner a
-- start it can use without depending on the expression index the schema parser
-- cannot see.

CREATE INDEX oidc_devices_denied_idx ON oidc_devices (denied);

-- +goose Down
DROP INDEX IF EXISTS oidc_devices_denied_idx;
