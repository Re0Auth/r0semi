-- +goose Up
--
-- The session sweep collects orphaned index rows by age:
--
--   DELETE FROM session_subjects si
--    WHERE NOT EXISTS (SELECT 1 FROM sessions s WHERE s.token_hash = si.token_hash)
--      AND si.created_at < now() - $1::interval
--
-- (internal/store/postgres/sessions.go, SweepExpired). `created_at` was added by
-- migration 0015 for the grace period but never indexed, so the age predicate had
-- no way in and every sweep read the whole table. The primary key is token_hash,
-- which answers the lookup side of the anti-join, not the age side.
--
-- The table is small next to the token tables, but it gains a row on every sign-in
-- and is swept every fifteen minutes; the index keeps the sweep proportional to
-- the rows it actually collects rather than to everyone who has ever signed in.

CREATE INDEX session_subjects_created_at_idx ON session_subjects (created_at);

-- +goose Down
DROP INDEX IF EXISTS session_subjects_created_at_idx;
