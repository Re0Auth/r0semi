-- +goose Up
--
-- When an entry in session_subjects was written.
--
-- The sweep collects index rows whose session row does not exist, which is how
-- the table stays bounded despite having no foreign key. But the index row is
-- written during SignIn while scs commits the session row only when the response
-- is written — so for the length of one request a LIVE session has no session row,
-- and a sweep landing in that window deleted the only record of which account the
-- session belonged to. Nothing rewrites it afterwards: a later subject-scoped Kill
-- Switch then missed that live session while reporting the sweep complete.
--
-- With an age, the sweep can skip anything young enough to still be mid-flight and
-- only collect rows that are genuinely orphaned. The cost is that a real orphan
-- lingers for the grace period, which is bounded and harmless — nothing reads an
-- index row for a session that does not exist.
--
-- Existing rows take the migration's timestamp, which is by definition older than
-- the grace, so they are collected as before.

ALTER TABLE session_subjects ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();

-- +goose Down
ALTER TABLE session_subjects DROP COLUMN IF EXISTS created_at;
