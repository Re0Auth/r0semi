-- +goose Up
--
-- R10-96: scs commits a loaded session after the handler returns
-- (scs session.go commitAndWriteSessionCookie), so a request that loaded a
-- session before another request destroyed it writes its stale copy back through
-- CommitCtx's unconditional upsert. Deleting the row removed the conflict target
-- and the upsert took the INSERT branch, reviving a session the operator had just
-- invalidated — and the revived row is absent from session_subjects, so a
-- per-subject revocation can never reach it.
--
-- The marker makes invalidation authoritative: the upsert's DO UPDATE carries
-- `WHERE sessions.invalidated_at IS NULL`, so a commit for a destroyed token
-- updates zero rows instead of re-creating the session. The payload is blanked at
-- the same time. The row and its deadline stay until the existing sweep removes
-- them, which is what outlives any in-flight commit.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS invalidated_at timestamptz;

-- +goose Down
ALTER TABLE sessions DROP COLUMN IF EXISTS invalidated_at;
