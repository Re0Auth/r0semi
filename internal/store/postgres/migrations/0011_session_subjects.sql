-- +goose Up
--
-- Which account a session belongs to.
--
-- scs has no such notion: a session is an opaque cookie and the store's Commit
-- sees only encoded bytes. Re0Auth records the mapping itself when it signs
-- someone in, so the Kill Switch can reach every session a subject holds.
--
-- There is deliberately no foreign key to sessions. The index row is written
-- inside the request that signs the user in, but scs commits the session row
-- only when the response is written, at the end of that same request. A foreign
-- key would therefore reject the row it is meant to accompany. Orphans are
-- collected by the session sweep, which is where a missing session row is
-- already a known condition.

CREATE TABLE session_subjects (
    token_hash text PRIMARY KEY,
    subject    text NOT NULL
);

CREATE INDEX session_subjects_subject_idx ON session_subjects (subject);

-- +goose Down
DROP TABLE session_subjects;
