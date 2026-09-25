-- +goose Up
--
-- Pseudonymisation of audit subjects.
--
-- The audit log names an account on nearly every row. That makes it a personal
-- data store in its own right, and it means an erasure that leaves the log alone
-- leaves the person's trail in place. This table is the destructible half of the
-- fix: audit rows carry a keyed pseudonym instead of the raw `usr_`, and deleting
-- one row here makes that account's whole history unlinkable — without touching a
-- single audit row, so the chain built in 0013 stays intact.
--
--   idx       = HMAC(audit key, "…subject-index/1" ‖ subject)   -- the lookup
--   key       = 32 random bytes                                  -- per subject
--   pseudonym = HMAC(key, "…pseudonym/1" ‖ subject)
--
-- The subject itself is deliberately NOT stored: `idx` is a keyed hash, so a
-- database dump does not contain the account ids in this table either. The audit
-- key lives in the environment, so a dump alone cannot recompute `idx` for a
-- candidate subject and therefore cannot resolve a pseudonym back to an account.
--
-- What this does and does not buy, stated plainly:
--
--   * after an erasure  -> the row is gone, so the pseudonym cannot be recomputed
--     from the subject by anyone, including this service. That is the point.
--   * before an erasure -> a dump of the whole database can still re-link a live
--     account's audit rows, because it contains both these keys and the account
--     ids. It also contains the account's identities and email, so that dump was
--     already total. Pseudonymisation is not a substitute for not being breached;
--     what it delivers is erasure.
--
-- Rows written before this migration keep whatever they already had. They are not
-- rewritten, because rewriting them would either invalidate the hashes written
-- over the old value (breaking 0013's chain) or require an in-Go data migration at
-- startup. See docs/architecture.md §4.17.

CREATE TABLE audit_subject_keys (
    idx text  PRIMARY KEY,
    key bytea NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS audit_subject_keys;
