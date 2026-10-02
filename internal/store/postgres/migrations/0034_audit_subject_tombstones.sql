-- +goose Up
--
-- Cross-instance erasure tombstones for audit pseudonyms (Z10-1).
--
-- The per-subject pseudonym key lives in audit_subject_keys (0014). Destroy
-- deletes that row, which unlinks the subject's audit history — but an erasure is
-- performed by ONE process, and every other replica holds a warm in-process cache
-- mapping the subject to the key it read before the erasure. A replica cannot
-- observe another replica's memory, so its cache kept pseudonymising the erased
-- subject indefinitely. The 30s cache TTL only shrank that from forever to a
-- window; it never closed it.
--
-- This table is the shared fact the replicas can agree on. Destroy writes one row
-- here in the same transaction that deletes the key. Every replica refreshes a
-- local mirror from this table before it answers from its cache, and a subject
-- named here is never answered from cache again: the warm entry is dropped and
-- the key is re-read (which, after the erasure, finds nothing).
--
--   seq           = insertion order, the watermark a replica syncs from. A
--                   timestamp would make two rows written in one transaction
--                   indistinguishable and could silently skip one.
--   idx           = the same HMAC(audit key, "…subject-index/1" ‖ subject) the
--                   key table uses. The raw subject is deliberately NOT stored:
--                   a database dump must not become a second account list.
--   tombstoned_at = when the erasure happened, for operators and future GC. It is
--                   not the sync key (see seq).
--
-- The supporting index is on tombstoned_at: an operator query for recent
-- erasures, and any future age-based cleanup, must not scan the table. It is
-- created in this file, so `seq`'s primary key is not the only index.

CREATE TABLE IF NOT EXISTS audit_subject_tombstones (
    seq           bigserial   PRIMARY KEY,
    idx           text        NOT NULL UNIQUE,
    tombstoned_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_subject_tombstones_tombstoned_at_idx
    ON audit_subject_tombstones (tombstoned_at);

-- +goose Down
--
-- Unlike 0013/0014 this step is reversible: dropping the table undoes a schema
-- change and does not destroy any hash, chain head or pseudonym key. It does
-- re-open the cross-replica window until TTL, which is the operator's call when
-- they roll back; the key rows themselves are untouched.
DROP INDEX IF EXISTS audit_subject_tombstones_tombstoned_at_idx;
DROP TABLE IF EXISTS audit_subject_tombstones;
