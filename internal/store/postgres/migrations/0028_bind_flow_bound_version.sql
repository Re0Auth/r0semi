-- +goose Up
--
-- S14-2 residual: a bind flow must remember what it was started against.
--
-- 992710b made CompleteBind take the per-binding keyedMutex, which orders a bind
-- against a CONCURRENT Unbind/CascadeRevoke/shredBinding within one process. But
-- the flow is consumed before the lock and the old row write was an unconditional
-- Put, so a removal that had already completed was still undone when the stale
-- callback finally ran: two tabs, a Kill Switch sweep, or an account erasure. The
-- keyedMutex is process-local, so on Postgres with several replicas it did not
-- order the two at all.
--
-- The fix is the compare-and-swap refreshBinding already uses, with the binding
-- version the flow must still match captured at BeginBind:
--   bound         - whether a binding existed when the flow began
--   bound_version - that binding's Version (meaningful only when bound is true)
-- CompleteBind re-checks them under the lock with PutIfVersion (when bound) or an
-- insert-if-absent (Create) when not, and refuses if the row moved or vanished.
-- Both are single store statements, so the check holds across processes where the
-- mutex cannot.
--
-- Existing pending flows default to bound=false/0, i.e. "nothing was bound": a
-- first bind whose row now exists loses the insert and is refused (fail closed).
-- A pending flow is at most one bind TTL from expiry, so the window is bounded.

ALTER TABLE federation_bind_flows ADD COLUMN bound boolean NOT NULL DEFAULT false;
ALTER TABLE federation_bind_flows ADD COLUMN bound_version bigint NOT NULL DEFAULT 0;

-- +goose Down
--
-- An ordinary reversible Down: these two columns are the precondition a pending
-- flow is checked against, not credential material, so dropping them cannot
-- invalidate a stored binding.
ALTER TABLE federation_bind_flows DROP COLUMN IF EXISTS bound_version;
ALTER TABLE federation_bind_flows DROP COLUMN IF EXISTS bound;
