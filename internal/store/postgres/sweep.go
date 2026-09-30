package postgres

import (
	"context"
	"fmt"
)

// sweepBatchSize bounds one statement of one cycle: each table contributes at
// most this many rows per cycle, so a backlog larger than the budget is worked
// off over the following ticks instead of never.
//
// Before this bound every table was one unbounded DELETE and the twelve shared a
// single transaction: a backlog whose delete outlived the pool's 30s
// statement_timeout rolled the whole cycle back, and each tick re-attempted the
// same, still-growing work with no progress (Z15-1, docs/issues/P2-medium.md).
const sweepBatchSize = 1000

// expiredTables are the dated rows the sweep removes, paired with the deadline
// column each one carries.
//
// The list holds twelve tables at HEAD. The Z15-1 register entry says ten, which
// was already stale when the fix landed (Z15-1, docs/issues/P2-medium.md).
//
// The set mirrors what the in-memory OP store sweeps. Deleting by deadline is the
// stricter direction, so a sweep can never revoke something still in use — every
// swept OIDC read path refuses an expired row before this sweep reaches it (N-01;
// TestEverySweptReadPathAdjudicatesItsDeadline pins the predicate each one
// carries). The oauth_* and federation_* deadlines are adjudicated by the legacy
// engine's service (oauth/as.go, oauth/device.go, internal/federation/bind.go),
// not by this adapter. Nothing else removed these rows, so without a sweep the
// tables keep every code, token and pending request the deployment ever issued.
//
// Every deadline column here is written by this process (never by the database),
// so every comparison is against this process's clock, passed in as a parameter.
// Judging them with the database's now() instead is the two-clock mix that could
// delete a row its writer still considered live; see DB.now.
//
// Sessions are not here. They have their own sweep (Sessions.SweepExpired), which
// also collects the orphan session_subjects rows, so it stays the single place
// that knows about that pair; the composition root runs both.
var expiredTables = []struct{ table, column string }{
	{"oauth_codes", "expires_at"},
	{"oauth_access_tokens", "expires_at"},
	{"oauth_refresh_tokens", "expires_at"},
	{"oauth_refresh_tombstones", "expires_at"},
	{"oauth_device_authorizations", "expires_at"},
	{"federation_bind_flows", "expires_at"},
	{"oidc_auth_requests", "expires_at"},
	{"oidc_codes", "expires_at"},
	{"oidc_access_tokens", "expires_at"},
	{"oidc_refresh_tokens", "expires_at"},
	{"oidc_refresh_token_tombstones", "expires_at"},
	{"oidc_devices", "expires_at"},
}

// SweepExpired removes dated rows whose deadline has passed and returns how many
// it removed. Each table contributes at most sweepBatchSize rows per cycle.
//
// Deletes run in one transaction, so a sweep is a single consistent step rather
// than a dozen independent ones: a caller that sees an error gets an unchanged
// database, not a half-swept one. Every delete is idempotent regardless, so a
// retry after a failure is always safe. That decision is deliberate and stays
// (docs/issues/not-doing.md); what changes here is that a single statement can no
// longer run without a bound.
//
// Each delete is a ctid lookup over the same deadline predicate, capped with
// LIMIT: the subquery still reads through the deadline index that
// TestEverySweptTableHasADeadlineIndex guards, and one cycle removes at most
// len(expiredTables) * sweepBatchSize rows, with the next tick continuing. That
// is what makes the pool's per-connection statement_timeout unreachable by
// design — an unbounded delete on a grown table could outlive it, roll the single
// transaction back and leave every tick re-attempting the same growing work
// (Z15-1, docs/issues/P2-medium.md).
//
// The table and column names are compile-time constants, never request input, so
// building each statement with Sprintf does not put anything user-controlled into
// the SQL.
func (db *DB) SweepExpired(ctx context.Context) (int64, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := db.now()
	var total int64
	for _, t := range expiredTables {
		// The outer predicate repeats the subquery's so the statement says which
		// rows it removes without the reader having to follow the ctid lookup; the
		// LIMIT is what bounds one cycle's work.
		tag, err := tx.Exec(ctx, fmt.Sprintf(
			`DELETE FROM %s WHERE %s < $1
			   AND ctid IN (SELECT ctid FROM %s WHERE %s < $1 LIMIT $2)`,
			t.table, t.column, t.table, t.column), now, sweepBatchSize)
		if err != nil {
			return 0, fmt.Errorf("postgres: sweep %s: %w", t.table, err)
		}
		total += tag.RowsAffected()
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return total, nil
}
