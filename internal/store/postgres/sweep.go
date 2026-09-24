package postgres

import (
	"context"
	"fmt"
)

// expiredTables are the dated rows the sweep removes, paired with the deadline
// column each one carries.
//
// The set mirrors what the in-memory OP store sweeps: an expired row is one a
// lookup already refuses, so removing it can never revoke something still in use.
// A lookup does refuse these -- the OP checks a token's deadline and the legacy
// engine's service owns that clock -- but nothing removed them, so without a
// sweep the tables keep every code, token and pending request the deployment ever
// issued.
//
// Sessions are not here. They have their own sweep (Sessions.SweepExpired), which
// also collects the orphan session_subjects rows, so it stays the single place
// that knows about that pair; the composition root runs both.
var expiredTables = []struct{ table, column string }{
	{"oauth_codes", "expires_at"},
	{"oauth_access_tokens", "expires_at"},
	{"oauth_refresh_tokens", "expires_at"},
	{"oauth_device_authorizations", "expires_at"},
	{"federation_bind_flows", "expires_at"},
	{"oidc_auth_requests", "expires_at"},
	{"oidc_codes", "expires_at"},
	{"oidc_access_tokens", "expires_at"},
	{"oidc_refresh_tokens", "expires_at"},
	{"oidc_devices", "expires_at"},
}

// SweepExpired removes every dated row whose deadline has passed and returns how
// many it removed.
//
// Deletes run in one transaction, so a sweep is a single consistent step rather
// than a dozen independent ones: a caller that sees an error gets an unchanged
// database, not a half-swept one. Every delete is idempotent regardless, so a
// retry after a failure is always safe.
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

	var total int64
	for _, t := range expiredTables {
		tag, err := tx.Exec(ctx, fmt.Sprintf(
			`DELETE FROM %s WHERE %s < now()`, t.table, t.column))
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
