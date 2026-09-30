package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/federation"
)

// Bindings implements federation.BindingStore on Postgres.
//
// It stores metadata only. The upstream token is not here and cannot be: the
// table has no such column, and federation.Binding has no such field.
type Bindings struct{ pool *pgxpool.Pool }

// bindingRow is one federation_bindings row, named so scanning matches by column
// rather than by position.
type bindingRow struct {
	UserID     string     `db:"user_id"`
	Game       string     `db:"game"`
	Source     string     `db:"source"`
	TokenType  string     `db:"token_type"`
	Expiry     *time.Time `db:"expiry"`
	HasRefresh bool       `db:"has_refresh"`
	// Version is scanned through int64 on purpose. The stored value is a
	// random uint64 written as int64(v); scanning the bigint straight into a
	// uint64 leaves the conversion to the driver's codec, which is not a
	// promise this project wants to depend on. Reading the signed value and
	// converting back is bit-exact and driver-agnostic.
	Version int64 `db:"version"`
}

func (r bindingRow) binding() federation.Binding {
	b := federation.Binding{
		User:       account.UserID(r.UserID),
		Game:       r.Game,
		Source:     r.Source,
		TokenType:  r.TokenType,
		HasRefresh: r.HasRefresh,
		// The version is a random uint64 stored bit-exactly in the signed
		// bigint column (see bindingRow.Version above), so the signed→unsigned
		// conversion returns the same bits rather than truncating a magnitude
		// (G115).
		Version: uint64(r.Version), //nolint:gosec // G115: bit-exact round trip of the random version
	}
	if r.Expiry != nil {
		b.Expiry = *r.Expiry
	}
	return b
}

// Get implements federation.BindingStore.
func (s *Bindings) Get(ctx context.Context, user account.UserID, game, source string) (federation.Binding, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT user_id, game, source, token_type, expiry, has_refresh, version
		  FROM federation_bindings
		 WHERE user_id = $1 AND game = $2 AND source = $3`,
		string(user), game, source)
	if err != nil {
		return federation.Binding{}, err
	}
	return scanBinding(rows)
}

// Put implements federation.BindingStore.
func (s *Bindings) Put(ctx context.Context, b federation.Binding) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO federation_bindings (user_id, game, source, token_type, expiry, has_refresh, version)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (user_id, game, source) DO UPDATE SET
			token_type  = EXCLUDED.token_type,
			expiry      = EXCLUDED.expiry,
			has_refresh = EXCLUDED.has_refresh,
			version     = EXCLUDED.version`,
		string(b.User), b.Game, b.Source, b.TokenType, nullTime(b.Expiry), b.HasRefresh, int64(b.Version)) //nolint:gosec // G115: bit-exact round trip of the random version
	return err
}

// PutIfVersion implements federation.BindingStore.
//
// It is a single conditional UPDATE, so the version check and the write cannot
// be separated by another writer: two processes that both read version N cannot
// both write N+1. It reports false when the row is absent or already at another
// version, which the caller must read as "somebody else won".
func (s *Bindings) PutIfVersion(ctx context.Context, b federation.Binding, expectedVersion uint64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE federation_bindings
		   SET token_type  = $4,
		       expiry      = $5,
		       has_refresh = $6,
		       version     = $7
		 WHERE user_id = $1 AND game = $2 AND source = $3 AND version = $8`,
		string(b.User), b.Game, b.Source, b.TokenType, nullTime(b.Expiry),
		b.HasRefresh, int64(b.Version), int64(expectedVersion)) //nolint:gosec // G115: bit-exact round trip of the random version
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// Delete implements federation.BindingStore. Deleting an absent binding is not
// an error, so unbinding stays idempotent.
func (s *Bindings) Delete(ctx context.Context, user account.UserID, game, source string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM federation_bindings WHERE user_id = $1 AND game = $2 AND source = $3`,
		string(user), game, source)
	return err
}

// List implements federation.BindingStore.
//
// Ordered in SQL rather than in Go, so the account page does not reorder itself
// between two loads depending on which rows the planner happened to return first.
func (s *Bindings) List(ctx context.Context, user account.UserID) ([]federation.Binding, error) {
	return s.queryBindings(ctx, `
		SELECT user_id, game, source, token_type, expiry, has_refresh, version
		  FROM federation_bindings
		 WHERE user_id = $1
		 ORDER BY game, source`, string(user))
}

// ListAll implements federation.BindingStore. It backs the Kill Switch's
// deployment-wide sweep, which is the only caller that needs bindings it was
// never handed by a user.
func (s *Bindings) ListAll(ctx context.Context) ([]federation.Binding, error) {
	return s.queryBindings(ctx, `
		SELECT user_id, game, source, token_type, expiry, has_refresh, version
		  FROM federation_bindings
		 ORDER BY user_id, game, source`)
}

// ListAllPage implements federation.BindingPager: the same order as ListAll, one
// page at a time, keyed on the primary key.
//
// The keyset predicate is what keeps the sweep's memory flat and its queries
// index-backed. It also tolerates the sweep deleting rows as it goes: the cursor
// is the last row *read*, so removing rows behind it cannot make the next page
// skip anything.
func (s *Bindings) ListAllPage(ctx context.Context, afterUser, afterGame, afterSource string, limit int) ([]federation.Binding, error) {
	if limit <= 0 {
		limit = 1
	}
	if afterUser == "" && afterGame == "" && afterSource == "" {
		return s.queryBindings(ctx, `
			SELECT user_id, game, source, token_type, expiry, has_refresh, version
			  FROM federation_bindings
			 ORDER BY user_id, game, source
			 LIMIT $1`, limit)
	}
	return s.queryBindings(ctx, `
		SELECT user_id, game, source, token_type, expiry, has_refresh, version
		  FROM federation_bindings
		 WHERE (user_id, game, source) > ($1, $2, $3)
		 ORDER BY user_id, game, source
		 LIMIT $4`, afterUser, afterGame, afterSource, limit)
}

func (s *Bindings) queryBindings(ctx context.Context, query string, args ...any) ([]federation.Binding, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	scanned, err := pgx.CollectRows(rows, pgx.RowToStructByName[bindingRow])
	if err != nil {
		return nil, err
	}

	out := make([]federation.Binding, 0, len(scanned))
	for _, r := range scanned {
		out = append(out, r.binding())
	}
	return out, nil
}

// scanBinding maps the single row of a one-row result, reporting the store's
// not-bound sentinel for an empty result. CollectOneRow produces pgx.ErrNoRows,
// which is the same signal the old QueryRow.Scan produced.
func scanBinding(rows pgx.Rows) (federation.Binding, error) {
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[bindingRow])
	if noRows(err) {
		return federation.Binding{}, federation.ErrNotBound
	}
	if err != nil {
		return federation.Binding{}, err
	}
	return row.binding(), nil
}

// BindFlows implements federation.BindFlowStore on Postgres. Consume is a single
// DELETE ... RETURNING, which is what makes a bind flow single-use under
// concurrent callbacks.
type BindFlows struct{ pool *pgxpool.Pool }

// Put implements federation.BindFlowStore.
func (s *BindFlows) Put(ctx context.Context, f federation.BindFlow) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO federation_bind_flows
			(state, id, user_id, game, source, pkce_verifier, return_to, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (state) DO UPDATE SET
			id            = EXCLUDED.id,
			user_id       = EXCLUDED.user_id,
			game          = EXCLUDED.game,
			source        = EXCLUDED.source,
			pkce_verifier = EXCLUDED.pkce_verifier,
			return_to     = EXCLUDED.return_to,
			expires_at    = EXCLUDED.expires_at`,
		f.State, f.ID, string(f.User), f.Game, f.Source, f.Verifier, f.ReturnTo, f.ExpiresAt)
	return err
}

// bindFlowRow is the RETURNING shape of a consumed federation_bind_flows row.
type bindFlowRow struct {
	ID           string    `db:"id"`
	UserID       string    `db:"user_id"`
	Game         string    `db:"game"`
	Source       string    `db:"source"`
	PKCEVerifier string    `db:"pkce_verifier"`
	ReturnTo     string    `db:"return_to"`
	ExpiresAt    time.Time `db:"expires_at"`
}

// Consume implements federation.BindFlowStore.
func (s *BindFlows) Consume(ctx context.Context, state string) (federation.BindFlow, error) {
	rows, err := s.pool.Query(ctx, `
		DELETE FROM federation_bind_flows
		 WHERE state = $1
		RETURNING id, user_id, game, source, pkce_verifier, return_to, expires_at`, state)
	if err != nil {
		return federation.BindFlow{}, err
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[bindFlowRow])
	if noRows(err) {
		return federation.BindFlow{}, federation.ErrUnknownBind
	}
	if err != nil {
		return federation.BindFlow{}, err
	}
	return federation.BindFlow{
		ID:        row.ID,
		User:      account.UserID(row.UserID),
		Game:      row.Game,
		Source:    row.Source,
		Verifier:  row.PKCEVerifier,
		State:     state,
		ReturnTo:  row.ReturnTo,
		ExpiresAt: row.ExpiresAt,
	}, nil
}

// PurgeUserFlows implements federation.BindFlowStore: every pending bind flow an
// account has started, gone.
//
// A pending flow holds a PKCE verifier, and it is a row about a person the
// account-erasure path must not leave behind. It is separated from Consume
// because Consume is keyed by state (a callback is redeeming one flow) while this
// is keyed by user (an erasure is clearing all of them).
func (s *BindFlows) PurgeUserFlows(ctx context.Context, user account.UserID) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM federation_bind_flows WHERE user_id = $1`, string(user))
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
