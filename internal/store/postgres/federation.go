package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/federation"
)

// Bindings implements federation.BindingStore on Postgres.
//
// It stores metadata only. The upstream token is not here and cannot be: the
// table has no such column, and federation.Binding has no such field.
type Bindings struct{ pool *pgxpool.Pool }

// Get implements federation.BindingStore.
func (s *Bindings) Get(ctx context.Context, user account.UserID, game, source string) (federation.Binding, error) {
	binding, err := scanBinding(s.pool.QueryRow(ctx, `
		SELECT user_id, game, source, token_type, expiry, has_refresh, version
		  FROM federation_bindings
		 WHERE user_id = $1 AND game = $2 AND source = $3`,
		string(user), game, source))
	if noRows(err) {
		return federation.Binding{}, federation.ErrNotBound
	}
	if err != nil {
		return federation.Binding{}, err
	}
	return binding, nil
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
		string(b.User), b.Game, b.Source, b.TokenType, nullTime(b.Expiry), b.HasRefresh, int64(b.Version))
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
		b.HasRefresh, int64(b.Version), int64(expectedVersion))
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

func (s *Bindings) queryBindings(ctx context.Context, query string, args ...any) ([]federation.Binding, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]federation.Binding, 0, 4)
	for rows.Next() {
		binding, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, binding)
	}
	return out, rows.Err()
}

// rowScanner is the slice of pgx shared by a Row and the current row of Rows.
type rowScanner interface{ Scan(dest ...any) error }

func scanBinding(row rowScanner) (federation.Binding, error) {
	var (
		binding federation.Binding
		userID  string
		expiry  *time.Time
		// version is scanned through int64 on purpose. The stored value is a
		// random uint64 written as int64(v); scanning the bigint straight into a
		// uint64 leaves the conversion to the driver's codec, which is not a
		// promise this project wants to depend on. Reading the signed value and
		// converting back is bit-exact and driver-agnostic.
		version int64
	)
	if err := row.Scan(&userID, &binding.Game, &binding.Source, &binding.TokenType,
		&expiry, &binding.HasRefresh, &version); err != nil {
		return federation.Binding{}, err
	}
	binding.User = account.UserID(userID)
	binding.Version = uint64(version)
	if expiry != nil {
		binding.Expiry = *expiry
	}
	return binding, nil
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

// Consume implements federation.BindFlowStore.
func (s *BindFlows) Consume(ctx context.Context, state string) (federation.BindFlow, error) {
	var (
		flow   federation.BindFlow
		userID string
	)
	err := s.pool.QueryRow(ctx, `
		DELETE FROM federation_bind_flows
		 WHERE state = $1
		RETURNING id, user_id, game, source, pkce_verifier, return_to, expires_at`, state).
		Scan(&flow.ID, &userID, &flow.Game, &flow.Source, &flow.Verifier, &flow.ReturnTo, &flow.ExpiresAt)
	if noRows(err) {
		return federation.BindFlow{}, federation.ErrUnknownBind
	}
	if err != nil {
		return federation.BindFlow{}, err
	}
	flow.State = state
	flow.User = account.UserID(userID)
	return flow, nil
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
