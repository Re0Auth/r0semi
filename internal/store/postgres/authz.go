package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Re0Auth/r0semi/internal/authz"
)

// Authz implements authz.Store on Postgres.
//
// It holds no credential, and the handle id is stored as-is: the id appears in
// browser URLs and server logs by design, and the HTTP layer binds it to the
// session that created it, so hashing it here would protect nothing.
type Authz struct{ pool *pgxpool.Pool }

const authzCols = `id, client_id, client_name, redirect_uri, scopes, state,
	code_challenge, code_challenge_method, created_at, expires_at`

// Put implements authz.Store.
func (s *Authz) Put(ctx context.Context, r authz.Request) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO authz_requests (`+authzCols+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE SET
			client_id             = EXCLUDED.client_id,
			client_name           = EXCLUDED.client_name,
			redirect_uri          = EXCLUDED.redirect_uri,
			scopes                = EXCLUDED.scopes,
			state                 = EXCLUDED.state,
			code_challenge        = EXCLUDED.code_challenge,
			code_challenge_method = EXCLUDED.code_challenge_method,
			created_at            = EXCLUDED.created_at,
			expires_at            = EXCLUDED.expires_at`,
		r.ID, r.ClientID, r.ClientName, r.RedirectURI, scopeArray(r.Scopes), r.State,
		r.CodeChallenge, r.CodeChallengeMethod, r.CreatedAt, r.ExpiresAt)
	return err
}

// Get implements authz.Store. Expiry is the service's concern, so an expired
// request is still returned (once) rather than swallowed.
func (s *Authz) Get(ctx context.Context, id string) (authz.Request, error) {
	var (
		r      authz.Request
		scopes []string
	)
	err := s.pool.QueryRow(ctx, `SELECT `+authzCols+` FROM authz_requests WHERE id = $1`, id).
		Scan(&r.ID, &r.ClientID, &r.ClientName, &r.RedirectURI, &scopes, &r.State,
			&r.CodeChallenge, &r.CodeChallengeMethod, &r.CreatedAt, &r.ExpiresAt)
	if noRows(err) {
		return authz.Request{}, authz.ErrNotFound
	}
	if err != nil {
		return authz.Request{}, err
	}
	r.Scopes = scopesFrom(scopes)
	return r, nil
}

// Delete implements authz.Store. Deleting an absent handle is not an error, so
// approve/deny stay idempotent.
func (s *Authz) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM authz_requests WHERE id = $1`, id)
	return err
}

// SweepExpired deletes expired rows. The service already deletes the handles it
// is asked about, so this is for the ones the user simply abandoned.
func (s *Authz) SweepExpired(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM authz_requests WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
