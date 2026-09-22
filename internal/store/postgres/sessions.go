package postgres

import (
	"context"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Re0Auth/r0semi/oauth"
)

// Sessions implements alexedwards/scs's Store on Postgres, so a restart no
// longer signs everybody out.
//
// Rows are keyed by sha256(cookie value): a dumped table is not a set of usable
// session cookies.
type Sessions struct{ pool *pgxpool.Pool }

// Compile-time proof that the shape still matches scs's interface.
var _ scs.Store = (*Sessions)(nil)

// sessionTokenHash reuses the OAuth hashing deliberately: the input has the same
// shape (32 bytes of crypto/rand) and the same reasoning applies, so a second
// implementation would only be a chance to drift.
func sessionTokenHash(token string) string { return oauth.TokenHash(token) }

// Delete implements scs.Store. Deleting an absent session is not an error.
func (s *Sessions) Delete(token string) error {
	_, err := s.pool.Exec(context.Background(),
		`DELETE FROM sessions WHERE token_hash = $1`, sessionTokenHash(token))
	return err
}

// Find implements scs.Store.
//
// scs defines an expired session as "not found", so an expired row is removed
// here rather than returned. Note the interface carries no context: scs does not
// pass one, so these calls use context.Background.
func (s *Sessions) Find(token string) ([]byte, bool, error) {
	var (
		data   []byte
		expiry time.Time
	)
	err := s.pool.QueryRow(context.Background(),
		`SELECT data, expiry FROM sessions WHERE token_hash = $1`, sessionTokenHash(token)).
		Scan(&data, &expiry)
	if noRows(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !time.Now().Before(expiry) {
		_ = s.Delete(token)
		return nil, false, nil
	}
	return data, true, nil
}

// Commit implements scs.Store. An existing token is overwritten.
func (s *Sessions) Commit(token string, data []byte, expiry time.Time) error {
	_, err := s.pool.Exec(context.Background(), `
		INSERT INTO sessions (token_hash, data, expiry)
		VALUES ($1, $2, $3)
		ON CONFLICT (token_hash) DO UPDATE SET
			data   = EXCLUDED.data,
			expiry = EXCLUDED.expiry`,
		sessionTokenHash(token), data, expiry)
	return err
}

// SweepExpired deletes expired rows. Find already removes the sessions it is
// asked about, so this is for the ones nobody comes back to.
func (s *Sessions) SweepExpired(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expiry < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RevokeAllSessions deletes every session, signing everyone out. It is the session
// half of the Kill Switch. Returns how many were removed.
func (s *Sessions) RevokeAllSessions(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
