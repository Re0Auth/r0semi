package postgres

import (
	"context"
	"errors"
	"strings"
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
type Sessions struct {
	pool *pgxpool.Pool
	// now is the clock this store judges expiry by. scs computes the expiry it
	// hands Commit from its own clock, so the value is a Go-clock timestamp and
	// must be judged by one: comparing it against the database's now() (which is
	// what SweepExpired used to do) expires sessions at a time that depends on the
	// skew between two machines — early, when the database's clock is ahead.
	// Never nil; set by DB.Sessions.
	now func() time.Time
}

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
	if !s.now().Before(expiry) {
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
//
// `expiry` is judged by this process's clock, the same one scs wrote it with (see
// the field comment); the index rows below are judged by the database, because
// their `created_at` is written by the database's own DEFAULT.
//
// The index rows it collects are aged by sessionIndexGrace. They have to be: an
// index row is written during SignIn, but scs commits the session row only when
// the response is written, so for the length of one request a live session has no
// row. Sweeping that window deleted the only record of which account the session
// belonged to, and nothing rewrote it — a later subject Kill Switch then missed a
// live session while the sweep looked complete.
func (s *Sessions) SweepExpired(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expiry < $1`, s.now())
	if err != nil {
		return 0, err
	}
	if _, err := s.pool.Exec(ctx, `
		DELETE FROM session_subjects si
		 WHERE NOT EXISTS (SELECT 1 FROM sessions s WHERE s.token_hash = si.token_hash)
		   AND si.created_at < now() - $1::interval`, sessionIndexGrace); err != nil {
		return tag.RowsAffected(), err
	}
	return tag.RowsAffected(), nil
}

// sessionIndexGrace is how long an index row may be missing its session row before
// the sweep treats it as an orphan.
//
// It has to exceed the longest possible gap between SignIn writing the index and
// scs committing the session row — one request — by a wide margin, because being
// wrong in the other direction silently drops a live session from the account's
// revocable set.
const sessionIndexGrace = "1 hour"

// RevokeAllSessions deletes every session, signing everyone out. It is the session
// half of the Kill Switch. Returns how many sessions were removed.
func (s *Sessions) RevokeAllSessions(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions`)
	if err != nil {
		return 0, err
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM session_subjects`); err != nil {
		return tag.RowsAffected(), err
	}
	return tag.RowsAffected(), nil
}

// RevokeSubjectSessions deletes every session belonging to one account. It needs
// the subject index: a session cookie carries no subject, and the store cannot
// read the account out of an encoded payload.
func (s *Sessions) RevokeSubjectSessions(ctx context.Context, subject string) (int64, error) {
	if strings.TrimSpace(subject) == "" {
		return 0, errors.New("postgres: subject is required")
	}
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM sessions
		 WHERE token_hash IN (SELECT token_hash FROM session_subjects WHERE subject = $1)`, subject)
	if err != nil {
		return 0, err
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM session_subjects WHERE subject = $1`, subject); err != nil {
		return tag.RowsAffected(), err
	}
	return tag.RowsAffected(), nil
}

// Remember implements auth.SessionIndex. It records which account a session token
// belongs to, so the Kill Switch can reach that account's sessions later.
func (s *Sessions) Remember(ctx context.Context, token, subject string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO session_subjects (token_hash, subject)
		VALUES ($1, $2)
		ON CONFLICT (token_hash) DO UPDATE SET subject = EXCLUDED.subject`,
		sessionTokenHash(token), subject)
	return err
}

// Forget implements auth.SessionIndex.
func (s *Sessions) Forget(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM session_subjects WHERE token_hash = $1`, sessionTokenHash(token))
	return err
}
