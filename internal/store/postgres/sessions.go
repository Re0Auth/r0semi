package postgres

import (
	"context"
	"errors"
	"fmt"
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

// Compile-time proof that the shape still matches scs's interfaces.
//
// CtxStore is the one that matters: scs's LoadAndSave prefers FindCtx/CommitCtx/
// DeleteCtx when the store implements them (data.go's doStoreFind and friends),
// and it hands them the request context. Implementing only Store meant every
// session read ran on context.Background() — no deadline, and no cancellation when
// the client hangs up. The plain methods stay for callers that know only Store;
// scs is not one of them.
var (
	_ scs.Store    = (*Sessions)(nil)
	_ scs.CtxStore = (*Sessions)(nil)
)

// sessionTokenHash reuses the OAuth hashing deliberately: the input has the same
// shape (32 bytes of crypto/rand) and the same reasoning applies, so a second
// implementation would only be a chance to drift.
func sessionTokenHash(token string) string { return oauth.TokenHash(token) }

// Delete implements scs.Store.
func (s *Sessions) Delete(token string) error { return s.DeleteCtx(context.Background(), token) }

// DeleteCtx implements scs.CtxStore. Deleting an absent session is not an error.
func (s *Sessions) DeleteCtx(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM sessions WHERE token_hash = $1`, sessionTokenHash(token))
	return err
}

// Find implements scs.Store.
func (s *Sessions) Find(token string) ([]byte, bool, error) {
	return s.FindCtx(context.Background(), token)
}

// FindCtx implements scs.CtxStore.
//
// scs defines an expired session as "not found", so an expired row is removed
// here rather than returned.
//
// The context is the request's, and that is the point of this method existing:
// this query runs on every browser request that carries a session cookie, and
// without a deadline it waits for a pooled connection for as long as the pool is
// saturated. The pool's statement_timeout bounds a statement, not the wait for a
// connection, so the request would park until the server's write timeout cut the
// socket — with the goroutine and the connection still held.
func (s *Sessions) FindCtx(ctx context.Context, token string) ([]byte, bool, error) {
	var (
		data   []byte
		expiry time.Time
	)
	err := s.pool.QueryRow(ctx,
		`SELECT data, expiry FROM sessions WHERE token_hash = $1`, sessionTokenHash(token)).
		Scan(&data, &expiry)
	if noRows(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !s.now().Before(expiry) {
		_ = s.DeleteCtx(ctx, token)
		return nil, false, nil
	}
	return data, true, nil
}

// Commit implements scs.Store.
func (s *Sessions) Commit(token string, data []byte, expiry time.Time) error {
	return s.CommitCtx(context.Background(), token, data, expiry)
}

// sessionCommitTimeout bounds a commit that outlives its request.
//
// The request context is deliberately detached below, and this is what keeps that
// from meaning "wait for a pooled connection forever".
const sessionCommitTimeout = 5 * time.Second

// CommitCtx implements scs.CtxStore. An existing token is overwritten.
//
// The client's cancellation is dropped here, and that is the one place in this
// store where it is. scs commits the session after the handler returns: a browser
// that navigates away in that window cancels the request context, and failing the
// write because of it would lose the session of a user who had just signed in —
// the exact case the write exists for. What is not dropped is the bound: this runs
// on its own deadline rather than the request's, so a saturated pool still fails
// fast instead of parking a goroutine with a connection it does not have.
func (s *Sessions) CommitCtx(ctx context.Context, token string, data []byte, expiry time.Time) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionCommitTimeout)
	defer cancel()

	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (token_hash, data, expiry)
		VALUES ($1, $2, $3)
		ON CONFLICT (token_hash) DO UPDATE SET
			data   = EXCLUDED.data,
			expiry = EXCLUDED.expiry`,
		sessionTokenHash(token), data, expiry)
	return err
}

// SweepExpired deletes expired rows. Find already removes the sessions it is
// asked about, so this is for the ones nobody comes back to. Each of its two
// statements contributes at most sessionSweepBatchSize rows per cycle.
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
//
// Both deletes are bounded (LIMIT) and the second runs even when the first fails,
// with the two errors joined. The orphan index rows are the state nothing else
// collects, so an unbounded first statement that hit the pool's statement_timeout
// used to return before the second one, letting orphans accumulate forever
// (Z15V-1, docs/issues/P2-medium.md). The total reported is what the cycle
// removed across both statements.
func (s *Sessions) SweepExpired(ctx context.Context) (int64, error) {
	sessionsTag, sessionsErr := s.pool.Exec(ctx, `
		DELETE FROM sessions WHERE expiry < $1
		   AND ctid IN (SELECT ctid FROM sessions WHERE expiry < $1 LIMIT $2)`,
		s.now(), sessionSweepBatchSize)

	// Deliberately not an early return on sessionsErr: see the method comment.
	// The anti-join selects the orphan ctids through the created_at index
	// (0019_session_subjects_created_at_idx) and deletes at most a batch of them.
	subjectsTag, subjectsErr := s.pool.Exec(ctx, `
		DELETE FROM session_subjects si
		 WHERE si.created_at < now() - $1::interval
		   AND si.ctid IN (
		       SELECT orphan.ctid FROM session_subjects orphan
		        WHERE orphan.created_at < now() - $1::interval
		          AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.token_hash = orphan.token_hash)
		        LIMIT $2)`,
		sessionIndexGrace, sessionSweepBatchSize)

	removed := sessionsTag.RowsAffected() + subjectsTag.RowsAffected()
	if sessionsErr != nil {
		sessionsErr = fmt.Errorf("postgres: sweep sessions: %w", sessionsErr)
	}
	if subjectsErr != nil {
		subjectsErr = fmt.Errorf("postgres: sweep session_subjects: %w", subjectsErr)
	}
	return removed, errors.Join(sessionsErr, subjectsErr)
}

// sessionSweepBatchSize bounds one cycle of the session sweep, one statement at a
// time, so a backlog is worked off over the following ticks rather than in a
// single unbounded delete (Z15V-1, docs/issues/P2-medium.md).
const sessionSweepBatchSize = 1000

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
