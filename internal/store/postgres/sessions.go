package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/jackc/pgx/v5"
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
//
// A delete marks the row rather than removing it (R10-96). scs commits a session
// after the handler returns, so a request that loaded this session before the
// delete would otherwise re-create it with an unconditional upsert. The marker is
// the conflict target that makes CommitCtx's upsert lose; the payload is blanked
// because the session is over. The row itself, with its deadline, is removed by
// the sweep.
func (s *Sessions) DeleteCtx(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE sessions SET invalidated_at = $2, data = '\x'::bytea
		 WHERE token_hash = $1 AND invalidated_at IS NULL`,
		sessionTokenHash(token), s.now())
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
		`SELECT data, expiry FROM sessions WHERE token_hash = $1 AND invalidated_at IS NULL`, sessionTokenHash(token)).
		Scan(&data, &expiry)
	if noRows(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !s.now().Before(expiry) {
		// Housekeeping, not invalidation: a lapsed row is removed outright, like
		// the sweep does. It is not a marker, and leaving it would keep a dead row
		// for the account's whole lifetime.
		_, _ = s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1 AND expiry <= $2`,
			sessionTokenHash(token), s.now())
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
			expiry = EXCLUDED.expiry
		WHERE sessions.invalidated_at IS NULL`,
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

// deleteTableBatched removes every row of one table, one bounded statement at a
// time, on the caller's transaction.
//
// The Kill Switch's deletes are unbounded ("every session"), and a single
// statement over a large table can be cancelled by the pool's statement_timeout
// halfway through — leaving the operator with an error and the sessions alive
// (S03-10). Each statement here carries ASC LIMIT, exactly like SweepExpired's,
// so the sweep of a backlog is a series of statements that each fit the bound.
// The table name is a compile-time constant at both call sites, never request
// input.
func deleteTableBatched(ctx context.Context, tx pgx.Tx, table string) (int64, error) {
	var removed int64
	for {
		tag, err := tx.Exec(ctx,
			`DELETE FROM `+table+` WHERE ctid IN (SELECT ctid FROM `+table+` LIMIT $1)`,
			sessionSweepBatchSize)
		if err != nil {
			return removed, err
		}
		n := tag.RowsAffected()
		removed += n
		if n < sessionSweepBatchSize {
			return removed, nil
		}
	}
}

// invalidateTableBatched marks every live row of one table as deleted, one
// bounded statement at a time, on the caller's transaction. It is
// deleteTableBatched's tombstone-preserving sibling: the Kill Switch must make
// sessions unreachable without removing the conflict target that an in-flight
// scs commit would otherwise re-create (R10-96).
//
// The table name is a compile-time constant at both call sites, never request
// input, and the deadline that retires the markers is the row's existing expiry,
// which the sweep already removes.
func invalidateTableBatched(ctx context.Context, tx pgx.Tx, table string, now time.Time) (int64, error) {
	var marked int64
	for {
		// Same Sprintf-with-compile-time-constant shape as the dated sweep: the
		// table name is never request input.
		tag, err := tx.Exec(ctx, fmt.Sprintf(`
			UPDATE %s SET invalidated_at = $1, data = '\x'::bytea
			 WHERE invalidated_at IS NULL
			   AND ctid IN (SELECT ctid FROM %s WHERE invalidated_at IS NULL LIMIT $2)`,
			table, table),
			now, sessionSweepBatchSize)
		if err != nil {
			return marked, err
		}
		n := tag.RowsAffected()
		marked += n
		if n < sessionSweepBatchSize {
			return marked, nil
		}
	}
}

// RevokeAllSessions invalidates every session, signing everyone out. It is the
// session half of the Kill Switch. Returns how many sessions were invalidated.
//
// The session rows are marked rather than deleted (R10-96): an in-flight request
// that loaded a session before this call commits after it, and an unconditional
// upsert would re-create the row. Both statements run in one transaction and in
// bounded batches: the session row and its subject index row are two halves of one
// revocable session, and a partial application that reported a count is not a
// state a retry can distinguish from success. The count is zero when any statement
// fails, because the rollback leaves nothing removed (S03-10, S09-8).
func (s *Sessions) RevokeAllSessions(ctx context.Context) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	removed, err := invalidateTableBatched(ctx, tx, "sessions", s.now())
	if err != nil {
		return 0, err
	}
	if _, err := deleteTableBatched(ctx, tx, "session_subjects"); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return removed, nil
}

// RevokeSubjectSessions invalidates every session belonging to one account. It
// needs the subject index: a session cookie carries no subject, and the store
// cannot read the account out of an encoded payload.
//
// The session rows are marked, not deleted (R10-96): a request that loaded one of
// them before this call commits after it, and an unconditional upsert would both
// re-create the row and leave it absent from the index this method just cleared —
// a revived session no later per-subject sweep could reach. The index rows are
// still deleted: they are the mapping, not the session.
//
// Both statements share one transaction for the same reason RevokeAllSessions'
// do: an index row left behind after its session was removed is an orphan the
// sweep has to age out, and a session removed without its index row is one the
// next Kill Switch cannot reach (S09-8).
func (s *Sessions) RevokeSubjectSessions(ctx context.Context, subject string) (int64, error) {
	if strings.TrimSpace(subject) == "" {
		return 0, errors.New("postgres: subject is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		UPDATE sessions SET invalidated_at = $2, data = '\x'::bytea
		 WHERE invalidated_at IS NULL
		   AND token_hash IN (SELECT token_hash FROM session_subjects WHERE subject = $1)`,
		subject, s.now())
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM session_subjects WHERE subject = $1`, subject); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
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
