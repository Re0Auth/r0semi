package postgres

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// sessionDeleteTemplateRE captures a backquoted SQL literal that begins (anywhere
// in it) with DELETE FROM. Sessions.SweepExpired builds each of its two statements
// from one such literal.
var sessionDeleteTemplateRE = regexp.MustCompile("`([^`]*DELETE FROM[^`]*)`")

// sessionSweepBody returns the source of Sessions.SweepExpired, delimited the way
// the audit7 z15verify probe delimits it, so a LIMIT elsewhere in the file cannot
// satisfy the guard and an unrelated statement cannot be counted.
func sessionSweepBody(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("sessions.go")
	if err != nil {
		t.Fatalf("cannot read sessions.go: %v", err)
	}
	src := string(b)
	start := strings.Index(src, "func (s *Sessions) SweepExpired")
	if start < 0 {
		t.Fatal("Sessions.SweepExpired not found in sessions.go; the guard reads the wrong construct")
	}
	body := src[start:]
	if end := strings.Index(body[len("func"):], "\nfunc "); end >= 0 {
		body = body[:len("func")+end]
	}
	return body
}

// TestSessionsSweepStatementsAreBoundedAndBothRun is the database-free half of
// Z15V-1's fix.
//
// TestSweepSparesAFreshIndexRowAndCollectsAnAgedOne proves the statements work on
// a handful of rows; it cannot see that either is unbounded, nor that a failure of
// the first used to return before the second. The second is the one that removes
// orphan session_subjects rows, which nothing else collects, so on Postgres an
// unbounded first statement that hit the pool's statement_timeout let those rows
// accumulate forever (Z15V-1, docs/issues/P2-medium.md).
func TestSessionsSweepStatementsAreBoundedAndBothRun(t *testing.T) {
	body := sessionSweepBody(t)

	stmts := sessionDeleteTemplateRE.FindAllStringSubmatch(body, -1)
	if len(stmts) != 2 {
		t.Fatalf("found %d DELETE statements in Sessions.SweepExpired, want 2; the guard reads the wrong construct",
			len(stmts))
	}
	for i, m := range stmts {
		if !strings.Contains(strings.ToUpper(m[1]), "LIMIT") {
			t.Errorf("Sessions.SweepExpired statement %d carries no LIMIT: %q. An unbounded delete can outlive "+
				"the pool's statement_timeout, so one backlog cycle never makes bounded progress (Z15V-1)",
				i+1, strings.TrimSpace(m[1]))
		}
	}

	// The second statement must not run only when the first succeeded: that early
	// return is how orphan index rows accumulated. Exactly one return, after both
	// Execs, is the structural form of "the second always runs".
	if returns := regexp.MustCompile(`(?m)^[ \t]*return\b`).FindAllString(body, -1); len(returns) != 1 {
		t.Errorf("Sessions.SweepExpired has %d returns, want one at the end: an early return can skip the "+
			"orphan-collecting statement (Z15V-1)", len(returns))
	}
	if got := strings.Count(body, "s.pool.Exec"); got != 2 {
		t.Errorf("Sessions.SweepExpired issues %d statements, want 2", got)
	}
	if lastExec, lastReturn := strings.LastIndex(body, "s.pool.Exec"), strings.LastIndex(body, "return"); lastExec < 0 || lastReturn < lastExec {
		t.Error("Sessions.SweepExpired returns before its second statement; the orphan-collecting statement " +
			"is skippable (Z15V-1)")
	}
	if !strings.Contains(body, "errors.Join") {
		t.Error("Sessions.SweepExpired does not combine both statements' errors: a first failure would hide " +
			"the second instead of reporting both (Z15V-1)")
	}
}

// TestSessionsSweepIsBoundedAndItsSecondStatementAlwaysRuns is the database-backed
// half of Z15V-1's fix.
//
// The first case plants more than one batch of expired sessions plus an aged
// orphan index row and asserts that one cycle removes exactly the session batch,
// leaves the rest for the next tick, and still collects the orphan. The second
// case holds a row lock on the only expired session so the sessions DELETE hits
// the pool's statement_timeout: the sweep must return that error and still collect
// the orphan, which is the statement that used to be skipped.
func TestSessionsSweepIsBoundedAndItsSecondStatementAlwaysRuns(t *testing.T) {
	t.Run("one cycle is bounded and still collects the orphan", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		store := db.Sessions()

		const beyond = 9
		expired := int(sessionSweepBatchSize) + beyond
		plantExpiredSessions(t, db, ctx, expired, time.Now().Add(-time.Hour))
		plantAgedOrphan(t, db, ctx, "z15v-orphan")

		removed, err := store.SweepExpired(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// The session batch plus the single orphan the second statement collects.
		if want := int64(sessionSweepBatchSize) + 1; removed != want {
			t.Fatalf("one cycle removed %d rows, want the session batch plus the orphan (%d)", removed, want)
		}
		if got := countSweptRows(t, db, `SELECT count(*) FROM sessions`); got != beyond {
			t.Fatalf("%d expired sessions remain after one cycle, want %d", got, beyond)
		}
		if got := countSweptRows(t, db,
			`SELECT count(*) FROM session_subjects WHERE token_hash = 'z15v-orphan'`); got != 0 {
			t.Fatal("the aged orphan survived the cycle; the second statement did not collect it")
		}

		// The next cycle continues where the first stopped.
		removed, err = store.SweepExpired(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if removed != beyond {
			t.Fatalf("second cycle removed %d rows, want the remaining %d", removed, beyond)
		}
	})

	t.Run("the second statement runs when the first fails", func(t *testing.T) {
		db := openTestDBWith(t, PoolOptions{StatementTimeout: 250 * time.Millisecond})
		ctx := context.Background()
		store := db.Sessions()

		if _, err := db.pool.Exec(ctx, `
			INSERT INTO sessions (token_hash, data, expiry)
			VALUES ('z15v-locked', '\x00'::bytea, $1)`, time.Now().Add(-time.Hour)); err != nil {
			t.Fatalf("plant expired session: %v", err)
		}
		plantAgedOrphan(t, db, ctx, "z15v-orphan")

		// Hold a row lock on the only expired session: the sweep's first statement
		// blocks on it and hits the 250ms statement_timeout, while the orphan
		// statement reads `sessions` under MVCC and succeeds.
		tx, err := db.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx,
			`SELECT 1 FROM sessions WHERE token_hash = 'z15v-locked' FOR UPDATE`); err != nil {
			t.Fatalf("lock the expired session: %v", err)
		}

		removed, err := store.SweepExpired(ctx)
		if err == nil {
			t.Fatal("the first statement did not fail: the row lock did not make the sessions delete time out, " +
				"so this case proves nothing")
		}
		if removed != 1 {
			t.Fatalf("removed = %d with the first statement failing, want the 1 orphan the second still collects",
				removed)
		}
		if got := countSweptRows(t, db,
			`SELECT count(*) FROM session_subjects WHERE token_hash = 'z15v-orphan'`); got != 0 {
			t.Fatal("the orphan survived a cycle whose first statement failed: the second statement was " +
				"skipped (Z15V-1)")
		}
	})
}

// plantExpiredSessions inserts n already-expired session rows in one statement.
func plantExpiredSessions(t *testing.T, db *DB, ctx context.Context, n int, expiry time.Time) {
	t.Helper()
	if _, err := db.pool.Exec(ctx, `
		INSERT INTO sessions (token_hash, data, expiry)
		SELECT 'z15v-' || i::text, '\x00'::bytea, $1
		  FROM generate_series(1, $2) AS i`, expiry, n); err != nil {
		t.Fatalf("plant %d expired sessions: %v", n, err)
	}
}

// plantAgedOrphan inserts a session_subjects row with no session row, aged past
// sessionIndexGrace so the sweep treats it as a genuine orphan.
func plantAgedOrphan(t *testing.T, db *DB, ctx context.Context, token string) {
	t.Helper()
	if _, err := db.pool.Exec(ctx, `
		INSERT INTO session_subjects (token_hash, subject, created_at)
		VALUES ($1, 'z15v-subject', now() - interval '2 hours')`, token); err != nil {
		t.Fatalf("plant aged orphan %q: %v", token, err)
	}
}
