package postgres

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Re0Auth/r0semi/oauth"
)

// R10-121: a bulk revocation was one unbounded DELETE per table inside one
// transaction. The pool's statement_timeout is per STATEMENT, not per
// transaction, so on a grown table one DELETE is cancelled, the whole
// transaction rolls back, and the Kill Switch reports failure having revoked
// NOTHING — worst exactly when the tables are largest. The fix is a bounded
// ctid-batched delete that keeps the single transaction and the count.

// revokeFake is a querier whose Exec models a table with `remaining` matching
// rows, one bounded batch at a time. It refuses any statement without a LIMIT,
// which is the property under test: no single statement may be unbounded.
type revokeFake struct {
	remaining  int
	calls      int
	statements []string
}

func (f *revokeFake) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	f.calls++
	f.statements = append(f.statements, sql)
	if !strings.Contains(sql, "LIMIT") || !strings.Contains(sql, "ctid IN") {
		return pgconn.CommandTag{}, fmt.Errorf("unbounded statement: %s", sql)
	}
	n := 1000
	if f.remaining < n {
		n = f.remaining
	}
	f.remaining -= n
	return pgconn.NewCommandTag(fmt.Sprintf("DELETE %d", n)), nil
}

func (f *revokeFake) QueryRow(context.Context, string, ...any) pgx.Row { return nil }
func (f *revokeFake) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, nil
}

func TestR10121RevokeMatchingIsBoundedPerStatement(t *testing.T) {
	// 2.5 batches: the loop must run three times (1000, 1000, 500) and stop.
	const batch = 1000
	f := &revokeFake{remaining: 2*batch + batch/2}
	total, err := revokeMatching(context.Background(), f, []string{"oidc_access_tokens"}, oauth.TokenFilter{})
	if err != nil {
		t.Fatalf("R10-121: revokeMatching issued an unbounded statement or stopped early: %v", err)
	}
	if want := 2*batch + batch/2; total != want {
		t.Fatalf("revokeMatching removed %d rows, want %d", total, want)
	}
	if f.calls != 3 {
		t.Fatalf("revokeMatching issued %d statements, want 3 bounded batches", f.calls)
	}
}

func TestR10121RevokeMatchingStopsWhenTheTableIsEmpty(t *testing.T) {
	f := &revokeFake{remaining: 0}
	total, err := revokeMatching(context.Background(), f, []string{"oidc_access_tokens"}, oauth.TokenFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 || f.calls != 1 {
		t.Fatalf("an empty table took %d statements for %d rows, want 1 for 0", f.calls, total)
	}
}

// TestR10121NoBulkRevokeStatementIsUnbounded is the source guard for the paths a
// fake querier cannot reach through the concrete pool: the legacy loop, the
// pending-authorization deletes and the helper itself.
func TestR10121NoBulkRevokeStatementIsUnbounded(t *testing.T) {
	oauthSrc := stripSourceComments(sourceOf(t, "oauth.go"))
	helper := functionBody(t, oauthSrc, "func deleteMatchingBatched(")
	for _, want := range []string{"DELETE FROM", "ctid IN", "LIMIT"} {
		if !strings.Contains(helper, want) {
			t.Fatalf("R10-121: deleteMatchingBatched has no %q, so its statement is not bounded", want)
		}
	}
	for _, fn := range []string{"func revokeMatching(", "func (s *Tokens) RevokeTokens("} {
		if body := functionBody(t, oauthSrc, fn); !strings.Contains(body, "deleteMatchingBatched") {
			t.Fatalf("R10-121: %s still issues its bulk deletes unbounded", fn)
		}
	}
	oidcSrc := stripSourceComments(sourceOf(t, "oidc.go"))
	pending := functionBody(t, oidcSrc, "func revokePendingAuthorizations(")
	for _, want := range []string{"DELETE FROM oidc_auth_requests", "DELETE FROM oidc_codes", "ctid IN", "LIMIT"} {
		if !strings.Contains(pending, want) {
			t.Fatalf("R10-121: revokePendingAuthorizations has no %q, so one of its bulk deletes is unbounded", want)
		}
	}
}
