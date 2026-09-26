package postgres

import (
	"context"
	"testing"
	"time"
)

// TestDeadlinesAreJudgedByTheClockThatWroteThem guards the single-clock policy:
// every deadline this package writes must be judged by the clock that wrote it,
// in SQL as well as in Go.
//
// The fixture puts the store clock two hours behind the database's, so a deadline
// written through the store is already past as far as Postgres is concerned while
// its writer still considers it live. Every block asserts that premise first — the
// database's own verdict has to differ, or the block would pass without the policy
// — and then requires the store to honour the writer. Under the previous mix (SQL
// predicates comparing against now()), each of these failed, two hours early:
// the code was refused, the session was swept, the grant vanished.
func TestDeadlinesAreJudgedByTheClockThatWroteThem(t *testing.T) {
	const skew = -2 * time.Hour
	storeClock := func() time.Time { return time.Now().Add(skew) }

	db := openTestDBWith(t, DefaultPoolOptions(), WithClock(storeClock))
	ctx := context.Background()

	// --- sessions: written by scs's clock, so judged by this one --------------
	sessions := db.Sessions()
	if err := sessions.Commit("clock-cookie", []byte("payload"), storeClock().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !premiseExpiredByTheDatabase(t, db,
		`SELECT expiry < now() FROM sessions WHERE token_hash = $1`, sessionTokenHash("clock-cookie")) {
		t.Fatal("the fixture is not skewed: the database still considers the session live")
	}
	if data, ok, err := sessions.Find("clock-cookie"); err != nil || !ok || string(data) != "payload" {
		t.Fatalf("Find refused a session its writer still considers live: ok=%v err=%v", ok, err)
	}
	if _, err := sessions.SweepExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := sessions.Find("clock-cookie"); !ok {
		t.Fatal("the sweep deleted a session its writer still considers live")
	}

	// --- the transaction sweep over the dated tables --------------------------
	if _, err := db.pool.Exec(ctx, `
		INSERT INTO oidc_access_tokens (id_hash, client_id, subject, scopes, expires_at)
		VALUES ('clock-token', 'oidc-web', 'usr_1', '{}', $1)`, storeClock().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !premiseExpiredByTheDatabase(t, db,
		`SELECT expires_at < now() FROM oidc_access_tokens WHERE id_hash = 'clock-token'`) {
		t.Fatal("the fixture is not skewed: the database still considers the token live")
	}
	removed, err := db.SweepExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 0 {
		t.Fatalf("SweepExpired removed %d row(s) their writer still considers live", removed)
	}

	// --- the read paths that judge a deadline in SQL --------------------------
	oidc, _, octx := oidcFixtureOn(t, db)

	ar := newAuthRequest(t, octx, oidc)
	if err := oidc.CompleteLogin(octx, ar.GetID(), "usr_1", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := oidc.SaveAuthCode(octx, ar.GetID(), "clock-code"); err != nil {
		t.Fatal(err)
	}
	if !premiseExpiredByTheDatabase(t, db,
		`SELECT expires_at < now() FROM oidc_codes WHERE code_hash = $1`, hashValue("clock-code")) {
		t.Fatal("the fixture is not skewed: the database still considers the code live")
	}
	if _, err := oidc.AuthRequestByCode(octx, "clock-code"); err != nil {
		t.Fatalf("a code its writer still considers live was refused: %v", err)
	}

	ar2 := newAuthRequest(t, octx, oidc)
	if err := oidc.CompleteLogin(octx, ar2.GetID(), "usr_1", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	ar2, err = oidc.AuthRequestByID(octx, ar2.GetID())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := oidc.CreateAccessAndRefreshTokens(octx, ar2, ""); err != nil {
		t.Fatal(err)
	}
	grants, err := oidc.Grants(octx, "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) == 0 {
		t.Fatal("Grants hid a grant its writer still considers live")
	}
}

// premiseExpiredByTheDatabase asserts the fixture really is skewed: the row is
// expired as far as Postgres's own clock is concerned, so a database-clock
// comparison would refuse it and every check above would be discriminating.
func premiseExpiredByTheDatabase(t *testing.T, db *DB, query string, args ...any) bool {
	t.Helper()
	var expired bool
	if err := db.pool.QueryRow(context.Background(), query, args...).Scan(&expired); err != nil {
		t.Fatalf("premise query failed: %v", err)
	}
	return expired
}
