package postgres

import (
	"context"
	"errors"
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

// TestDeviceDeadlinesAreJudgedByTheClockThatWroteThem is the device-authorization
// half of the policy above: the poll throttle's interval, the approval's
// expires_at predicate and its auth_time stamp are all process-side facts, so
// the store clock decides them (P2-32; the memory backend already did).
//
// The same skew fixture applies, with the premise asserted for each deadline:
// the database's own clock calls the device code expired while the writer
// still considers it live, so each check below is discriminating.
func TestDeviceDeadlinesAreJudgedByTheClockThatWroteThem(t *testing.T) {
	const skew = -2 * time.Hour
	storeClock := func() time.Time { return time.Now().Add(skew).UTC() }

	db := openTestDBWith(t, DefaultPoolOptions(), WithClock(storeClock))
	ctx := context.Background()
	oidc, _, _ := oidcFixtureOn(t, db)

	// The deadline is written from the store clock, so the writer still
	// considers the code live for an hour; the database calls it two hours
	// gone. `expires` is what StoreDeviceAuthorization's caller passes, so it
	// must be a store-clock value for the fixture to mean anything.
	expires := storeClock().Add(time.Hour)
	if err := oidc.StoreDeviceAuthorization(ctx, "oidc-device", "clock-device-code", "CLCK-2345",
		expires, []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if !premiseExpiredByTheDatabase(t, db,
		`SELECT expires_at < now() FROM oidc_devices WHERE client_id = 'oidc-device'`) {
		t.Fatal("the fixture is not skewed: the database still considers the device code live")
	}

	// --- the poll: the throttle's interval must be judged by the store clock ---
	st, err := oidc.GetDeviceAuthorizatonState(ctx, "oidc-device", "clock-device-code")
	if err != nil {
		t.Fatalf("a first poll of a code its writer still considers live was refused: %v", err)
	}
	if st.Done || st.Denied {
		t.Fatalf("the poll answered a decision nobody made: %+v", st)
	}
	// A second poll inside the advertised interval is slow_down, and that
	// judgement too must come from the store clock: the last_poll the first
	// poll wrote is a store-clock value, so the database's now() would call it
	// long past due and answer a second poll instead of throttling it.
	if _, err := oidc.GetDeviceAuthorizatonState(ctx, "oidc-device", "clock-device-code"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second poll inside the interval = %v, want slow_down (context.DeadlineExceeded)", err)
	}

	// --- the approval: expires_at judged by the writer's clock, auth_time
	// stamped with it ---
	if err := oidc.approveDevice(ctx, "CLCK-2345", "usr_1", []string{"account.id"}); err != nil {
		t.Fatalf("approving a code its writer still considers live was refused: %v", err)
	}
	st, err = oidc.DeviceByUserCode(ctx, "CLCK-2345")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Done {
		t.Fatal("the approval did not land")
	}
	// The stamp is taken from the store clock inside approveDevice, so it lands
	// within a second of this read on either side. Testing `!AuthTime.Before(want)`
	// against a clock read AFTER the call would reject every correct stamp (it is
	// always a few microseconds older than the read); only the two-clock failure,
	// a stamp two hours ahead, is what this window has to reject.
	if want := storeClock(); st.AuthTime.Sub(want) > time.Second || want.Sub(st.AuthTime) > time.Second {
		t.Fatalf("auth_time = %s, want the store clock (%s): a database-clock stamp would run "+
			"two hours ahead of when the human actually decided", st.AuthTime, want)
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
