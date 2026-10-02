package postgres

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/authorization"
)

// TestW2AuthRequestByIDSourceCarriesTheSentinel is the database-free half of the
// Postgres S04-7 check. The by-ID read is the one the consent screen performs, and
// it is the only read whose "no row" means "this pending request is gone": the
// query carries the deadline predicate, so a miss is the caller's situation and
// must carry authorization.ErrRequestExpired. Every other error — a pool that
// could not answer, a row that failed to decode — must stay itself, or an outage
// is reported to the browser as a dead link.
//
// It reads the shipped source because the alternative is a live database, and the
// behavioural twin below skips without one; this guard cannot silently skip.
func TestW2AuthRequestByIDSourceCarriesTheSentinel(t *testing.T) {
	body := sourceOf(t, "oidc.go")

	// AuthRequestByID itself owns the deadline predicate.
	byID := oidcStoreMethod(t, body, "AuthRequestByID")
	if !strings.Contains(byID, "expires_at > $2") {
		t.Fatalf("AuthRequestByID no longer adjudicates the deadline; the guard is reading the wrong method")
	}

	// scanAuthRequest is the by-ID read's implementation; the miss is classified
	// there, and only there.
	scan := receiverMethod(t, body, "oidc.go", "scanAuthRequest")
	flat := flatten(scan)
	if !strings.Contains(flat, "if noRows(err) {") {
		t.Fatal("scanAuthRequest does not classify pgx.ErrNoRows: a miss and an outage are indistinguishable")
	}
	if !strings.Contains(flat, "authorization.ErrRequestExpired") {
		t.Error("scanAuthRequest does not carry authorization.ErrRequestExpired for the unknown/expired case, " +
			"so the HTTP layer answers a real expired consent link as a 500 (S04-7)")
	}

	// The query error and the non-noRows collect error must keep their cause, not
	// the sentinel.
	for _, marker := range []string{"postgres: auth request: %w"} {
		if !strings.Contains(flat, marker) {
			t.Errorf("scanAuthRequest no longer wraps the store's own failure with %q, so an outage would be "+
				"reported as an expired request (S04-7)", marker)
		}
	}
}

// TestW2PostgresAuthRequestByIDMissIsTheSentinel is the behavioural twin: it needs
// a database and skips without TEST_DATABASE_URL, like the rest of the integration
// tests. The control read proves the store still serves a live handle, so the
// assertion is not satisfied by a store that refuses everything.
func TestW2PostgresAuthRequestByIDMissIsTheSentinel(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping Postgres integration test")
	}
	store, _, ctx := oidcFixture(t)

	if _, err := store.AuthRequestByID(ctx, "no-such-request"); !errors.Is(err, authorization.ErrRequestExpired) {
		t.Errorf("an unknown handle = %v, want it to wrap authorization.ErrRequestExpired (S04-7)", err)
	}

	ar := newAuthRequest(t, ctx, store)
	if _, err := store.AuthRequestByID(ctx, ar.GetID()); err != nil {
		t.Fatalf("AuthRequestByID inside the TTL: %v", err)
	}

	// Age the row past its deadline directly: the store clock is real.
	if _, err := store.pool.Exec(ctx,
		`UPDATE oidc_auth_requests SET expires_at = now() - interval '1 minute' WHERE id = $1`,
		ar.GetID()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthRequestByID(ctx, ar.GetID()); !errors.Is(err, authorization.ErrRequestExpired) {
		t.Errorf("a handle past its deadline = %v, want it to wrap authorization.ErrRequestExpired (S04-7)", err)
	}
}
