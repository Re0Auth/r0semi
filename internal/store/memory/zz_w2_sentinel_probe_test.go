package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/internal/authorization"
)

// TestW2AuthRequestByIDMissAndDeadlineCarryTheSentinel pins S04-7 at the source:
// the consent screen's reader is the only place that can tell "the engine does not
// hold this request" apart from "the store could not answer", and it has to say
// which by carrying authorization.ErrRequestExpired. Before this the by-ID read
// returned a fresh anonymous error, so the HTTP layer — which only has the sentinel
// to classify on — answered 500 for a request that was merely gone.
//
// Both ways a request stops existing are covered: never issued (or swept), and
// past its deadline. The control in the middle keeps the assertion from being
// satisfied by a read that refuses everything.
func TestW2AuthRequestByIDMissAndDeadlineCarryTheSentinel(t *testing.T) {
	clock := newTestClock()
	store := clockedStore(t, clock)
	ctx := context.Background()

	// Unknown: never issued, or already swept.
	if _, err := store.AuthRequestByID(ctx, "no-such-request"); !errors.Is(err, authorization.ErrRequestExpired) {
		t.Errorf("an unknown handle = %v, want it to wrap authorization.ErrRequestExpired (S04-7)", err)
	}

	ar, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     "cli",
		RedirectURI:  "https://app.example/cb",
		ResponseType: oidc.ResponseTypeCode,
		Scopes:       oidc.SpaceDelimitedArray{"account.id"},
		State:        "st-w2",
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	// Control: inside the TTL the handle reads, so a reader that classified every
	// error as "expired" would not pass.
	if _, err := store.AuthRequestByID(ctx, ar.GetID()); err != nil {
		t.Fatalf("AuthRequestByID inside the TTL: %v", err)
	}

	// Past the deadline the by-ID read adjudicates it itself (Z07-1), and the
	// answer must be the sentinel rather than a plain error.
	clock.Advance(31 * time.Minute)
	if _, err := store.AuthRequestByID(ctx, ar.GetID()); !errors.Is(err, authorization.ErrRequestExpired) {
		t.Errorf("a handle past its deadline = %v, want it to wrap authorization.ErrRequestExpired (S04-7)", err)
	}
}
