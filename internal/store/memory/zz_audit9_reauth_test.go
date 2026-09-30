package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
)

// AUDIT9 / S02-1 (fixed) — a freshness-bound authorization request is refused when
// it completes without a satisfying authentication.
//
// The store used to substitute the consent-decision clock for auth_time whenever
// `prompt=login` or an elapsed `max_age` was present, so the id_token advertised a
// fresh authentication that never happened. It now keeps a recorded time only when
// that time satisfies the bound, and refuses (ErrReauthenticationRequired) when it
// does not.
func TestAudit9CompleteLoginRefusesAnUnsatisfiedFreshnessBound(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	zero := uint(0) // prompt=login is normalized to max_age=0 by the library

	ar, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:            "cli",
		RedirectURI:         "https://app.example/cb",
		ResponseType:        oidc.ResponseTypeCode,
		Scopes:              []string{"account.id"},
		CodeChallenge:       "challenge-1234567890",
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
		Prompt:              []string{oidc.PromptLogin},
		MaxAge:              &zero,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	// A session authenticated an hour ago does not satisfy "authenticate now".
	stale := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	if err := store.SetAuthTime(ctx, ar.GetID(), stale); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteLogin(ctx, ar.GetID(), "usr_1", []string{"account.id"}); !errors.Is(err, oidcstore.ErrReauthenticationRequired) {
		t.Fatalf("CompleteLogin with a stale session = %v, want ErrReauthenticationRequired", err)
	}
	if done, err := store.AuthRequestByID(ctx, ar.GetID()); err != nil || done.Done() {
		t.Fatalf("the refused request was completed anyway: done=%v err=%v", done != nil && done.Done(), err)
	}

	// A real (re-)authentication moments ago satisfies it, and the recorded time is
	// kept rather than replaced by the decision clock.
	fresh := time.Now().Add(-5 * time.Second).UTC().Truncate(time.Second)
	if err := store.SetAuthTime(ctx, ar.GetID(), fresh); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteLogin(ctx, ar.GetID(), "usr_1", []string{"account.id"}); err != nil {
		t.Fatalf("CompleteLogin after a fresh authentication: %v", err)
	}
	done, err := store.AuthRequestByID(ctx, ar.GetID())
	if err != nil {
		t.Fatal(err)
	}
	if !done.GetAuthTime().Equal(fresh) {
		t.Errorf("auth_time = %s, want the recorded authentication %s", done.GetAuthTime(), fresh)
	}
}
