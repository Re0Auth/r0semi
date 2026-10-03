//go:build audit5

package concurrency

import (
	"context"
	"errors"
	"testing"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

// R10-59: revocation and issuance are not ordered across the resolve step.
//
// The exchange's resolve (AuthRequestByCode) consumes the code and the auth
// request before the library calls CreateAccessAndRefreshTokens. A Kill Switch
// that commits in that window has no source row left to delete, so the
// revocation reports success and then a live pair is minted behind it. The HTTP
// boundary now carries the observed revocation generation from resolve to mint,
// and the mint refuses a pair minted across a revocation.
//
// The probe enters the window deterministically: it drives the two calls in
// sequence, with the revocation in between, rather than racing goroutines.

func TestR1059AMintAfterAKillSwitchInTheConsumeWindowIsRefused(t *testing.T) {
	store := newProbeStore(t, nil)
	ctx := oidcstore.WithRevocationEpochs(context.Background())

	ar, err := store.CreateAuthRequest(ctx, probeAuthRequest(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteLogin(ctx, ar.GetID(), "usr_target", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAuthCode(ctx, ar.GetID(), "code-r1059"); err != nil {
		t.Fatal(err)
	}

	// The exchange's resolve step: the code and the request are consumed here.
	tokenReq, err := store.AuthRequestByCode(ctx, "code-r1059")
	if err != nil {
		t.Fatalf("AuthRequestByCode: %v", err)
	}

	// The Kill Switch runs between the consume and the mint.
	if _, err := store.RevokeTokens(ctx, oauth.TokenFilter{Subject: "usr_target"}); err != nil {
		t.Fatalf("RevokeTokens: %v", err)
	}

	if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, tokenReq, ""); !errors.Is(err, memory.ErrGrantRevokedInFlight) {
		t.Fatalf("R10-59: a mint that ran after a successful Kill Switch returned err=%v, and the "+
			"credential it wrote is live even though the revocation deleted every row it could see", err)
	}
	if got := store.Counts(); got.AccessTokens != 0 || got.RefreshTokens != 0 {
		t.Fatalf("R10-59: the refused mint still stored a pair: %+v", got)
	}
}

// TestR1059AMintWithoutARevocationStillSucceeds is the control: the guard must
// not refuse an ordinary exchange, and the same context carrier must not make
// the store unusable.
func TestR1059AMintWithoutARevocationStillSucceeds(t *testing.T) {
	store := newProbeStore(t, nil)
	ctx := oidcstore.WithRevocationEpochs(context.Background())

	ar, err := store.CreateAuthRequest(ctx, probeAuthRequest(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteLogin(ctx, ar.GetID(), "usr_ok", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAuthCode(ctx, ar.GetID(), "code-r1059-ok"); err != nil {
		t.Fatal(err)
	}
	tokenReq, err := store.AuthRequestByCode(ctx, "code-r1059-ok")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, tokenReq, ""); err != nil {
		t.Fatalf("an ordinary exchange was refused: %v", err)
	}
	if got := store.Counts(); got.AccessTokens != 1 || got.RefreshTokens != 1 {
		t.Fatalf("an ordinary exchange did not store its pair: %+v", got)
	}
}
