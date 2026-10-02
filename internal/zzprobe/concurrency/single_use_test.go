//go:build audit5

package concurrency

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

// --- Single-use semantics under a real goroutine race ---
//
// The existing pins (internal/store/memory/oidc_test.go's
// TestAuthorizationCodeIsSingleUse / TestRefreshTokenRotationIsSingleUse, and
// internal/httpapi's device-code pins) write the interleaving out by hand. That is
// the right shape for a defect that lives between two lock acquisitions, but it
// cannot show whether the store's *lock scope* is what makes the claim atomic —
// i.e. whether the judgment and the write really happen under one acquisition when
// two goroutines run at once.
//
// These probes race them for real, with a barrier so the goroutines enter the
// store together, and assert "exactly one winner" rather than "the second call
// fails".

// race runs n copies of fn at once and returns how many reported success.
func race(n int, fn func() bool) (wins int32) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start // barrier: every goroutine is inside the store's window at once
			if fn() {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	return wins
}

// An authorization code is claimed by the lookup itself, so exactly one of N
// concurrent exchanges may win.
func TestAuthorizationCodeIsSingleUseUnderAGoroutineRace(t *testing.T) {
	st := newProbeStore(t, nil)
	ctx := context.Background()
	ar, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID: probeClientID, RedirectURI: probeRedirect,
		ResponseType: oidc.ResponseTypeCode, Scopes: []string{"account.id"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteLogin(ctx, ar.GetID(), "usr_1", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveAuthCode(ctx, ar.GetID(), "code-under-race"); err != nil {
		t.Fatal(err)
	}

	const n = 16
	wins := race(n, func() bool {
		_, err := st.AuthRequestByCode(ctx, "code-under-race")
		return err == nil
	})
	if wins != 1 {
		t.Errorf("%d of %d concurrent exchanges of one authorization code succeeded, want exactly 1", wins, n)
	}
	// Anti-vacuity: the code really was there to be claimed.
	if _, err := st.AuthRequestByCode(ctx, "code-under-race"); err == nil {
		t.Error("the code was still redeemable after the race; the probe may not have reached the claim")
	}
}

// Two consent submissions for the same pending request mint two codes for one
// request. Only one may be redeemable, whichever order the exchanges land in.
func TestASecondCodeForOneAuthRequestIsNotASecondGrant(t *testing.T) {
	st := newProbeStore(t, nil)
	ctx := context.Background()
	ar, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID: probeClientID, RedirectURI: probeRedirect,
		ResponseType: oidc.ResponseTypeCode, Scopes: []string{"account.id"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteLogin(ctx, ar.GetID(), "usr_1", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	// A double-click on the consent screen.
	if err := st.SaveAuthCode(ctx, ar.GetID(), "code-first"); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveAuthCode(ctx, ar.GetID(), "code-second"); err != nil {
		t.Fatal(err)
	}

	const n = 8
	codes := []string{"code-first", "code-second"}
	wins := race(n, func() bool {
		// Both codes are presented, over and over, by both halves of the race.
		for _, c := range codes {
			if _, err := st.AuthRequestByCode(ctx, c); err == nil {
				return true
			}
		}
		return false
	})
	if wins != 1 {
		t.Errorf("%d of %d concurrent exchanges succeeded, want exactly 1: a second code for one authorization request must not be a second grant", wins, n)
	}
}

// Rotation is a claim: N concurrent refreshes of the same token may produce
// exactly one new generation, and every other caller must be told its token was
// spent rather than handed a second one.
func TestRefreshRotationIsSingleUseUnderAGoroutineRace(t *testing.T) {
	st := newProbeStore(t, nil)
	ctx := context.Background()
	req := &oidcstore.AuthRequest{ClientID: probeClientID, Subject: "usr_1", Scopes: []string{"account.id"}}
	_, refresh, _, err := st.CreateAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatal(err)
	}
	// One read, held by every goroutine: the property under test is whether the
	// claim on the presented token and the write of its replacement happen under a
	// single lock acquisition, not whether two reads can both succeed.
	held, err := st.TokenRequestByRefreshToken(ctx, refresh)
	if err != nil {
		t.Fatal(err)
	}

	const n = 16
	var spent int32
	wins := race(n, func() bool {
		_, _, _, err := st.CreateAccessAndRefreshTokens(ctx, held, refresh)
		if errors.Is(err, memory.ErrRefreshTokenSpent) {
			atomic.AddInt32(&spent, 1)
			return false
		}
		if err != nil {
			t.Errorf("rotation failed for a reason other than a spent token: %v", err)
			return false
		}
		return true
	})
	if wins != 1 {
		t.Errorf("%d of %d concurrent rotations of one refresh token succeeded, want exactly 1", wins, n)
	}
	if int(spent) != n-1 {
		t.Errorf("%d of %d losers were told the token was spent, want %d", spent, n, n-1)
	}
}

// A device code is consumed by the Done read, so exactly one of N concurrent polls
// may see the approval — the other N-1 must find nothing to consume. This extends
// the C3-2 pins from "the second poll finds nothing" to "no two polls can both
// mint", which is the property that makes the consumption a claim.
func TestDeviceCodeApprovalIsConsumedExactlyOnceUnderAGoroutineRace(t *testing.T) {
	st := newProbeStore(t, nil)
	ctx := context.Background()
	if err := st.StoreDeviceAuthorization(ctx, probeClientID, "device-code-race", "RACE-CODE",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := st.DecideDeviceAuthorization(ctx, "RACE-CODE", "usr_1", true, nil, nil); err != nil {
		t.Fatal("the approval was refused; the probe never reached the consumption path")
	}

	const n = 16
	var done, missing int32
	race(n, func() bool {
		state, err := st.GetDeviceAuthorizatonState(ctx, probeClientID, "device-code-race")
		if err != nil {
			atomic.AddInt32(&missing, 1)
			return false
		}
		if state.Done && state.Subject != "usr_1" {
			t.Errorf("the consumed state carried subject %q, want usr_1", state.Subject)
		}
		if state.Done {
			atomic.AddInt32(&done, 1)
		}
		return true
	})
	if done != 1 {
		t.Errorf("%d of %d concurrent polls saw Done, want exactly 1", done, n)
	}
	if done+missing != n {
		t.Errorf("done+missing = %d+%d, want %d", done, missing, n)
	}
}

// Two approvals of the same device code: at most one may land, and whichever one
// does must be the one whose subject the token will carry.
func TestConcurrentDeviceApprovalsProduceOneApprover(t *testing.T) {
	st := newProbeStore(t, nil)
	ctx := context.Background()
	if err := st.StoreDeviceAuthorization(ctx, probeClientID, "device-code-approve", "APPR-CODE",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	subjects := []string{"usr_a", "usr_b"}
	var ok int32
	wins := race(2, func() bool {
		// Both goroutines try both subjects, so the write order is a race.
		for _, s := range subjects {
			if err := st.DecideDeviceAuthorization(ctx, "APPR-CODE", s, true, nil, nil); err == nil {
				atomic.AddInt32(&ok, 1)
				return true
			}
		}
		return false
	})
	if wins > 1 {
		t.Errorf("%d approvals of one device code succeeded, want at most 1", wins)
	}
	if ok == 0 {
		t.Fatal("no approval succeeded; the probe measured nothing")
	}
	// The state the library will read carries the approver's own subject.
	state, err := st.DeviceByUserCode(ctx, "APPR-CODE")
	if err != nil {
		t.Fatal(err)
	}
	if state.Subject != "usr_a" && state.Subject != "usr_b" {
		t.Errorf("the approved state carries subject %q, which is not an approver", state.Subject)
	}
}

// Revocation is idempotent under concurrency: N simultaneous Kill Switches over
// the same subject must leave nothing revocable behind, and must not corrupt the
// subject indexes they mutate while ranging them.
func TestConcurrentRevocationsLeaveNothingBehind(t *testing.T) {
	st := newProbeStore(t, nil)
	ctx := context.Background()
	req := &oidcstore.AuthRequest{ClientID: probeClientID, Subject: "usr_1", Scopes: []string{"account.id"}}
	for i := 0; i < 8; i++ {
		if _, _, _, err := st.CreateAccessAndRefreshTokens(ctx, req, ""); err != nil {
			t.Fatal(err)
		}
	}
	if got := st.Counts().Records(); got == 0 {
		t.Fatal("nothing was minted; the probe measured nothing")
	}

	race(8, func() bool {
		_, err := st.RevokeTokens(ctx, oauth.TokenFilter{})
		return err == nil
	})

	if c := st.Counts(); c.AccessTokens != 0 || c.RefreshTokens != 0 {
		t.Errorf("after concurrent revocation the store still holds %d access and %d refresh tokens",
			c.AccessTokens, c.RefreshTokens)
	}
	if got, err := st.Grants(ctx, "usr_1"); err != nil || len(got) != 0 {
		t.Errorf("Grants after revocation = %v (err %v), want none", got, err)
	}
}
