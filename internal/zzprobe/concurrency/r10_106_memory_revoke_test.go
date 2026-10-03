//go:build audit5

package concurrency

import (
	"context"
	"fmt"
	"testing"
	"time"

	oidc "github.com/zitadel/oidc/v3/pkg/oidc"
)

// probeAuthRequest is the minimal authorize request CreateAuthRequest accepts.
// It is a public client with no credential, i.e. what an anonymous caller sends.
func probeAuthRequest() *oidc.AuthRequest {
	return &oidc.AuthRequest{
		ClientID:     probeClientID,
		RedirectURI:  probeRedirect,
		ResponseType: oidc.ResponseTypeCode,
		Scopes:       oidc.SpaceDelimitedArray{"account.id"},
	}
}

// This file is the round-10 probe for R10-106 / R10-145 / R10-107.
//
// R10-106/R10-145: an unauthenticated POST /oauth/revoke with an arbitrary
// unknown token makes memory.OIDCStore.RevokeToken walk the ENTIRE live refresh
// map while holding the store's single mutex, then answer RFC 7009 success.
// A public client needs only its client_id, so the cost is anonymous.
//
// R10-107: the pending authorization-request and device-authorization maps have
// no population bound and no admission control. The resident set is
// arrival_rate x TTL, which per-address rate limiting does not bound.
//
// Every test below FAILS on the code as found; the assertions are the guards a
// fix must satisfy.

// r10RevokeScanPopulation is large enough that a per-entry copy of the ~224-byte
// refreshToken (oidc.go:304-322) costs several milliseconds, while small enough
// to build in a couple of seconds. The budget is a hard wall-clock bound, not a
// ratio: after the fix the call is two map misses and must be effectively free.
const (
	r10RevokeScanPopulation = 100_000
	r10RevokeScanBudget     = 3 * time.Millisecond
)

// r10PendingAuthRequestCap and r10PendingDeviceCap mirror the bounds a fix is
// expected to ship. They are hardcoded so this probe still compiles against the
// unfixed tree; a separate shipped guard (in package memory) pins the constants
// so the two cannot drift.
const (
	r10PendingAuthRequestCap = 1 << 17
	r10PendingDeviceCap      = 1 << 15
)

// TestR10UnknownPublicRevokeDoesNotScanTheWholeRefreshTable is R10-145's
// strongest presentation: no valid token, no secret, only a public client_id.
func TestR10UnknownPublicRevokeDoesNotScanTheWholeRefreshTable(t *testing.T) {
	if testing.Short() {
		t.Skip("population probe")
	}
	st := newProbeStore(t, nil)
	ctx := context.Background()

	for i := 0; i < r10RevokeScanPopulation; i++ {
		if _, _, _, err := st.CreateAccessAndRefreshTokens(ctx, tokenRequest("usr_r10", "account.id"), ""); err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
	}
	before := st.Counts()

	start := time.Now()
	if err := st.RevokeToken(ctx, "not-a-token-any-client-issued", "", probeClientID); err != nil {
		t.Fatalf("revoking an unknown token: %v", err)
	}
	elapsed := time.Since(start)

	after := st.Counts()
	if after != before {
		t.Fatalf("revoking an unknown token changed the store: %+v -> %+v", before, after)
	}
	if elapsed > r10RevokeScanBudget {
		t.Fatalf("R10-106/R10-145: an unknown token revoke held the store lock over %d refresh rows for %v "+
			"(budget %v); RevokeToken scans s.refreshTokens under s.mu at oidc.go:941 and then returns "+
			"RFC 7009 success at oidc.go:976-978", r10RevokeScanPopulation, elapsed, r10RevokeScanBudget)
	}
	t.Logf("unknown-token revoke over %d refresh rows: %v", r10RevokeScanPopulation, elapsed)
}

// TestR10ConsumedRefreshRevokeDoesNotScanTheWholeRefreshTable is R10-106's
// consumed-token presentation. It exists so a fix that special-cases only
// "unknown" strings (before the id_hash scan) still fails this probe.
func TestR10ConsumedRefreshRevokeDoesNotScanTheWholeRefreshTable(t *testing.T) {
	if testing.Short() {
		t.Skip("population probe")
	}
	st := newProbeStore(t, nil)
	ctx := context.Background()

	// One rotation plus a large resident population. The spent value is no
	// longer keyed in refreshTokens; only the id_hash scan could ever match it.
	_, spent, _, err := st.CreateAccessAndRefreshTokens(ctx, tokenRequest("usr_r10", "account.id"), "")
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	if _, _, _, err := st.CreateAccessAndRefreshTokens(ctx, tokenRequest("usr_r10", "account.id"), spent); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	for i := 0; i < r10RevokeScanPopulation; i++ {
		if _, _, _, err := st.CreateAccessAndRefreshTokens(ctx, tokenRequest("usr_r10", "account.id"), ""); err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
	}
	before := st.Counts()

	start := time.Now()
	if err := st.RevokeToken(ctx, spent, "", probeClientID); err != nil {
		t.Fatalf("revoking a consumed refresh token: %v", err)
	}
	elapsed := time.Since(start)

	if after := st.Counts(); after != before {
		t.Fatalf("revoking a consumed token changed the store: %+v -> %+v", before, after)
	}
	if elapsed > r10RevokeScanBudget {
		t.Fatalf("R10-106: revoking a consumed refresh token held the store lock over %d refresh rows for %v "+
			"(budget %v); the id_hash presentation must be resolved by an index, not by scanning",
			r10RevokeScanPopulation, elapsed, r10RevokeScanBudget)
	}
}

// TestR10PendingAuthorizationPopulationsAreBounded is R10-107's admission half
// for authorize. The cap must be enforced before the insert, under the same
// lock, and must fail closed (an error, nothing stored).
func TestR10PendingAuthorizationPopulationsAreBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("population probe")
	}
	st := newProbeStore(t, nil)
	ctx := context.Background()

	for i := 0; i < r10PendingAuthRequestCap; i++ {
		if _, err := st.CreateAuthRequest(ctx, probeAuthRequest(), "usr_r10"); err != nil {
			t.Fatalf("CreateAuthRequest %d: %v", i, err)
		}
	}
	if got := st.Counts().AuthRequests; got != r10PendingAuthRequestCap {
		t.Fatalf("setup: expected %d pending auth requests, got %d", r10PendingAuthRequestCap, got)
	}

	_, err := st.CreateAuthRequest(ctx, probeAuthRequest(), "usr_r10")
	if err == nil {
		t.Fatalf("R10-107: CreateAuthRequest accepted request %d with the pending population already at %d; "+
			"there is no admission bound, so the resident set grows as arrival_rate x TTL",
			r10PendingAuthRequestCap+1, r10PendingAuthRequestCap)
	}
	if got := st.Counts().AuthRequests; got != r10PendingAuthRequestCap {
		t.Fatalf("R10-107: a refused request was stored anyway: population %d", got)
	}
}

// TestR10DeviceAuthorizationPopulationsAreBounded is R10-107's admission half
// for the device grant.
func TestR10DeviceAuthorizationPopulationsAreBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("population probe")
	}
	st := newProbeStore(t, nil)
	ctx := context.Background()
	expires := time.Now().Add(10 * time.Minute)

	for i := 0; i < r10PendingDeviceCap; i++ {
		if err := st.StoreDeviceAuthorization(ctx, probeClientID,
			fmt.Sprintf("dev-%08d", i), fmt.Sprintf("CODE-%08d", i), expires, []string{"account.id"}); err != nil {
			t.Fatalf("StoreDeviceAuthorization %d: %v", i, err)
		}
	}
	if got := st.Counts().Devices; got != r10PendingDeviceCap {
		t.Fatalf("setup: expected %d device authorizations, got %d", r10PendingDeviceCap, got)
	}

	err := st.StoreDeviceAuthorization(ctx, probeClientID, "dev-overflow", "CODE-OVERFLOW", expires, []string{"account.id"})
	if err == nil {
		t.Fatalf("R10-107: StoreDeviceAuthorization accepted device %d with the population already at %d; "+
			"there is no admission bound", r10PendingDeviceCap+1, r10PendingDeviceCap)
	}
	if got := st.Counts().Devices; got != r10PendingDeviceCap {
		t.Fatalf("R10-107: a refused device authorization was stored anyway: population %d", got)
	}
}
