//go:build audit6

package z04pgstore

// The device-authorization consume path's expiry check.
//
// RFC 8628 §3.5 answers expired_token for a device code past its expires_in.
// The library's CheckDeviceAuthorizationState (zitadel/oidc v3, pkg/op/device.go)
// orders its checks Denied → Done → Expires, so a state that is Done short-
// circuits BEFORE the expiry check and CreateDeviceTokenResponse mints tokens
// for it. Both of this project's stores feed that branch: neither refuses an
// approved device code that has since expired.
//
//   - Postgres: GetDeviceAuthorizatonState's claim is
//     `DELETE FROM oidc_devices WHERE device_code_hash = $1 AND client_id = $2
//     AND done = true AND denied = false RETURNING …` — no expires_at
//     predicate, in contrast with AuthRequestByCode's claim, which does check
//     (`AND expires_at > $2`).
//   - Memory: `d.done && !d.denied` → delete and return the state — same shape.
//
// The window is bounded by the sweep (15 minutes), but the code's own
// advertised lifetime is not enforced on the only path that mints.
//
// The memory half is executable here with an injected clock (the contract
// reference a database-free probe can run); the Postgres half is asserted on
// the shipped SQL text.

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

// fakeDeviceClock is a settable clock for the memory store's Now option.
type fakeDeviceClock struct{ now time.Time }

func (c *fakeDeviceClock) Now() time.Time { return c.now }

// memoryOIDCOn builds a memory OIDCStore on an injected clock. The clients and
// signer are only required to exist; nothing on the device path consults them.
func memoryOIDCOn(t *testing.T, clock *fakeDeviceClock) *memory.OIDCStore {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	c, err := oauth.NewClient("probe-device", "Device", oauth.ClientPublic, "",
		[]string{"https://device.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatalf("build probe client: %v", err)
	}
	if err := clients.Create(context.Background(), c); err != nil {
		t.Fatalf("register probe client: %v", err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   testSigner(t),
		Now:      clock.Now,
	})
	if err != nil {
		t.Fatalf("build memory store: %v", err)
	}
	return store
}

// TestAnApprovedDeviceCodeCannotBeRedeemedAfterItsExpiry is the contract half:
// a code that was approved while live, polled after its writer's clock calls it
// expired, must not be handed to the library as a consumable authorization.
//
// The store returns the state with Done=true (and consumes it), which the
// library's CheckDeviceAuthorizationState turns into a token mint because its
// Done branch runs before its expiry branch — so the test fails today.
func TestAnApprovedDeviceCodeCannotBeRedeemedAfterItsExpiry(t *testing.T) {
	clock := &fakeDeviceClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	store := memoryOIDCOn(t, clock)
	ctx := context.Background()

	const (
		clientID   = "probe-device"
		deviceCode = "probe-device-code"
		userCode   = "ABCD-EFGH"
	)
	expires := clock.now.Add(10 * time.Minute)
	if err := store.StoreDeviceAuthorization(ctx, clientID, deviceCode, userCode, expires,
		[]string{"account.id"}); err != nil {
		t.Fatalf("store device authorization: %v", err)
	}
	if err := store.DecideDeviceAuthorization(ctx, userCode, "usr_probe", true, nil, nil); err != nil {
		t.Fatalf("approve while live: %v", err)
	}

	// The premise: the code's writer now considers it expired. The approval
	// entrance refuses it in this state (that is P2-32's fix working) — which is
	// what makes the consume path's silence the inconsistency.
	clock.now = clock.now.Add(11 * time.Minute)
	if err := store.DecideDeviceAuthorization(ctx, userCode, "usr_other", true, nil, nil); err == nil {
		t.Fatal("the premise is broken: approving an expired code succeeded; the clock is not being consulted")
	}

	st, err := store.GetDeviceAuthorizatonState(ctx, clientID, deviceCode)
	if err == nil && st != nil && st.Done && !st.Denied {
		t.Fatal("an approved device authorization was handed back as consumable after its expiry: the " +
			"library checks Done BEFORE Expires (zitadel/oidc pkg/op/device.go, CheckDeviceAuthorization" +
			"State), so this state mints tokens for a code past its advertised expires_in. The claim " +
			"statement must carry the same expires_at predicate AuthRequestByCode's does — the window " +
			"today is bounded only by the 15-minute sweep, not by the code's own lifetime")
	}
	if err != nil {
		t.Logf("refusal: %v", err)
	}
}

// TestThePostgresDeviceConsumeClaimChecksExpiry is the SQL half: the shipped
// claim statement has no expires_at predicate. AuthRequestByCode's claim — the
// established shape in the same file, praised for exactly this — is the
// control the probe holds it against.
func TestThePostgresDeviceConsumeClaimChecksExpiry(t *testing.T) {
	code := stripGoComments(readShipped(t, adapterDir+"/oidc.go"))

	consume := methodBodyOf(t, code, "GetDeviceAuthorizatonState")
	claim := regexp.MustCompile(`DELETE FROM oidc_devices[\s\S]*?RETURNING`).FindString(consume)
	if claim == "" {
		t.Fatal("the device consume claim was not found; the probe is not reading the statement")
	}
	if !strings.Contains(claim, "expires_at") {
		t.Error("GetDeviceAuthorizatonState's claim DELETE has no expires_at predicate: an approved device " +
			"code stays mintable after expiry until the sweep removes the row, while the library's own " +
			"expiry check never runs (Done short-circuits before Expires). AuthRequestByCode's claim in " +
			"the same file shows the shape to copy: `AND expires_at > $n` written from the store clock")
	}

	byCode := methodBodyOf(t, code, "AuthRequestByCode")
	control := regexp.MustCompile(`DELETE FROM oidc_codes[\s\S]*?RETURNING`).FindString(byCode)
	if control == "" || !strings.Contains(control, "expires_at") {
		t.Fatal("the control is broken: AuthRequestByCode's claim no longer checks expiry, so the " +
			"comparison this probe makes is meaningless — re-read the adapter")
	}
}
