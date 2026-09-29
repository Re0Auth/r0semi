//go:build audit6

// Zone-01 findings on the device flow: expiry of an approved code, and client
// authentication at both halves of RFC 8628.
package z01protocolauth

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// 01-4 · An approved device authorization past its expires_at is still
// redeemable. Both stores' "done" branch of GetDeviceAuthorizatonState consumes
// and returns the record with NO expiry predicate:
//
//	internal/store/memory/oidc.go   — `if d.done && !d.denied { delete…; return st }`
//	internal/store/postgres/oidc.go — `DELETE … WHERE device_code_hash=$1 AND client_id=$2
//	                                  AND done = true AND denied = false` (no expires_at)
//
// and the library checks `state.Done` BEFORE `time.Now().After(state.Expires)`
// (pkg/op/device.go CheckDeviceAuthorizationState), so an approved record past
// its TTL still mints tokens. The only reaper is the sweep (memory: every 5
// minutes plus on every new device authorization; postgres: every 15 minutes),
// whose own comment claims "an expired row is one a lookup already refuses" —
// which this branch disproves. RFC 8628 §3.2: expires_in is the lifetime of the
// device_code AND the user_code.
//
// The probe drives the real memory store (the same object the composition root
// builds) with its injectable clock: approve while live, advance the clock past
// expiry, then ask for the poll-time state.
func TestProbeApprovedDeviceCodePastItsExpiryIsStillRedeemable(t *testing.T) {
	clock := newClock()
	e := newPlane(t, planeOptions{now: clock})

	ctx := context.Background()
	const (
		client   = "z01-device-client"
		devCode  = "device-code-value-z01"
		userCode = "BCDF-GHJK"
	)
	expires := clock.Now().Add(2 * time.Minute)
	if err := e.store.StoreDeviceAuthorization(ctx, client, devCode, userCode, expires,
		[]string{"openid", "account.id"}); err != nil {
		t.Fatal(err)
	}

	// The user approves through the same store call the verification route's
	// decision makes (DecideDeviceAuthorization), while the code is live.
	if err := e.store.DecideDeviceAuthorization(ctx, userCode, "usr_z01", true, nil, nil); err != nil {
		t.Fatalf("approval: %v", err)
	}

	// Control first, while unexpired: the poll-time state is redeemable.
	st, err := e.store.GetDeviceAuthorizatonState(ctx, client, devCode)
	if err != nil {
		t.Fatalf("unexpired poll-time state: %v", err)
	}
	if !st.Done {
		t.Fatalf("unexpired approved state not Done: %+v", st)
	}

	// Now the same shape, past its expires_at. A fresh one is needed because
	// the read above consumed it (that part is correct single-use behaviour).
	expires = clock.Now().Add(2 * time.Minute)
	const (
		devCode2  = "device-code-value-z01-second"
		userCode2 = "BCDF-GHJL"
	)
	if err := e.store.StoreDeviceAuthorization(ctx, client, devCode2, userCode2, expires,
		[]string{"openid", "account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := e.store.DecideDeviceAuthorization(ctx, userCode2, "usr_z01", true, nil, nil); err != nil {
		t.Fatalf("approval: %v", err)
	}

	clock.Advance(3 * time.Minute) // past the 2-minute expiry

	st, err = e.store.GetDeviceAuthorizatonState(ctx, client, devCode2)
	if err == nil && st != nil && st.Done && !st.Denied {
		t.Errorf("an approved device authorization PAST its expires_at is still redeemable "+
			"(state %+v): the store's done branch carries no expiry predicate and the library checks "+
			"Done before Expires, so the code mints tokens after its advertised lifetime until the "+
			"sweep reaps it (memory: 5 min, postgres: 15 min)", st)
	} else {
		t.Logf("the expired approved code was refused: %v", err)
	}

	// Control: a PENDING record past expiry is still refused the way the sweep
	// comment describes, so only the done branch is the gap.
	const (
		devCode3  = "device-code-value-z01-third"
		userCode3 = "BCDF-GHJM"
	)
	if err := e.store.StoreDeviceAuthorization(ctx, client, devCode3, userCode3,
		clock.Now().Add(2*time.Minute), []string{"openid", "account.id"}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(3 * time.Minute)
	if st, err := e.store.GetDeviceAuthorizatonState(ctx, client, devCode3); err == nil && st != nil {
		t.Logf("pending-past-expiry state: %+v (the library answers expired_token from st.Expires)", st)
	}
}

// 01-5a · RFC 8628 §3.1: "The client authentication requirements of [RFC 6749
// §3.2.1] apply to requests on this endpoint" — a confidential client MUST
// authenticate at the device authorization endpoint. Re0Auth's pre-flight
// resolves the client from an unauthenticated form field, and the library's
// ParseDeviceCodeRequest reports the form client_id without authenticating it:
// an anonymous caller can mint a device authorization naming any confidential
// client. The payoff stops at the poll (which does require Basic auth), but
// the phishing surface is a real client's registered name on the
// verification page.
func TestProbeConfidentialClientCanStartADeviceFlowUnauthenticated(t *testing.T) {
	e := newPlane(t, planeOptions{})

	// No Authorization header, no client_secret: only the form client_id.
	resp, raw := e.postForm(t, "/oauth/device_authorization",
		url.Values{"client_id": {e.webID}, "scope": {"openid account.id"}}, "", "")
	if resp.StatusCode == http.StatusOK {
		out := decodeJSON(t, raw)
		t.Errorf("an anonymous request minted a device authorization AS the confidential client "+
			"(device_code %q…, user_code %q): RFC 8628 §3.1 requires a confidential client to "+
			"authenticate at this endpoint, and the verification page will present this client's "+
			"registered name to whoever follows the user_code",
			truncate(out["device_code"]), out["user_code"])
	} else {
		t.Logf("unauthenticated confidential device start answered %d %s", resp.StatusCode, raw)
	}
}

// 01-5b · The device grant's poll only accepts HTTP Basic client
// authentication. The library's ClientIDFromRequest counts Basic (or a JWT
// assertion) as authentication only, and deviceAccessToken refuses a
// confidential client whose `clientAuthenticated` bit is false — a form secret
// is never even read. The token endpoint's discovery advertises
// client_secret_post, and that method genuinely works on the code and refresh
// grants of the same endpoint; only the device branch rejects it. This is the
// same shape as the fixed P2-23 (introspection advertised client_secret_post
// and only accepted Basic).
//
// Additionally the branch order burns the grant: CheckDeviceAuthorizationState
// consumes the approved record BEFORE the client-auth check, so a poll with
// the wrong method consumes the code while answering 401.
func TestProbeDeviceGrantPollRefusesAdvertisedClientAuthMethod(t *testing.T) {
	e := newPlane(t, planeOptions{})

	// Two codes: the first poll (client_secret_post) will consume its record
	// even while answering 401, so the control needs a fresh one.
	devA, userA := e.deviceAuth(t, e.webID, e.webID, e.webSec, []string{"openid", "account.id"})
	e.approveDevice(t, userA)

	resp, body, raw := e.pollDevice(t, devA, "", "", url.Values{
		"client_id":     {e.webID},
		"client_secret": {e.webSec},
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("the device grant poll refused the token endpoint's advertised auth method: "+
			"client_secret_post answered %d %s (discovery's token_endpoint_auth_methods_supported "+
			"lists it; the code and refresh grants of the same endpoint accept it)", resp.StatusCode, raw)
	} else {
		t.Logf("client_secret_post poll worked: %v", body)
	}

	// The 401 above consumed the approved record — show the burn, then run the
	// Basic control on a fresh code.
	resp2, _, raw2 := e.pollDevice(t, devA, e.webID, e.webSec, nil)
	t.Logf("re-polling the code after the refused method: %d %s (single-use or burned by the 401)",
		resp2.StatusCode, raw2)

	devB, userB := e.deviceAuth(t, e.webID, e.webID, e.webSec, []string{"openid", "account.id"})
	e.approveDevice(t, userB)
	resp3, _, raw3 := e.pollDevice(t, devB, e.webID, e.webSec, nil)
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("Basic-auth control poll = %d %s — the flow itself is broken, the probe above proved nothing",
			resp3.StatusCode, raw3)
	}
}

// helper for the truncate above (keeps the log line readable).
func truncate(v any) string {
	s, _ := v.(string)
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
