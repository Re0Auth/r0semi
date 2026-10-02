//go:build audit6

// Adversarial verification of the z01/z02 high-severity claims 1–5:
//
//  1. prompt=login / max_age are ignored (no re-authentication, stale auth_time)
//     — FALSIFIED by S02-1; the probes are regression guards now.
//  2. an approved device_code past expires_at is still redeemable.
//  3. an anonymous request can start a device flow as a confidential client.
//  4. the device grant's poll refuses the advertised client_secret_post while
//     the same endpoint accepts it for authorization_code / refresh_token.
//  5. a refreshed id_token drops the nonce.
//
// Claims 6–8 (refresh replay, the revocation liveness oracle, the
// percent-encoded introspection guard bypass) live in z02_probe_test.go; the
// last is also FALSIFIED and kept as a guard.
package zverify

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
)

// ---------------------------------------------------------------------------
// 1 · prompt=login / max_age
// ---------------------------------------------------------------------------

// TestV01PromptLoginCompletesOnTheStaleSession was the falsification attempt for
// "prompt=login and max_age are silently ignored, no re-authentication, stale
// auth_time". S02-1 fixed it, so the attempt now comes out FALSIFIED and the
// test stands as a regression guard under its original name.
//
// What it measures:
//   - the OP accepts the request (or answers login_required through the
//     redirect, the other permitted way);
//   - a two-hour-old authentication cannot complete it:
//     CompleteLogin returns oidcstore.ErrReauthenticationRequired and leaves the
//     request undecided, so no id_token can advertise the old session (or a
//     fabricated decision clock) as a fresh authentication;
//   - a real re-authentication completes it, and the id_token carries exactly
//     that recorded time.
func TestV01PromptLoginCompletesOnTheStaleSession(t *testing.T) {
	clock := newVClock()
	e := newVEnv(t, clock, nil)

	// The browser signed in two hours ago. In production cmd/re0auth's login hook
	// passes sessions.AuthenticatedAt to SetAuthTime; this is that value.
	signedInAt := clock.Now().Add(-2 * time.Hour)

	for name, extra := range map[string]map[string]string{
		"prompt=login": {"prompt": "login"},
		"max_age=0":    {"max_age": "0"},
		"max_age=1":    {"max_age": "1"},
	} {
		t.Run(name, func(t *testing.T) {
			id, resp, raw := e.authorize(t, e.webID, []string{"openid", "account.id"}, extra)
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("%s was refused outright (%d: %s) — the finding would be vacuous", name, resp.StatusCode, raw)
			}
			loc := resp.Header.Get("Location")
			if strings.Contains(loc, "error=") {
				t.Logf("FALSIFIED for %s: the OP answered with an error redirect (%s)", name, loc)
				return
			}
			if id == "" {
				t.Fatalf("%s did not start the interactive flow: %s", name, loc)
			}

			// The stale session must not complete the request.
			if err := e.completeLogin(t, id, "usr_vfy", []string{"openid", "account.id"}, signedInAt); !errors.Is(err, oidcstore.ErrReauthenticationRequired) {
				t.Fatalf("%s: completing on a %.0f-minute-old session = %v, want "+
					"oidcstore.ErrReauthenticationRequired; the freshness request was ignored",
					name, time.Since(signedInAt).Minutes(), err)
			}
			if req, err := e.store.AuthRequestByID(context.Background(), id); err != nil || req.Done() {
				t.Fatalf("%s: the refused completion left the request decided: done=%v err=%v",
					name, req != nil && req.Done(), err)
			}

			// A real re-authentication satisfies it, and the id_token carries that
			// recorded time rather than the decision clock.
			fresh := clock.Now().Add(-5 * time.Second)
			tokens := e.approveAndExchange(t, id, "usr_vfy", e.webID, e.webSec,
				[]string{"openid", "account.id"}, fresh)
			if tokens.IDToken == "" {
				t.Fatalf("%s issued no id_token", name)
			}
			claims := idTokenPayload(t, tokens.IDToken)
			authTime, ok := claims["auth_time"].(float64)
			if !ok {
				t.Fatalf("%s: id_token carries no numeric auth_time: %v", name, claims)
			}
			got := time.Unix(int64(authTime), 0).UTC()
			if got.Sub(fresh) < -time.Minute || got.Sub(fresh) > time.Minute {
				t.Errorf("%s: id_token auth_time = %s, want the recorded re-authentication %s", name, got, fresh)
			}
			t.Logf("%s: the two-hour-old session was refused and the fresh authentication produced auth_time=%s",
				name, got)
		})
	}
}

// TestV01MaxAgeIsNotStoredAnywhere was written for WHY the claim held at the
// storage boundary: nothing on the auth request could carry the freshness
// requirement forward. S02-1 reversed that — oidcstore.AuthRequest now carries
// Prompt and MaxAge across the boundary — so the test now pins the requirement
// being stored, under its original name.
func TestV01MaxAgeIsNotStoredAnywhere(t *testing.T) {
	clock := newVClock()
	e := newVEnv(t, clock, nil)

	id, _, _ := e.authorize(t, e.webID, []string{"openid", "account.id"}, map[string]string{
		"prompt": "login", "max_age": "0",
	})
	if id == "" {
		t.Fatal("no pending auth request")
	}
	req, err := e.store.AuthRequestByID(context.Background(), id)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	// The login hook records the session's auth_time later, so at this point the
	// request has no recorded authentication — that is what lets the boundary
	// judge whether the session must be sent through the provider.
	if got := req.GetAuthTime(); !got.IsZero() {
		t.Fatalf("a fresh request already carries auth_time %v; the probe's premise is stale", got)
	}
	// The requirement itself IS carried now: the library normalized
	// prompt=login to max_age=0 (ValidateAuthReqPrompt), and the store keeps the
	// bound so CompleteLogin can refuse a session that does not satisfy it.
	ar, ok := req.(*oidcstore.AuthRequest)
	if !ok {
		t.Fatalf("the store returned %T, not *oidcstore.AuthRequest; the storage shape changed", req)
	}
	if ar.MaxAge == nil || *ar.MaxAge != 0 {
		t.Errorf("stored MaxAge = %v, want the normalized 0 (prompt=login ⇒ max_age=0)", ar.MaxAge)
	}
	if !slices.Contains(ar.Prompt, "login") {
		t.Errorf("stored Prompt = %v, want it to contain login", ar.Prompt)
	}
	t.Logf("pending request after prompt=login&max_age=0 carries MaxAge=%d, Prompt=%v (S02-1)", *ar.MaxAge, ar.Prompt)
}

// ---------------------------------------------------------------------------
// 2 · device code past expires_at
// ---------------------------------------------------------------------------

// TestV02ApprovedDeviceCodePastExpiryStillMintsTokens is the end-to-end
// falsification attempt for "an approved device_code past expires_at is still
// redeemable". The store's clock is moved, not slept on, so the test is exact.
func TestV02ApprovedDeviceCodePastExpiryStillMintsTokens(t *testing.T) {
	clock := newVClock()
	e := newVEnv(t, clock, nil)
	ctx := context.Background()

	const lifetime = 10 * time.Minute
	expires := clock.Now().Add(lifetime)

	if err := e.store.StoreDeviceAuthorization(ctx, e.pubID, "vfy-device-code", "BCDF-GHJK", expires,
		[]string{"openid", "account.id"}); err != nil {
		t.Fatalf("StoreDeviceAuthorization: %v", err)
	}
	if err := e.store.DecideDeviceAuthorization(ctx, "BCDF-GHJK", "usr_vfy", true, nil, nil); err != nil {
		t.Fatalf("DecideDeviceAuthorization: %v", err)
	}

	// Step past the advertised lifetime.
	clock.Advance(lifetime + time.Minute)

	resp, raw := e.devicePoll(t, "vfy-device-code", e.pubID, "", false)
	if resp.StatusCode != http.StatusOK {
		t.Logf("FALSIFIED: the approved code past its expires_at was refused (%d: %s)", resp.StatusCode, raw)
		return
	}
	tokens := vTokens(t, raw)
	if tokens.AccessToken == "" {
		t.Fatalf("200 without an access token: %s", raw)
	}
	refresh := ""
	if tokens.RefreshToken != "" {
		refresh = "and a refresh token"
	}
	t.Errorf("CONFIRMED: an approved device authorization was redeemed %.0f minutes AFTER its expires_at "+
		"and minted an access token %s — the advertised expires_in does not bound the device_code's "+
		"redemption (access=%s…, scope=%q)",
		(clock.Now().Sub(expires)).Minutes(), refresh, tokens.AccessToken[:8], tokens.Scope)
}

// TestV02PendingDeviceCodePastExpiryIsRefused is the contrast that isolates the
// gap to the DONE branch: an unapproved record past expiry is still refused.
func TestV02PendingDeviceCodePastExpiryIsRefused(t *testing.T) {
	clock := newVClock()
	e := newVEnv(t, clock, nil)
	ctx := context.Background()

	expires := clock.Now().Add(10 * time.Minute)
	if err := e.store.StoreDeviceAuthorization(ctx, e.pubID, "vfy-pending-code", "BCDF-GHJL", expires,
		[]string{"openid", "account.id"}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(11 * time.Minute)

	resp, raw := e.devicePoll(t, "vfy-pending-code", e.pubID, "", false)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a PENDING code past expiry was redeemed: %s", raw)
	}
	t.Logf("control holds: pending-past-expiry = %d %s", resp.StatusCode, raw)
}

// ---------------------------------------------------------------------------
// 3 · anonymous device authorization as a confidential client
// ---------------------------------------------------------------------------

// TestV03AnonymousDeviceStartAsConfidentialClient attempts to falsify
// "POST /oauth/device_authorization does not require confidential client
// authentication". The falsifier is any non-200 for a request that carries only
// the form client_id of a CONFIDENTIAL client and no secret.
func TestV03AnonymousDeviceStartAsConfidentialClient(t *testing.T) {
	clock := newVClock()
	e := newVEnv(t, clock, nil)

	// No Authorization header, no client_secret: only the form client_id.
	resp, raw := e.deviceStart(t, e.webID, "", []string{"openid", "account.id"})
	if resp.StatusCode != http.StatusOK {
		t.Logf("FALSIFIED: the anonymous device start was refused (%d: %s)", resp.StatusCode, raw)
		return
	}
	body := vJSON(t, raw)
	t.Errorf("CONFIRMED: an unauthenticated request naming the CONFIDENTIAL client %q minted a device "+
		"authorization (user_code=%v, expires_in=%v) — RFC 8628 §3.1 applies RFC 6749 §3.2.1's client "+
		"authentication to this endpoint",
		e.webID, body["user_code"], body["expires_in"])
}

// ---------------------------------------------------------------------------
// 4 · the poll refuses client_secret_post
// ---------------------------------------------------------------------------

// TestV04DevicePollRejectsClientSecretPostWhileCodeAndRefreshAcceptIt.
//
// The claim has two halves and both must hold for it to be CONFIRMED:
//   - the same endpoint accepts client_secret_post on authorization_code and on
//     refresh_token (so the refusal is device-branch specific);
//   - the device poll with client_secret_post is refused.
//
// The "burn" half (the refused poll consumed the record) is measured too.
func TestV04DevicePollRejectsClientSecretPostWhileCodeAndRefreshAcceptIt(t *testing.T) {
	clock := newVClock()
	e := newVEnv(t, clock, nil)
	ctx := context.Background()

	// --- control: client_secret_post works for authorization_code ---
	verifier, _ := vPKCE()
	scopes := []string{"account.id", "offline_access"}
	id, _, _ := e.authorize(t, e.webID, scopes, nil)
	code := e.approveAndCallback(t, id, "usr_vfy", scopes, time.Time{})
	resp, raw := e.post(t, "/oauth/token", map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  vRedirect,
		"code_verifier": verifier,
		"client_id":     e.webID,
		"client_secret": e.webSec,
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("client_secret_post does not work for authorization_code either (%d: %s) — "+
			"the claim's contrast is false", resp.StatusCode, raw)
	}
	first := vTokens(t, raw)
	if first.RefreshToken == "" {
		t.Fatalf("no refresh token despite offline_access: %s", raw)
	}

	// --- control: client_secret_post works for refresh_token ---
	resp, raw = e.post(t, "/oauth/token", map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": first.RefreshToken,
		"client_id":     e.webID,
		"client_secret": e.webSec,
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("client_secret_post does not work for refresh_token either (%d: %s) — "+
			"the claim's contrast is false", resp.StatusCode, raw)
	}

	// --- the device grant with the same method ---
	if err := e.store.StoreDeviceAuthorization(ctx, e.webID, "vfy-dev-post", "BCDF-GHJM",
		clock.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := e.store.DecideDeviceAuthorization(ctx, "BCDF-GHJM", "usr_vfy", true, nil, nil); err != nil {
		t.Fatal(err)
	}
	resp, raw = e.devicePoll(t, "vfy-dev-post", e.webID, e.webSec, true)
	if resp.StatusCode == http.StatusOK {
		t.Logf("FALSIFIED: the device poll ACCEPTED client_secret_post (%d)", resp.StatusCode)
		return
	}
	refusedStatus := resp.StatusCode
	refusedBody := string(raw)

	// The burn: the same (already-approved) code polled correctly afterwards.
	resp2, raw2 := e.devicePoll(t, "vfy-dev-post", e.webID, e.webSec, false)
	t.Errorf("CONFIRMED: the device grant refuses the token endpoint's own advertised "+
		"client_secret_post (poll = %d %s) while authorization_code and refresh_token on the SAME "+
		"endpoint accept it; re-polling the approved code with Basic afterwards = %d %s",
		refusedStatus, refusedBody, resp2.StatusCode, raw2)
}

// ---------------------------------------------------------------------------
// 5 · the refreshed id_token drops the nonce
// ---------------------------------------------------------------------------

// TestV05RefreshDropsTheNonce compares the nonce in the code grant's id_token
// with the nonce in the refresh grant's id_token. The claim is that only the
// first carries it (OIDC Core §12.2 asks the refresh-issued id_token to keep the
// original nonce).
func TestV05RefreshDropsTheNonce(t *testing.T) {
	clock := newVClock()
	e := newVEnv(t, clock, nil)

	first := e.codeFlow(t, e.webID, e.webSec, []string{"openid", "account.id", "offline_access"}, "usr_vfy", time.Time{})
	if first.RefreshToken == "" {
		t.Fatalf("no refresh token although offline_access was requested: %+v", first)
	}
	codeClaims := idTokenPayload(t, first.IDToken)
	if codeClaims["nonce"] != "vfy-nonce" {
		t.Fatalf("the code grant's id_token carries nonce=%v, so the probe's premise (the nonce was "+
			"requested and recorded) does not hold", codeClaims["nonce"])
	}

	resp, raw := e.refresh(t, e.webID, e.webSec, first.RefreshToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh = %d: %s", resp.StatusCode, raw)
	}
	rotated := vTokens(t, raw)
	if rotated.IDToken == "" {
		t.Fatalf("the refresh grant issued no id_token although openid was granted: %s", raw)
	}
	refreshClaims := idTokenPayload(t, rotated.IDToken)
	nonce, present := refreshClaims["nonce"]
	if !present || nonce == "" {
		t.Errorf("CONFIRMED: the refresh grant's id_token has no nonce (code grant had %q); OIDC Core "+
			"§12.2: \"its nonce Claim Value MUST be the same as that in the ID Token issued when the "+
			"original authentication occurred\" when the refresh-issued id_token is present",
			codeClaims["nonce"])
		return
	}
	if nonce != codeClaims["nonce"] {
		t.Errorf("the refresh-issued id_token carries a DIFFERENT nonce (%v vs %v)", nonce, codeClaims["nonce"])
		return
	}
	t.Logf("FALSIFIED: the refresh-issued id_token kept nonce=%v", nonce)
}
