//go:build audit6

// Adversarial verification of claims 6–8 (refresh replay, the revocation
// liveness oracle, the percent-encoded introspection guard bypass).
package zverify

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 6 · a detected refresh-token replay leaves the thief's generation alive
// ---------------------------------------------------------------------------

// TestV06ReplayDetectionLeavesTheThiefsGenerationAlive replays the exact six
// steps the claim describes and then asks whether the thief can keep using the
// chain. It is CONFIRMED only if the legitimate client's replay is refused AND
// the thief's replacement still mints tokens.
func TestV06ReplayDetectionLeavesTheThiefsGenerationAlive(t *testing.T) {
	clock := newVClock()
	e := newVEnv(t, clock, nil)

	// Generation 1.
	first := e.codeFlow(t, e.webID, e.webSec,
		[]string{"account.id", "offline_access"}, "usr_vfy", time.Time{})
	gen1 := first.RefreshToken
	if gen1 == "" {
		t.Fatal("no refresh token issued, so the probe is vacuous")
	}

	// The thief rotates generation 1 first: they now hold generation 2.
	resp, raw := e.refresh(t, e.webID, e.webSec, gen1)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the thief could not rotate the stolen token: %d %s", resp.StatusCode, raw)
	}
	thiefGen2 := vTokens(t, raw).RefreshToken
	if thiefGen2 == "" || thiefGen2 == gen1 {
		t.Fatalf("no rotation: %q", thiefGen2)
	}

	// The legitimate client replays its own copy of generation 1. This refusal
	// IS the theft signal RFC 9700 §4.14.2 keys the family revocation on.
	resp, raw = e.refresh(t, e.webID, e.webSec, gen1)
	replayStatus := resp.StatusCode
	replayBody := string(raw)
	if replayStatus == http.StatusOK {
		t.Fatalf("the replayed token was ACCEPTED, so there is no detection at all to test: %s", raw)
	}
	if got := vJSON(t, raw)["error"]; got != "invalid_grant" {
		t.Fatalf("the replay was refused with %v, not invalid_grant: %s", got, raw)
	}

	// The finding: the thief's generation 2 still works.
	resp, raw = e.refresh(t, e.webID, e.webSec, thiefGen2)
	if resp.StatusCode != http.StatusOK {
		t.Logf("FALSIFIED: the thief's generation died with the detection (%d: %s)", resp.StatusCode, raw)
		return
	}
	after := vTokens(t, raw)
	if after.AccessToken == "" {
		t.Fatalf("200 without an access token: %s", raw)
	}
	t.Errorf("CONFIRMED: the replay of generation 1 was refused with %d %s, yet the thief's own "+
		"generation 2 still rotated into generation 3 and minted a live access token (%s…) — the "+
		"detection revokes nothing but the presented value", replayStatus, replayBody, after.AccessToken[:8])
}

// TestV06IsTheMissingNonceTheReasonForNoFamilyRule checks the mechanism claim
// that the replay is refused but nothing else: the store's only signal is that
// the presented value is gone. It documents (not asserts) what the store can
// know, so a future family rule is not believed to exist by accident.
func TestV06IsTheMissingNonceTheReasonForNoFamilyRule(t *testing.T) {
	clock := newVClock()
	e := newVEnv(t, clock, nil)

	tokens := e.codeFlow(t, e.webID, e.webSec, []string{"account.id", "offline_access"}, "usr_vfy", time.Time{})
	rotated, raw := e.refresh(t, e.webID, e.webSec, tokens.RefreshToken)
	if rotated.StatusCode != http.StatusOK {
		t.Fatalf("rotation = %d: %s", rotated.StatusCode, raw)
	}
	gen2 := vTokens(t, raw).RefreshToken

	// The store can still resolve the spent value's identity: TokenRequestByRefreshToken
	// answered for generation 1 only while it was live, so the replay carries no
	// family identifier at all.
	_, err := e.store.TokenRequestByRefreshToken(context.Background(), tokens.RefreshToken)
	t.Logf("TokenRequestByRefreshToken(spent generation 1) = %v; TokenRequestByRefreshToken(generation 2) succeeds=%v",
		err, func() bool { _, e2 := e.store.TokenRequestByRefreshToken(context.Background(), gen2); return e2 == nil }())
}

// ---------------------------------------------------------------------------
// 7 · /oauth/revoke as a liveness oracle
// ---------------------------------------------------------------------------

// TestV07RevocationIsALivenessOracleForForeignTokens measures the two answers
// that make the oracle: an anonymous caller naming a PUBLIC client id gets 401
// for a live token of another client and 200 for a string that is not a token.
func TestV07RevocationIsALivenessOracleForForeignTokens(t *testing.T) {
	clock := newVClock()
	e := newVEnv(t, clock, nil)

	victim := e.codeFlow(t, e.webID, e.webSec, []string{"account.id"}, "usr_vfy", time.Time{})
	if victim.AccessToken == "" {
		t.Fatal("no access token to test with")
	}

	// The caller knows only the public client id: no secret, no Basic header.
	respLive, rawLive := e.post(t, "/oauth/revoke", map[string]string{
		"token":     victim.AccessToken,
		"client_id": e.pubID,
	}, "", "")
	respUnknown, rawUnknown := e.post(t, "/oauth/revoke", map[string]string{
		"token":     "this-string-is-not-a-token",
		"client_id": e.pubID,
	}, "", "")

	t.Logf("live foreign token: %d %s", respLive.StatusCode, strings.TrimSpace(string(rawLive)))
	t.Logf("unknown string   : %d %s", respUnknown.StatusCode, strings.TrimSpace(string(rawUnknown)))

	if respLive.StatusCode == respUnknown.StatusCode {
		t.Logf("FALSIFIED: both answers are %d, so the endpoint does not distinguish them",
			respLive.StatusCode)
		return
	}
	if respLive.StatusCode != http.StatusUnauthorized || respUnknown.StatusCode != http.StatusOK {
		t.Fatalf("the answers are %d/%d, which the oracle mechanism does not predict",
			respLive.StatusCode, respUnknown.StatusCode)
	}
	// The owner can still use the token: the 401 was an ownership refusal, not a
	// revocation.
	if status, _ := e.userinfoStatus(t, victim.AccessToken); status != http.StatusOK {
		t.Errorf("the refused revocation killed the token anyway (%d)", status)
	}
	t.Errorf("CONFIRMED: an unauthenticated caller naming the public client %q gets 401 for a LIVE "+
		"foreign access token and 200 for an unknown string, so the endpoint answers \"is this string a "+
		"live token?\" — the oracle oauth/as.go's Revoke comment says it must not be",
		e.pubID)
}

// TestV07WrongSecretIsIndistinguishable pins the other half the original probe
// mentions: a wrong secret for a confidential client is also a 401, so the
// oracle does not need a public client id at all — the shape needs only an
// identity that reaches the ownership check.
func TestV07WrongSecretIsIndistinguishable(t *testing.T) {
	clock := newVClock()
	e := newVEnv(t, clock, nil)
	victim := e.codeFlow(t, e.webID, e.webSec, []string{"account.id"}, "usr_vfy", time.Time{})

	resp, raw := e.post(t, "/oauth/revoke", map[string]string{
		"token": victim.AccessToken,
	}, e.webID, "wrong-secret")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a wrong secret answered %d: %s", resp.StatusCode, raw)
	}
	t.Logf("wrong-secret refusal: %d %s (same 401 shape, different cause — the pair is not separable "+
		"from the outside except by whether the secret is right)", resp.StatusCode, strings.TrimSpace(string(raw)))
}

// ---------------------------------------------------------------------------
// 8 · percent-encoded client_id bypasses the introspection guard
// ---------------------------------------------------------------------------

// TestV08PercentEncodedClientIDBypassesTheIntrospectionGuard sends the SAME
// public client id twice to /oauth/introspect, once literally and once with one
// character percent-encoded. The library's ClientBasicAuth runs
// url.QueryUnescape on the Basic username; the project's guard
// (refuseIntrospectionByANonConfidentialClient) and its introspection filter
// read the raw string.
func TestV08PercentEncodedClientIDBypassesTheIntrospectionGuard(t *testing.T) {
	clock := newVClock()
	// The round-5 P0-6 shape: the public client is on the allowlist.
	e := newVEnv(t, clock, []string{"vfy-public"})

	// A syntactically token-shaped but worthless value: no facts to leak either
	// way, so the probe isolates the authentication half.
	const garbage = "AAAA.BBBB.CCCC.DDDD.EEEE"

	escaped := strings.Replace(e.pubID, "p", "%70", 1)
	if escaped == e.pubID {
		t.Fatalf("fixture id %q has no escapable character", e.pubID)
	}
	t.Logf("literal id %q, percent-encoded %q", e.pubID, escaped)

	plainResp, plainRaw := e.post(t, "/oauth/introspect",
		map[string]string{"token": garbage}, e.pubID, "not-a-secret")
	escResp, escRaw := e.post(t, "/oauth/introspect",
		map[string]string{"token": garbage}, escaped, "not-a-secret")

	t.Logf("literal id : %d %s", plainResp.StatusCode, strings.TrimSpace(string(plainRaw)))
	t.Logf("escaped id : %d %s", escResp.StatusCode, strings.TrimSpace(string(escRaw)))

	if escResp.StatusCode == http.StatusUnauthorized {
		t.Logf("FALSIFIED: the escaped id was refused too (%d)", escResp.StatusCode)
		return
	}
	if plainResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("control failed: the literal public id was not refused (%d)", plainResp.StatusCode)
	}
	if escResp.StatusCode != http.StatusOK {
		t.Fatalf("the escaped id answered %d, which the mechanism does not predict", escResp.StatusCode)
	}
	if active, _ := vJSON(t, escRaw)["active"].(bool); active {
		t.Errorf("the escaped caller got active=true: %s", escRaw)
	}
	t.Errorf("CONFIRMED: Basic username %q (QueryUnescape -> %q) authenticates as the PUBLIC client "+
		"while the project's non-confidential guard cannot resolve it, so the documented 401 "+
		"invalid_client is bypassable by encoding one character of the id",
		escaped, e.pubID)
}

// TestV08DataHalfStillFailsClosed is the control the original probe claims: even
// with the guard bypassed, a real foreign token is not described, because the
// introspection filter keys on the raw (escaped) id.
func TestV08DataHalfStillFailsClosed(t *testing.T) {
	clock := newVClock()
	e := newVEnv(t, clock, []string{"vfy-public"})

	tokens := e.codeFlow(t, e.webID, e.webSec,
		[]string{"account.id", "offline_access"}, "usr_vfy", time.Time{})
	escaped := strings.Replace(e.pubID, "p", "%70", 1)

	resp, raw := e.post(t, "/oauth/introspect",
		map[string]string{"token": tokens.AccessToken}, escaped, "not-a-secret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the escaped caller was refused (%d): %s", resp.StatusCode, raw)
	}
	body := vJSON(t, raw)
	if body["active"] == true {
		t.Fatalf("the escaped public client read another client's token facts: %s", raw)
	}
	if _, leaked := body["scope"]; leaked {
		t.Errorf("the response leaked scope: %s", raw)
	}
	if _, leaked := body["sub"]; leaked {
		t.Errorf("the response leaked sub: %s", raw)
	}
	t.Logf("data half holds: escaped caller on a real foreign token = 200 %s",
		strings.TrimSpace(string(raw)))
}
