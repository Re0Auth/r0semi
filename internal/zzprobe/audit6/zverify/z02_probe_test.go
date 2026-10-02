//go:build audit6

// Adversarial verification of claims 6–8 (refresh replay, the revocation
// liveness oracle, the percent-encoded introspection guard bypass).
package zverify

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/store/memory"
)

// ---------------------------------------------------------------------------
// 6 · a detected refresh-token replay revokes the thief's generation
// ---------------------------------------------------------------------------

// TestV06ReplayDetectionRevokesTheThiefsGeneration replays the exact six steps
// the original finding described, but as the fixed contract: RFC 9700 §4.14.2
// makes the legitimate client's replay of a rotated token the theft signal, so
// the whole family — the thief's replacement included — must be revoked. It FAILS
// if the thief's generation survives.
func TestV06ReplayDetectionRevokesTheThiefsGeneration(t *testing.T) {
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
	thiefGen2 := vTokens(t, raw)
	if thiefGen2.RefreshToken == "" || thiefGen2.RefreshToken == gen1 {
		t.Fatalf("no rotation: %q", thiefGen2.RefreshToken)
	}

	// The legitimate client replays its own copy of generation 1. This refusal
	// IS the theft signal RFC 9700 §4.14.2 keys the family revocation on.
	resp, raw = e.refresh(t, e.webID, e.webSec, gen1)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("the replayed token was ACCEPTED, so there is no detection at all to test: %s", raw)
	}
	if got := vJSON(t, raw)["error"]; got != "invalid_grant" {
		t.Fatalf("the replay was refused with %v, not invalid_grant: %s", got, raw)
	}

	// The fix: the thief's generation 2 must die with the detection — both the
	// refresh token it holds and the access token minted with it.
	resp, raw = e.refresh(t, e.webID, e.webSec, thiefGen2.RefreshToken)
	if resp.StatusCode == http.StatusOK {
		after := vTokens(t, raw)
		t.Fatalf("the thief's generation survived the detected replay: it rotated again and minted "+
			"access token %s… — the family was not revoked (RFC 9700 §4.14.2)", after.AccessToken)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("the thief's replacement refusal = %d, want 400: %s", resp.StatusCode, raw)
	}
	if got := vJSON(t, raw)["error"]; got != "invalid_grant" {
		t.Fatalf("the thief's replacement error = %v, want invalid_grant: %s", got, raw)
	}
	if status, _ := e.userinfoStatus(t, thiefGen2.AccessToken); status == http.StatusOK {
		t.Errorf("the thief's rotated access token is still active after the family revocation (userinfo = %d)", status)
	}
}

// TestV06TheTombstoneCarriesTheFamily records the mechanism the family rule keys
// on. The spent value is not simply forgotten: rotation leaves a tombstone keyed
// by the spent token's hash that carries its family id, so a later replay of that
// hash resolves to a chain the store can revoke — which is exactly what the read
// path (TokenRequestByRefreshToken) does, the only method a refresh grant reaches
// before the stale token would be refused.
func TestV06TheTombstoneCarriesTheFamily(t *testing.T) {
	clock := newVClock()
	e := newVEnv(t, clock, nil)

	tokens := e.codeFlow(t, e.webID, e.webSec, []string{"account.id", "offline_access"}, "usr_vfy", time.Time{})
	rotated, raw := e.refresh(t, e.webID, e.webSec, tokens.RefreshToken)
	if rotated.StatusCode != http.StatusOK {
		t.Fatalf("rotation = %d: %s", rotated.StatusCode, raw)
	}
	gen2 := vTokens(t, raw).RefreshToken

	// The replayed value is refused, and the refusal revokes the family the
	// tombstone names rather than being a bare "unknown token".
	resp, raw := e.refresh(t, e.webID, e.webSec, tokens.RefreshToken)
	if resp.StatusCode != http.StatusBadRequest || vJSON(t, raw)["error"] != "invalid_grant" {
		t.Fatalf("the spent generation was not refused with 400 invalid_grant: %d %s", resp.StatusCode, raw)
	}
	if resp, _ := e.refresh(t, e.webID, e.webSec, gen2); resp.StatusCode == http.StatusOK {
		t.Errorf("the replacement survived the replay, so no family was revoked")
	}

	// The store-level shape: a rotation leaves a tombstone, and replaying the
	// spent value on the read path returns the replay sentinel rather than a bare
	// lookup miss — that is the family revocation firing, not a generic refusal.
	other := e.codeFlow(t, e.webID, e.webSec, []string{"account.id", "offline_access"}, "usr_vfy", time.Time{})
	rotatedOther, rawOther := e.refresh(t, e.webID, e.webSec, other.RefreshToken)
	if rotatedOther.StatusCode != http.StatusOK {
		t.Fatalf("control rotation = %d: %s", rotatedOther.StatusCode, rawOther)
	}
	otherGen2 := vTokens(t, rawOther).RefreshToken
	if _, err := e.store.TokenRequestByRefreshToken(context.Background(), other.RefreshToken); !errors.Is(err, memory.ErrRefreshTokenSpent) {
		t.Errorf("the store's read path reported %v for a replayed spent token, want ErrRefreshTokenSpent", err)
	}
	if _, err := e.store.TokenRequestByRefreshToken(context.Background(), otherGen2); err == nil {
		t.Errorf("the replacement survived the store-level replay, so no family was revoked")
	}
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

// TestV08PercentEncodedClientIDBypassesTheIntrospectionGuard was the
// falsification attempt for claim 8. It is FALSIFIED — the guard now resolves
// the Basic username the way the library does (url.QueryUnescape,
// internal/oidchttp basicClientID), so the escaped spelling reaches the same
// public client and is refused with 401 invalid_client. The test stands as the
// regression guard, under its original name.
//
// The two spellings must answer the SAME way; a future change that reads the raw
// header again would make the escaped one pass this guard.
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

	if plainResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("control failed: the literal public id was not refused (%d)", plainResp.StatusCode)
	}
	if escResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the percent-encoded public id was admitted (%d: %s): the guard read the raw header "+
			"instead of the decoded username the library authenticates (claim 8 is back)", escResp.StatusCode, escRaw)
	}
	if got := vJSON(t, escRaw)["error"]; got != "invalid_client" {
		t.Errorf("the escaped refusal error = %v, want invalid_client: %s", got, escRaw)
	}
}

// TestV08DataHalfStillFailsClosed is the control the original probe claimed: even
// with the guard bypassed, a real foreign token was not described because the
// introspection filter keyed on the raw (escaped) id. The guard bypass is now
// closed — the escaped spelling is refused outright — so the data half holds
// one step earlier, and this test pins that refusal plus the control.
func TestV08DataHalfStillFailsClosed(t *testing.T) {
	clock := newVClock()
	e := newVEnv(t, clock, []string{"vfy-public"})

	tokens := e.codeFlow(t, e.webID, e.webSec,
		[]string{"account.id", "offline_access"}, "usr_vfy", time.Time{})
	escaped := strings.Replace(e.pubID, "p", "%70", 1)

	resp, raw := e.post(t, "/oauth/introspect",
		map[string]string{"token": tokens.AccessToken}, escaped, "not-a-secret")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the escaped caller was admitted on a real foreign token (%d): %s", resp.StatusCode, raw)
	}
	body := vJSON(t, raw)
	if body["error"] != "invalid_client" {
		t.Errorf("the refusal error = %v, want invalid_client: %s", body["error"], raw)
	}
	// A refusal must describe nothing: no liveness bit, no scope, no subject.
	for _, field := range []string{"active", "scope", "sub"} {
		if _, leaked := body[field]; leaked {
			t.Errorf("the refusal body carries %q: %s", field, raw)
		}
	}

	// Control: the literal spelling is refused the same way, so the answer is
	// the non-confidential guard and not an escape-specific accident.
	plainResp, plainRaw := e.post(t, "/oauth/introspect",
		map[string]string{"token": tokens.AccessToken}, e.pubID, "not-a-secret")
	if plainResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("control: the literal public id answered %d: %s", plainResp.StatusCode, plainRaw)
	}
	t.Logf("both spellings refused: escaped=%d literal=%d", resp.StatusCode, plainResp.StatusCode)
}
