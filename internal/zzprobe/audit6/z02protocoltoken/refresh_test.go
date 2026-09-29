//go:build audit6

package z02protocoltoken

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Z02-5 guards — the refresh grant cannot widen. Every row asks for a scope the
// grant does not carry and must be refused with invalid_scope; the narrowing
// rows must produce a token that actually is narrower.
func TestZ02RefreshCannotEscalateScope(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})

	// The grant carries account.id only (narrow's registered scope set);
	// offline_access is the internal trigger that issues a refresh token (O-6).
	tokens := asTokens(t, e.codeFlowAs(t, e.narrowID, e.narrowSec, "https://narrow.example/cb", []string{"account.id", "offline_access"}, "usr_z02", "n1"))
	if tokens.RefreshToken == "" {
		t.Fatal("no refresh token issued, so the probe is vacuous")
	}

	for name, scope := range map[string]string{
		"an unregistered scope":   "phigros.score.read",
		"the requested scope set": "account.id phigros.score.read",
		"openid never granted":    "openid",
	} {
		t.Run(name, func(t *testing.T) {
			body, code := e.postToken(t, e.narrowID, e.narrowSec, form(
				"grant_type", "refresh_token",
				"refresh_token", tokens.RefreshToken,
				"scope", scope,
			))
			if code == http.StatusOK {
				t.Fatalf("the refresh grant widened the scope: %v", body)
			}
			if got := body["error"]; got != "invalid_scope" {
				t.Fatalf("error = %v, want invalid_scope: %v", got, body)
			}
		})
	}

	// A second generation (empty scope parameter = keep the original set), then
	// a widening attempt on the rotated token.
	rotated, status := e.refresh(t, e.narrowID, e.narrowSec, tokens.RefreshToken)
	if status != http.StatusOK {
		t.Fatalf("the plain refresh was refused: %d %v", status, rotated)
	}
	second := asTokens(t, rotated)
	if second.RefreshToken == "" || second.RefreshToken == tokens.RefreshToken {
		t.Fatalf("rotation did not happen: %q", second.RefreshToken)
	}
	body, code := e.postToken(t, e.narrowID, e.narrowSec, form(
		"grant_type", "refresh_token",
		"refresh_token", second.RefreshToken,
		"scope", "account.id phigros.score.read",
	))
	if code == http.StatusOK {
		t.Fatalf("a refresh widened the scope after a plain rotation: %v", body)
	}

	// The response's scope field matches what was granted (offline_access is
	// hidden, O-6) and the replacement token really carries the narrowed set.
	if strings.Contains(second.Scope, "offline_access") {
		t.Errorf("the refresh response exposed offline_access: %q", second.Scope)
	}
	status, info, _ := e.introspect(t, second.AccessToken, e.narrowID, e.narrowSec)
	if status != http.StatusOK || info["active"] != true {
		t.Fatalf("control failed: the issuing client cannot introspect its rotated token: %d %v", status, info)
	}
	if got, _ := info["scope"].(string); got != "account.id" {
		t.Errorf("the rotated token's scope = %q, want account.id", got)
	}

	// An equal-scope refresh keeps working (the subset rule, stated plainly).
	body, code = e.postToken(t, e.narrowID, e.narrowSec, form(
		"grant_type", "refresh_token",
		"refresh_token", second.RefreshToken,
		"scope", "account.id",
	))
	if code != http.StatusOK {
		t.Fatalf("an equal-scope refresh was refused: %v", body)
	}
}

// Z02-6 guards — the refresh grant cannot cross clients, and a bearer that is
// not a refresh token cannot be spent as one.
func TestZ02RefreshCrossClientAndWrongShapeRefused(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})

	tokens := asTokens(t, e.codeFlowAs(t, e.webID, e.webSec, "https://client.example/cb", []string{"account.id", "offline_access"}, "usr_z02", "n1"))
	if tokens.RefreshToken == "" {
		t.Fatal("no refresh token issued")
	}

	// Another confidential client presenting the web client's refresh token.
	body, code := e.postToken(t, e.narrowID, e.narrowSec, form(
		"grant_type", "refresh_token", "refresh_token", tokens.RefreshToken))
	if code == http.StatusOK {
		t.Fatalf("a client refreshed another client's token: %v", body)
	}
	if got := body["error"]; got != "invalid_grant" {
		t.Fatalf("cross-client refresh error = %v, want invalid_grant: %v", got, body)
	}

	// A public client naming itself in the form cannot present it either — and
	// cannot use Basic with a garbage secret to impersonate the owner.
	for _, basic := range [][2]string{{"", ""}, {e.deviceID, "garbage"}} {
		resp, raw := e.postForm(t, "/oauth/token", form(
			"grant_type", "refresh_token", "refresh_token", tokens.RefreshToken,
			"client_id", e.deviceID,
		), basic[0], basic[1])
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("a public client refreshed another client's token (Basic %q): %s", basic[0], raw)
		}
	}

	// An access token is not a refresh token.
	body, code = e.postToken(t, e.webID, e.webSec, form(
		"grant_type", "refresh_token", "refresh_token", tokens.AccessToken))
	if code == http.StatusOK {
		t.Fatalf("an access token was spent as a refresh token: %v", body)
	}
	if got := body["error"]; got != "invalid_grant" {
		t.Fatalf("wrong-shape refresh error = %v, want invalid_grant: %v", got, body)
	}

	// An authorization code is not a refresh token.
	codeToken, _ := e.authorizeCode(t, e.webID, "https://client.example/cb", []string{"account.id"}, "usr_z02")
	body, code = e.postToken(t, e.webID, e.webSec, form(
		"grant_type", "refresh_token", "refresh_token", codeToken))
	if code == http.StatusOK {
		t.Fatalf("an authorization code was spent as a refresh token: %v", body)
	}

	// An id_token is not a refresh token.
	body, code = e.postToken(t, e.webID, e.webSec, form(
		"grant_type", "refresh_token", "refresh_token", tokens.IDToken))
	if code == http.StatusOK {
		t.Fatalf("an id_token was spent as a refresh token: %v", body)
	}
}

// Z02-7 guards — replay of a rotated refresh token is invalid_grant (ADR-0005
// §9), the replacement stays live, and expiry is enforced by the store's clock.
func TestZ02RefreshReplayAndExpiry(t *testing.T) {
	clock := newTestClock()
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02", now: clock.Now})

	tokens := asTokens(t, e.codeFlow(t, []string{"openid", "account.id", "offline_access"}))
	first := tokens.RefreshToken

	rotated, status := e.refresh(t, e.webID, e.webSec, first)
	if status != http.StatusOK {
		t.Fatalf("the first refresh was refused: %d %v", status, rotated)
	}
	second := asTokens(t, rotated)

	replay, status := e.refresh(t, e.webID, e.webSec, first)
	if status != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want 400: %v", status, replay)
	}
	if got := replay["error"]; got != "invalid_grant" {
		t.Fatalf("replay error = %v, want invalid_grant: %v", got, replay)
	}
	// The replacement is live, and rotating it yields the third generation —
	// the one the id_token and expiry checks below run against.
	thirdResp, status := e.refresh(t, e.webID, e.webSec, second.RefreshToken)
	if status != http.StatusOK {
		t.Fatalf("the replacement refresh token was rejected: %d %v", status, thirdResp)
	}

	// A replay of the FIRST generation after two rotations: same refusal —
	// there is no window where a two-generations-old token works again.
	clock.Advance(time.Second)
	if _, status := e.refresh(t, e.webID, e.webSec, first); status != http.StatusBadRequest {
		t.Fatalf("a two-generations-old token was accepted: %d", status)
	}

	// The refreshed id_token keeps sub (the P0-1 fix covers this path too).
	idt := asTokens(t, thirdResp)
	if idt.IDToken == "" {
		t.Fatal("the refresh grant issued no id_token although openid was granted")
	}
	claims := idTokenClaims(t, idt.IDToken)
	if claims["sub"] != "usr_z02" {
		t.Errorf("the refreshed id_token's sub = %v, want usr_z02 (P0-1 regression on the refresh path)", claims["sub"])
	}
	if _, hasNonce := claims["nonce"]; hasNonce {
		t.Errorf("the refreshed id_token carries a nonce: %v", claims["nonce"])
	}

	// Expiry: past the 30-day refresh TTL the replacement is refused.
	clock.Advance(31 * 24 * time.Hour)
	_, status = e.refresh(t, e.webID, e.webSec, idt.RefreshToken)
	if status == http.StatusOK {
		t.Fatalf("an expired refresh token was accepted")
	}
}

// Z02-5b (FINDING) — a replayed (spent) refresh token is refused, but nothing
// is done about the generation the thief already holds. RFC 9700 §4.14.2: on
// reuse of a rotated refresh token the AS SHOULD revoke the whole token
// family, because the replay is itself the theft signal. Here the thief
// rotates the stolen token (getting generation 3), the legitimate client then
// replays its stolen copy (the AS refuses it — the theft is now detected),
// and the thief's generation 3 keeps working as if nothing had happened.
func TestZ02RefreshReplayDoesNotRevokeTheThiefsGeneration(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})

	tokens := asTokens(t, e.codeFlow(t, []string{"account.id", "offline_access"}))
	stolen := tokens.RefreshToken // the thief's copy of generation 2

	// The thief rotates first; they now hold generation 3.
	thief, status := e.refresh(t, e.webID, e.webSec, stolen)
	if status != http.StatusOK {
		t.Fatalf("control failed: the thief could not rotate the stolen token: %d %v", status, thief)
	}
	thiefTokens := asTokens(t, thief)

	// The legitimate client replays its copy: refused (single use held), and
	// this refusal is the theft signal the family rule keys on.
	replay, status := e.refresh(t, e.webID, e.webSec, stolen)
	if status == http.StatusBadRequest && replay["error"] == "invalid_grant" {
		t.Logf("the legitimate client's replay was refused with invalid_grant (theft detected)")
	} else {
		t.Fatalf("the replay was not refused as a spent token: %d %v", status, replay)
	}

	// The finding: the thief's generation must die with the detection, and it
	// does not — the stolen authorization keeps minting access tokens.
	after, status := e.refresh(t, e.webID, e.webSec, thiefTokens.RefreshToken)
	if status != http.StatusOK {
		t.Fatalf("the thief's generation unexpectedly stopped working (finding does not hold): %d %v", status, after)
	}
	afterTokens := asTokens(t, after)
	if got, info, _ := e.introspect(t, afterTokens.AccessToken, e.webID, e.webSec); got != http.StatusOK || info["active"] != true {
		t.Errorf("the thief's rotated access token is not active: %d %v", got, info)
	}
	t.Errorf("CONFIRMED: a detected refresh-token replay left the thief's chain alive — " +
		"the replayed (stolen) token was refused, but the generation minted from it still works, " +
		"so the thief keeps silent access for the rest of the 30-day refresh TTL")
}

// Z02-8 guards — revocation of one half kills the pair (RFC 7009 §2.1 via
// ADR-0005 §11), on both directions, including after a rotation.
func TestZ02RevocationPairsAndPropagation(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})

	t.Run("revoke access kills refresh", func(t *testing.T) {
		tokens := asTokens(t, e.codeFlow(t, []string{"account.id", "offline_access"}))
		resp, raw := e.postForm(t, "/oauth/revoke", form("token", tokens.AccessToken), e.webID, e.webSec)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("revocation answered %d: %s", resp.StatusCode, raw)
		}
		if status, _ := e.userinfo(t, tokens.AccessToken); status != http.StatusUnauthorized {
			t.Errorf("the revoked access token still works at userinfo")
		}
		if _, status := e.refresh(t, e.webID, e.webSec, tokens.RefreshToken); status == http.StatusOK {
			t.Errorf("the paired refresh token survived the access token's revocation")
		}
	})

	t.Run("revoke refresh kills access", func(t *testing.T) {
		tokens := asTokens(t, e.codeFlow(t, []string{"account.id", "offline_access"}))
		resp, raw := e.postForm(t, "/oauth/revoke", form("token", tokens.RefreshToken), e.webID, e.webSec)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("revocation answered %d: %s", resp.StatusCode, raw)
		}
		if status, _ := e.userinfo(t, tokens.AccessToken); status != http.StatusUnauthorized {
			t.Errorf("the paired access token survived the refresh token's revocation")
		}
	})

	t.Run("revoke rotated refresh kills the current pair", func(t *testing.T) {
		tokens := asTokens(t, e.codeFlow(t, []string{"account.id", "offline_access"}))
		rotated, status := e.refresh(t, e.webID, e.webSec, tokens.RefreshToken)
		if status != http.StatusOK {
			t.Fatalf("rotation refused: %d", status)
		}
		next := asTokens(t, rotated)
		resp, raw := e.postForm(t, "/oauth/revoke", form("token", next.RefreshToken), e.webID, e.webSec)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("revocation answered %d: %s", resp.StatusCode, raw)
		}
		if status, _ := e.userinfo(t, next.AccessToken); status != http.StatusUnauthorized {
			t.Errorf("the new access token survived the new refresh token's revocation")
		}
	})

	t.Run("revocation with a misleading token_type_hint still pairs", func(t *testing.T) {
		// The hint is advisory; the store resolves the token either way.
		tokens := asTokens(t, e.codeFlow(t, []string{"account.id", "offline_access"}))
		resp, raw := e.postForm(t, "/oauth/revoke", form(
			"token", tokens.AccessToken, "token_type_hint", "refresh_token"), e.webID, e.webSec)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("revocation with a misleading hint answered %d: %s", resp.StatusCode, raw)
		}
		if _, status := e.refresh(t, e.webID, e.webSec, tokens.RefreshToken); status == http.StatusOK {
			t.Errorf("a refresh token survived the revocation of its (hint-misnamed) access token")
		}
	})
}

// form builds url.Values from key/value pairs.
func form(kv ...string) url.Values {
	if len(kv)%2 != 0 {
		panic("form: odd argument count")
	}
	v := url.Values{}
	for i := 0; i < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}
