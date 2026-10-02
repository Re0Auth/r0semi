//go:build audit6

package z02protocoltoken

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
)

// Z02-1 / S02-1 (fixed — now a regression guard, name kept for the coverage
// matrix). `max_age` and `prompt=login` used to be accepted at the authorize
// entrance and then silently dropped: neither the stored request nor the login
// hook honored them, so a stale session completed the flow and the id_token
// carried the old auth_time with no login_required. The fixed store refuses
// CompleteLogin (oidcstore.ErrReauthenticationRequired) unless the recorded
// auth_time satisfies the bound, so a two-hour-old session cannot complete a
// freshness-bound request at all; after a real re-authentication the id_token
// carries that recorded time rather than the decision clock.
//
// The control keeps the probe honest: with no prompt/max_age the same stale
// session still completes and its auth_time is the session's old sign-in, so this
// is about the request and not a general auth_time regression.
func TestZ02MaxAgeAndPromptLoginAreIgnored(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})

	// The session signed in two hours ago. SetAuthTime is exactly what the
	// production login hook calls (cmd/re0auth main.go:1298) with
	// sessions.AuthenticatedAt, so this is the production shape: a stale
	// browser session, not a synthetic write.
	stale := time.Now().UTC().Add(-2 * time.Hour)

	// authorize sends the REAL request (including any freshness parameter) to the
	// real endpoint. It returns the pending request id, or "" when the endpoint
	// answered `login_required` through the redirect — also a correct answer for a
	// freshness request that cannot be satisfied without a UI.
	authorize := func(extra url.Values) (string, *url.URL) {
		t.Helper()
		q := url.Values{
			"response_type":         {"code"},
			"client_id":             {e.webID},
			"redirect_uri":          {"https://client.example/cb"},
			"scope":                 {"openid account.id"},
			"state":                 {"state-z02"},
			"nonce":                 {"nonce-z02"},
			"code_challenge":        {pkceValue(strings.Repeat("v", 64))},
			"code_challenge_method": {"S256"},
		}
		for k, vs := range extra {
			q[k] = vs
		}
		resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+q.Encode())
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("authorize with %v = %d (%s), want a redirect", extra, resp.StatusCode, bodyOf(t, resp))
		}
		loc, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if errParam := loc.Query().Get("error"); errParam != "" {
			if errParam == "login_required" {
				return "", loc
			}
			t.Fatalf("authorize with %v was answered with error=%q: %s", extra, errParam, loc)
		}
		id := loc.Query().Get("authRequestID")
		if id == "" {
			t.Fatalf("authorize with %v did not start the interactive flow: %s", extra, loc)
		}
		return id, loc
	}

	// completeAt records `at` as the session's sign-in time — exactly what a login
	// hook driven by an existing browser session would — then completes the pending
	// request through the real callback and token endpoint. It RETURNS the
	// CompleteLogin error instead of failing, so the probe can assert the refusal
	// the fix introduced.
	completeAt := func(id string, at time.Time) (map[string]any, error) {
		t.Helper()
		ctx := context.Background()
		verifier := strings.Repeat("v", 64)
		if err := e.store.SetAuthTime(ctx, id, at); err != nil {
			t.Fatal(err)
		}
		if err := e.store.CompleteLogin(ctx, id, "usr_z02", []string{"openid", "account.id"}); err != nil {
			return nil, err
		}
		resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize/callback?id="+url.QueryEscape(id))
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("callback status = %d: %s", resp.StatusCode, bodyOf(t, resp))
		}
		cb, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		code := cb.Query().Get("code")
		if code == "" {
			t.Fatalf("no code in %s", cb)
		}
		tokens, status := e.postToken(t, e.webID, e.webSec, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"https://client.example/cb"},
			"code_verifier": {verifier},
		})
		if status != http.StatusOK {
			t.Fatalf("token status = %d: %v", status, tokens)
		}
		return tokens, nil
	}

	authTimeOf := func(tokens map[string]any) time.Time {
		t.Helper()
		issued := asTokens(t, tokens)
		if issued.IDToken == "" {
			t.Fatal("no id_token issued although openid was requested")
		}
		claims := idTokenClaims(t, issued.IDToken)
		at, ok := claims["auth_time"].(float64)
		if !ok || at <= 0 {
			t.Fatalf("auth_time = %v, want a number", claims["auth_time"])
		}
		return time.Unix(int64(at), 0).UTC()
	}

	for name, extra := range map[string]url.Values{
		"prompt=login": {"prompt": {"login"}},
		"max_age=1":    {"max_age": {"1"}},
		"max_age=0":    {"max_age": {"0"}},
	} {
		t.Run(name, func(t *testing.T) {
			id, loc := authorize(extra)
			if id == "" {
				// No live session and the OP chose to say so: the request was
				// honored in the other permitted way.
				t.Logf("%s returned login_required (no live session): %s", name, loc)
				return
			}
			// The request is ACCEPTED (not refused as unsupported), but the
			// two-hour-old session must NOT satisfy it. The store refuses to
			// complete rather than substituting the consent-decision clock, so the
			// id_token can never advertise a fresh authentication that never
			// happened.
			if _, err := completeAt(id, stale); !errors.Is(err, oidcstore.ErrReauthenticationRequired) {
				t.Errorf("%s: completing on a %.0f-minute-old session = %v, want "+
					"oidcstore.ErrReauthenticationRequired; the freshness request was ignored",
					name, time.Since(stale).Minutes(), err)
			}
			if ar, err := e.store.AuthRequestByID(context.Background(), id); err != nil || ar.Done() {
				t.Errorf("%s: the refused completion left the request decided: done=%v err=%v",
					name, ar != nil && ar.Done(), err)
			}
			// A real re-authentication moments ago satisfies it, and the id_token
			// carries that recorded time (the round-trip tolerance covers the gap).
			fresh := time.Now().UTC().Add(-5 * time.Second)
			tokens, err := completeAt(id, fresh)
			if err != nil {
				t.Fatalf("%s: completing after a fresh authentication: %v", name, err)
			}
			if at := authTimeOf(tokens); at.Sub(fresh) < -time.Minute || at.Sub(fresh) > time.Minute {
				t.Errorf("%s: id_token auth_time = %s, want the recorded re-authentication %s", name, at, fresh)
			}
		})
	}

	// Control: without a freshness request the same stale session completes and the
	// id_token carries that old auth_time.
	id, _ := authorize(nil)
	if id == "" {
		t.Fatal("control failed: an ordinary authorize returned login_required with no prompt")
	}
	controlTokens, err := completeAt(id, stale)
	if err != nil {
		t.Fatalf("control failed: an ordinary request did not complete on the stale session: %v", err)
	}
	controlAuth := authTimeOf(controlTokens)
	if time.Since(controlAuth) < time.Hour {
		t.Fatalf("control failed: the recorded auth_time is fresh, so the stale-session shape does not hold")
	}
	if delta := controlAuth.Sub(stale); delta < -time.Minute || delta > time.Minute {
		t.Fatalf("control failed: auth_time %s is not the session's recorded %s", controlAuth, stale)
	}

	// And prompt=none (the O-8a fix) still refuses without a session, so the
	// finding is about login/max_age, not a general prompt regression.
	_, loc := authorize(url.Values{"prompt": {"none"}})
	if loc.Query().Get("error") != "login_required" {
		t.Fatalf("prompt=none no longer refuses without a session: %s", loc)
	}
}

// Z02-17 guards — the id_token's claims across all three grants. sub is the
// usr_ id (P0-1), aud/azp name the client, at_hash matches the access token,
// c_hash matches the code (code grant only), nonce survives (code grant only),
// and the signature verifies against the published JWKS.
func TestZ02IDTokenClaimsAcrossGrants(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})

	// --- the code grant ---
	codeTokens := asTokens(t, e.codeFlow(t, []string{"openid", "account.id", "offline_access"}))
	claims := idTokenClaims(t, codeTokens.IDToken)
	if claims["sub"] != "usr_z02" {
		t.Errorf("code grant: sub = %v", claims["sub"])
	}
	switch aud := claims["aud"].(type) {
	case string:
		if aud != e.webID {
			t.Errorf("code grant: aud = %q", aud)
		}
	case []any:
		if len(aud) != 1 || aud[0] != e.webID {
			t.Errorf("code grant: aud = %v", aud)
		}
	default:
		t.Errorf("code grant: aud has unexpected type %T", claims["aud"])
	}
	if claims["azp"] != e.webID {
		t.Errorf("code grant: azp = %v", claims["azp"])
	}
	if claims["nonce"] != "nonce-z02" {
		t.Errorf("code grant: nonce = %v", claims["nonce"])
	}
	if got := halfHash(t, codeTokens.AccessToken); got != claims["at_hash"] {
		t.Errorf("code grant: at_hash = %v, want %s (left half of sha256(access_token))", claims["at_hash"], got)
	}
	// c_hash is only defined when the id_token came from a code: drive the
	// authorize leg, hash the code, exchange it, and compare.
	code, _ := e.authorizeCode(t, e.webID, "https://client.example/cb", []string{"openid", "account.id"}, "usr_z02")
	exchanged, status := e.postToken(t, e.webID, e.webSec, form(
		"grant_type", "authorization_code",
		"code", code,
		"redirect_uri", "https://client.example/cb",
		"code_verifier", strings.Repeat("v", 64),
	))
	if status != http.StatusOK {
		t.Fatalf("control failed: the code exchange was refused: %d %v", status, exchanged)
	}
	if got := halfHash(t, code); got != idTokenClaims(t, asTokens(t, exchanged).IDToken)["c_hash"] {
		t.Errorf("code grant: c_hash = %v, want %s (left half of sha256(code))",
			idTokenClaims(t, asTokens(t, exchanged).IDToken)["c_hash"], got)
	}

	// --- the refresh grant ---
	rotated, status := e.refresh(t, e.webID, e.webSec, codeTokens.RefreshToken)
	if status != http.StatusOK {
		t.Fatalf("refresh refused: %d", status)
	}
	refreshTokens := asTokens(t, rotated)
	refreshClaims := idTokenClaims(t, refreshTokens.IDToken)
	if refreshClaims["sub"] != "usr_z02" {
		t.Errorf("refresh grant: sub = %v", refreshClaims["sub"])
	}
	if refreshClaims["azp"] != e.webID {
		t.Errorf("refresh grant: azp = %v", refreshClaims["azp"])
	}
	if got := halfHash(t, refreshTokens.AccessToken); got != refreshClaims["at_hash"] {
		t.Errorf("refresh grant: at_hash = %v, want %s", refreshClaims["at_hash"], got)
	}
	if _, has := refreshClaims["c_hash"]; has {
		t.Errorf("refresh grant: c_hash present without a code")
	}

	// --- the device grant ---
	deviceTokens, status, raw := e.deviceFlow(t, e.deviceID, "", "", []string{"openid", "account.id"}, "usr_dev")
	if status != http.StatusOK {
		t.Fatalf("device flow refused: %d %s", status, raw)
	}
	deviceJSON := asTokens(t, deviceTokens)
	if deviceJSON.IDToken == "" {
		t.Fatal("the device grant issued no id_token although openid was requested")
	}
	deviceClaims := idTokenClaims(t, deviceJSON.IDToken)
	if deviceClaims["sub"] != "usr_dev" {
		t.Errorf("device grant: sub = %v", deviceClaims["sub"])
	}
	switch aud := deviceClaims["aud"].(type) {
	case string:
		if aud != e.deviceID {
			t.Errorf("device grant: aud = %q", aud)
		}
	case []any:
		// The id_token builds `aud` as a JSON array (the production guard in
		// internal/oidchttp asserts that shape); a single-audience array is legal
		// OIDC, so accept it but require it to name exactly this client.
		if len(aud) != 1 || aud[0] != e.deviceID {
			t.Errorf("device grant: aud = %v", aud)
		}
	default:
		t.Errorf("device grant: aud has unexpected type %T", deviceClaims["aud"])
	}
	if deviceClaims["azp"] != e.deviceID {
		t.Errorf("device grant: azp = %v", deviceClaims["azp"])
	}
	if got := halfHash(t, deviceJSON.AccessToken); got != deviceClaims["at_hash"] {
		t.Errorf("device grant: at_hash = %v, want %s", deviceClaims["at_hash"], got)
	}
	if _, has := deviceClaims["nonce"]; has {
		t.Errorf("device grant: nonce present without an authorize request")
	}
	// O-2 holds on the device grant: no openid, no id_token.
	plain, status, raw := e.deviceFlow(t, e.deviceID, "", "", []string{"account.id"}, "usr_dev")
	if status != http.StatusOK {
		t.Fatalf("device flow without openid refused: %d %s", status, raw)
	}
	if asTokens(t, plain).IDToken != "" {
		t.Errorf("the device grant returned an id_token without openid")
	}
}

// halfHash computes the OIDC at_hash/c_hash shape: the left half of the
// SHA-256 of the value, base64url-encoded (RS256).
func halfHash(t *testing.T, value string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}
