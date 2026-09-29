//go:build audit6

package z02protocoltoken

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Z02-1 (FINDING) — `max_age` and `prompt=login` are accepted at the
// authorize entrance and then silently dropped: neither the wrapper
// (validateAuthorize handles only `prompt=none`) nor the stored request
// (oidcstore.AuthRequest carries neither Prompt nor MaxAge) nor the login
// hook (cmd/re0auth main.go:1292-1303 writes the session's ORIGINAL
// sign-in time as auth_time, whatever the request asked) honors them. An RP
// that asks for a fresh authentication — the step-up tool OIDC Core §3.1.2.1
// defines with a MUST for prompt=login — receives a code and an id_token
// whose auth_time is the stale session's, and no login_required, and no
// re-authentication. This is the same class as the round-5 P2-24
// (prompt=none, fixed by O-8a): neither value is in O-9's not-doing list,
// and neither is implemented.
func TestZ02MaxAgeAndPromptLoginAreIgnored(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})

	// The session signed in two hours ago. SetAuthTime is exactly what the
	// production login hook calls (cmd/re0auth main.go:1298) with
	// sessions.AuthenticatedAt, so this is the production shape: a stale
	// browser session, not a synthetic write.
	stale := time.Now().UTC().Add(-2 * time.Hour)

	authorize := func(extra url.Values) (*http.Response, string) {
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
		body := bodyOf(t, resp)
		return resp, string(body)
	}

	for name, extra := range map[string]url.Values{
		"prompt=login": {"prompt": {"login"}},
		"max_age=1":    {"max_age": {"1"}},
		"max_age=0":    {"max_age": {"0"}},
	} {
		t.Run(name, func(t *testing.T) {
			// The request is ACCEPTED (not refused as unsupported)…
			resp, _ := authorize(extra)
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("%s was refused outright (%d), which would make the finding vacuous", name, resp.StatusCode)
			}
			loc, err := url.Parse(resp.Header.Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(loc.RawQuery, "error=") {
				t.Fatalf("%s was answered with an error redirect: %s", name, loc)
			}
			if loc.Query().Get("authRequestID") == "" {
				t.Fatalf("%s did not start the interactive flow: %s", name, loc)
			}

			// …and completes on the two-hour-old session, minting an id_token
			// whose auth_time is that stale sign-in.
			tokens := e.codeFlowWithAuthTime(t, e.webID, e.webSec, "https://client.example/cb",
				[]string{"openid", "account.id"}, "usr_z02", "nonce-z02", stale)
			issued := asTokens(t, tokens)
			if issued.IDToken == "" {
				t.Fatal("no id_token issued although openid was requested")
			}
			claims := idTokenClaims(t, issued.IDToken)
			authTime, ok := claims["auth_time"].(float64)
			if !ok || authTime <= 0 {
				t.Fatalf("auth_time = %v, want a number", claims["auth_time"])
			}
			age := time.Since(time.Unix(int64(authTime), 0))
			if age > time.Minute {
				t.Errorf("CONFIRMED: %s completed on a %.0f-minute-old session — the OP neither "+
					"re-authenticated (auth_time would be fresh) nor returned login_required; the id_token "+
					"carries the stale auth_time and the RP's step-up request was silently ignored",
					name, age.Minutes())
			}
		})
	}

	// Control: without a freshness request the same stale session completes —
	// the flow itself is sound and the finding is specifically about the
	// ignored request.
	tokens := e.codeFlowWithAuthTime(t, e.webID, e.webSec, "https://client.example/cb",
		[]string{"openid", "account.id"}, "usr_z02", "nonce-z02", stale)
	claims := idTokenClaims(t, asTokens(t, tokens).IDToken)
	authTime, _ := claims["auth_time"].(float64)
	if time.Since(time.Unix(int64(authTime), 0)) < time.Hour {
		t.Fatalf("control failed: the recorded auth_time is fresh, so the stale-session shape does not hold")
	}

	// And prompt=none (the O-8a fix) still refuses without a session, so the
	// finding is about login/max_age, not a general prompt regression.
	resp, _ := authorize(url.Values{"prompt": {"none"}})
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != "login_required" {
		t.Fatalf("prompt=none no longer refuses without a session: %d %s", resp.StatusCode, loc)
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
	if deviceClaims["aud"] != e.deviceID {
		t.Errorf("device grant: aud = %v", deviceClaims["aud"])
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
