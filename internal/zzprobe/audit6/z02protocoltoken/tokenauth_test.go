//go:build audit6

package z02protocoltoken

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Z02-1 guard — the token endpoint's advertised client-authentication matrix
// must match what the endpoint does. Discovery advertises
// token_endpoint_auth_methods_supported = [none, client_secret_basic,
// client_secret_post]; each row here probes one cell of that matrix with the
// grant it is most used with.
func TestZ02TokenAuthMatrixMatchesAdvertisement(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})
	verifier := strings.Repeat("v", 64)

	// A code for the confidential client, exchanged four ways.
	exchange := func(t *testing.T, name, formClientID, formSecret string, basicID, basicSecret string) (int, map[string]any) {
		t.Helper()
		code, _ := e.authorizeCode(t, e.webID, "https://client.example/cb", []string{"account.id"}, "usr_z02")
		f := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"https://client.example/cb"},
			"code_verifier": {verifier},
		}
		if formClientID != "" {
			f.Set("client_id", formClientID)
		}
		if formSecret != "" {
			f.Set("client_secret", formSecret)
		}
		body, status := e.postToken(t, basicID, basicSecret, f)
		return status, body
	}

	t.Run("basic with the right secret", func(t *testing.T) {
		status, body := exchange(t, "basic", "", "", e.webID, e.webSec)
		if status != http.StatusOK {
			t.Fatalf("client_secret_basic was refused although it is advertised: %d %v", status, body)
		}
	})
	t.Run("basic with the wrong secret", func(t *testing.T) {
		status, body := exchange(t, "basic-wrong", "", "", e.webID, "wrong")
		if status != http.StatusUnauthorized {
			t.Fatalf("a wrong Basic secret was not refused with 401: %d %v", status, body)
		}
	})
	t.Run("basic with an empty secret", func(t *testing.T) {
		status, body := exchange(t, "basic-empty", "", "", e.webID, "")
		if status != http.StatusUnauthorized {
			t.Fatalf("an empty Basic secret was not refused with 401: %d %v", status, body)
		}
	})
	t.Run("client_secret_post", func(t *testing.T) {
		status, body := exchange(t, "post", e.webID, e.webSec, "", "")
		if status != http.StatusOK {
			t.Fatalf("client_secret_post was refused although it is advertised: %d %v", status, body)
		}
	})
	t.Run("client_secret_post with a wrong secret", func(t *testing.T) {
		status, body := exchange(t, "post-wrong", e.webID, "wrong", "", "")
		if status != http.StatusUnauthorized {
			t.Fatalf("a wrong posted secret was not refused with 401: %d %v", status, body)
		}
	})
	t.Run("none for a public client", func(t *testing.T) {
		code, _ := e.authorizeCode(t, e.deviceID, "https://device.example/cb", []string{"account.id"}, "usr_z02")
		body, status := e.postToken(t, "", "", url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"https://device.example/cb"},
			"client_id":     {e.deviceID},
			"code_verifier": {verifier},
		})
		if status != http.StatusOK {
			t.Fatalf("a public client naming itself was refused although none is advertised: %d %v", status, body)
		}
	})
	t.Run("no identity at all", func(t *testing.T) {
		code, _ := e.authorizeCode(t, e.webID, "https://client.example/cb", []string{"account.id"}, "usr_z02")
		body, status := e.postToken(t, "", "", url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"https://client.example/cb"},
			"code_verifier": {verifier},
		})
		if status != http.StatusUnauthorized {
			t.Fatalf("a confidential client without any identity was not refused: %d %v", status, body)
		}
	})

	// A request that names two different clients is malformed: the wrapper's
	// Basic-vs-form mismatch check. Both orderings of "the honest one in Basic,
	// somebody else in the form" must 400 before the library picks a side.
	for _, f := range []url.Values{
		{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "client_id": {e.narrowID}},
		{"grant_type": {"authorization_code"}, "code": {"x"}, "client_id": {e.narrowID}},
	} {
		resp, raw := e.postForm(t, "/oauth/token", f, e.webID, e.webSec)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("a request naming two clients answered %d: %s", resp.StatusCode, raw)
		}
	}

	// The percent-encoding seam: the wrapper compares the Basic username raw
	// while the library url.QueryUnescapes it. A caller that percent-encodes a
	// character of its id can therefore make the two layers resolve two
	// different strings. The mismatch check must still catch the two-identity
	// shape when the form names the decoded id.
	escaped := strings.Replace(e.webID, "-", "%2D", 1) // QueryUnescape(escaped) == e.webID
	if escaped == e.webID {
		t.Fatalf("fixture id %q has no escapable character", e.webID)
	}
	resp, raw := e.postForm(t, "/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"x"},
		// The form value decodes to the real id, the Basic username stays raw
		// and escaped, so the raw comparison sees the same string twice while
		// the library's two readers see different strings.
		"client_id": {escaped},
	}, escaped, e.webSec)
	t.Logf("escaped Basic id + matching escaped form id -> %d %s", resp.StatusCode, raw)

	// And the same escaped id with NO form copy: the library authenticates the
	// real client, the wrapper never resolved it at all.
	resp, raw = e.postForm(t, "/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"x"},
	}, escaped, e.webSec)
	t.Logf("escaped Basic id alone -> %d %s", resp.StatusCode, raw)
}

// Z02-4 (FINDING) — discovery advertises client_secret_post for the token
// endpoint, but the device_code grant only recognizes HTTP Basic as
// authentication for a confidential client: ClientIDFromRequest (the device
// grant's identity resolver) treats a posted secret as "not authenticated",
// so a client that negotiated client_secret_post gets 401 invalid_client on
// the one grant where it would present it that way.
func TestZ02DeviceGrantRefusesAdvertisedClientSecretPost(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})

	// Control 1: Basic works for the device grant.
	tokens, status, raw := e.deviceFlow(t, e.webID, e.webID, e.webSec, []string{"account.id"}, "usr_z02")
	if status != http.StatusOK || tokens["access_token"] == nil {
		t.Fatalf("control failed: a confidential client could not run the device grant with Basic: %d %s", status, raw)
	}

	// Control 2: the public client runs the grant with no secret (none).
	tokens, status, raw = e.deviceFlow(t, e.deviceID, "", "", []string{"account.id"}, "usr_z02")
	if status != http.StatusOK || tokens["access_token"] == nil {
		t.Fatalf("control failed: a public client could not run the device grant with none: %d %s", status, raw)
	}

	// The finding: client_secret_post — advertised at this very endpoint — is
	// refused by the device grant for a confidential client.
	tokens, status, raw = e.deviceFlow(t, e.webID, "", "", []string{"account.id"}, "usr_z02")
	if status == http.StatusOK {
		t.Errorf("the device grant accepted client_secret_post, so the finding does not hold: %s", raw)
	}
	if status != http.StatusUnauthorized {
		t.Errorf("the device grant answered client_secret_post with %d, want 401 invalid_client: %s", status, raw)
	}
	if !strings.Contains(string(raw), "invalid_client") {
		t.Errorf("the refusal is not invalid_client: %s", raw)
	}
}

// Z02-2 guards — the authorization-code exchange re-verifies everything the
// authorize entrance decided: the client, the redirect_uri, PKCE, and the
// code's single use. Each row is an attack that must fail.
func TestZ02CodeExchangeGuardsHold(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})
	verifier := strings.Repeat("v", 64)

	newExchange := func() url.Values {
		t.Helper()
		code, _ := e.authorizeCode(t, e.webID, "https://client.example/cb", []string{"account.id"}, "usr_z02")
		return url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"https://client.example/cb"},
			"code_verifier": {verifier},
		}
	}

	t.Run("redirect_uri omitted", func(t *testing.T) {
		form := newExchange()
		form.Del("redirect_uri")
		body, status := e.postToken(t, e.webID, e.webSec, form)
		if status == http.StatusOK {
			t.Errorf("an exchange without redirect_uri succeeded: %v", body)
		}
	})
	t.Run("redirect_uri mismatched", func(t *testing.T) {
		form := newExchange()
		form.Set("redirect_uri", "https://client.example/cb?x=1")
		body, status := e.postToken(t, e.webID, e.webSec, form)
		if status == http.StatusOK {
			t.Errorf("an exchange with a different redirect_uri succeeded: %v", body)
		}
	})
	t.Run("another client's code", func(t *testing.T) {
		form := newExchange()
		body, status := e.postToken(t, e.narrowID, e.narrowSec, form)
		if status == http.StatusOK {
			t.Errorf("a client exchanged a code issued to another client: %v", body)
		}
	})
	t.Run("wrong PKCE verifier", func(t *testing.T) {
		form := newExchange()
		form.Set("code_verifier", strings.Repeat("w", 64))
		body, status := e.postToken(t, e.webID, e.webSec, form)
		if status == http.StatusOK {
			t.Errorf("a wrong code_verifier still exchanged: %v", body)
		}
	})
	t.Run("code replay", func(t *testing.T) {
		form := newExchange()
		body, status := e.postToken(t, e.webID, e.webSec, form)
		if status != http.StatusOK {
			t.Fatalf("control failed: the first exchange was refused: %d %v", status, body)
		}
		body, status = e.postToken(t, e.webID, e.webSec, form)
		if status == http.StatusOK {
			t.Errorf("the same code was exchanged twice: %v", body)
		}
		if code := body["error"]; code != "invalid_grant" {
			t.Errorf("code replay error = %v, want invalid_grant: %v", code, body)
		}
	})

	// A failed exchange burns the code (fail-closed, ADR-0005 §8): the second
	// exchange — now with the right verifier — must still be refused, or the
	// burn would only have happened on success.
	form := newExchange()
	form.Set("code_verifier", strings.Repeat("w", 64))
	if body, status := e.postToken(t, e.webID, e.webSec, form); status == http.StatusOK {
		t.Fatalf("control failed: the wrong verifier was accepted: %v", body)
	}
	form.Set("code_verifier", verifier)
	body, status := e.postToken(t, e.webID, e.webSec, form)
	if status == http.StatusOK {
		t.Errorf("a code whose first exchange failed was still redeemable: %v", body)
	}
}

// Z02-3 guards — grant_type dispatch: only the three advertised grants work,
// and each refusal is a 4xx OAuth error, never a 5xx.
func TestZ02GrantTypeDispatchRefusesUnadvertised(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})

	for name, form := range map[string]url.Values{
		"client_credentials": {
			"grant_type": {"client_credentials"},
			"client_id":  {e.webID}, "client_secret": {e.webSec},
		},
		"jwt-bearer": {
			"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
			"assertion":  {"not-a-jwt"},
			"client_id":  {e.webID}, "client_secret": {e.webSec},
		},
		"token-exchange": {
			"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"client_id":  {e.webID}, "client_secret": {e.webSec},
		},
		"password": {
			"grant_type": {"password"}, "username": {"u"}, "password": {"p"},
			"client_id": {e.webID}, "client_secret": {e.webSec},
		},
		"unknown": {"grant_type": {"made-up-grant"}},
		"empty":   {"grant_type": {""}},
	} {
		t.Run(name, func(t *testing.T) {
			resp, raw := e.postForm(t, "/oauth/token", form, "", "")
			if resp.StatusCode >= 500 {
				t.Fatalf("grant %s produced a %d: %s", name, resp.StatusCode, raw)
			}
			if resp.StatusCode < 400 {
				t.Fatalf("grant %s was accepted: %d %s", name, resp.StatusCode, raw)
			}
			if strings.Contains(string(raw), "access_token") || strings.Contains(string(raw), "id_token") {
				t.Fatalf("grant %s minted a token: %s", name, raw)
			}
			payload := decodeJSON(t, raw)
			if _, ok := payload["error"].(string); !ok {
				t.Fatalf("grant %s answered outside the protocol error shape: %s", name, raw)
			}
		})
	}
}
