//go:build audit5

package protocol

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// PROBE 18 — unsupported grants and response types are refused in the protocol
// plane's shape, without a 500 and without minting anything. The wrapper trims
// `grant_types_supported` down to the three it implements (ADR-0005 point 5), so
// these are the requests a client built against the LIBRARY's defaults would send.
func TestProbeUnsupportedGrantsAndResponseTypesFailCleanly(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	grants := map[string]url.Values{
		"jwt-bearer": {
			"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
			"assertion":  {"not-a-jwt"},
			"client_id":  {e.webID}, "client_secret": {e.webSec},
		},
		"client_credentials": {
			"grant_type": {"client_credentials"},
			"client_id":  {e.webID}, "client_secret": {e.webSec},
		},
		"token_exchange": {
			"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"client_id":  {e.webID}, "client_secret": {e.webSec},
		},
		"password": {
			"grant_type": {"password"}, "username": {"u"}, "password": {"p"},
			"client_id": {e.webID}, "client_secret": {e.webSec},
		},
		"empty": {
			"grant_type": {""},
			"client_id":  {e.webID}, "client_secret": {e.webSec},
		},
		"client_assertion": {
			"grant_type":            {"client_credentials"},
			"client_assertion":      {"eyJhbGciOiJub25lIn0.e30."},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		},
	}
	for name, form := range grants {
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

	// Response types the library advertises by default but this deployment does
	// not implement: refused, and refused THROUGH THE REGISTERED REDIRECT, which is
	// what proves the refusal cannot be turned into an open redirect.
	for name, rt := range map[string]string{
		"token":         "token",
		"id_token":      "id_token",
		"code id_token": "code id_token",
		"none":          "none",
		"code token":    "code token",
		"garbage":       "not-a-response-type",
	} {
		t.Run("response_type/"+name, func(t *testing.T) {
			q := authValues(e, "https://client.example/cb", []string{"account.id"})
			q.Set("response_type", rt)
			resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+q.Encode())
			loc := resp.Header.Get("Location")
			if loc == "" {
				t.Fatalf("response_type=%q answered %d with no redirect: %s", rt, resp.StatusCode, bodyOf(t, resp))
			}
			parsed, err := url.Parse(loc)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Scheme+"://"+parsed.Host != "https://client.example" {
				t.Fatalf("the refusal for response_type=%q was redirected to %q", rt, loc)
			}
			if !strings.Contains(loc, "error=") {
				t.Fatalf("response_type=%q was not refused: %q", rt, loc)
			}
			if strings.Contains(loc, "code=") {
				t.Fatalf("response_type=%q produced a code: %q", rt, loc)
			}
		})
	}
}

// PROBE 19 — an anonymous GET /oauth/authorize allocates a pending authorization
// request that lives for RequestTTL (30 minutes by default). Nothing authenticates
// the caller: the client id and the redirect URI of a public client are both
// public values (the device client in this fixture is exactly that shape), and the
// only costs are a PKCE challenge that anyone can compute and a scope the client
// is registered for.
//
// The protocol plane is behind the per-client-address limiter and the in-flight
// cap (internal/httpapi Config.Limiter / MaxInFlight), so this is a measurement of
// the slope rather than a demonstration that the process dies — reported as a
// bounded availability note, with the number measured rather than asserted.
func TestProbeAnonymousAuthorizeAllocatesPendingRequests(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	before := e.store.Counts()
	const n = 200
	for i := 0; i < n; i++ {
		q := url.Values{
			"response_type":         {"code"},
			"client_id":             {e.deviceID}, // a PUBLIC client: its id is not a secret
			"redirect_uri":          {"https://device.example/cb"},
			"scope":                 {"account.id"},
			"state":                 {"state-probe"},
			"code_challenge":        {pkceValue(strings.Repeat("v", 64))},
			"code_challenge_method": {"S256"},
		}
		resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+q.Encode())
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("authorize #%d = %d %s", i, resp.StatusCode, bodyOf(t, resp))
		}
		if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login?") {
			t.Fatalf("authorize #%d did not reach the login plane: %q", i, loc)
		}
	}
	after := e.store.Counts()
	grew := after.AuthRequests - before.AuthRequests
	if grew != n {
		t.Fatalf("%d anonymous authorizations produced %d pending requests", n, grew)
	}
	t.Logf("%d unauthenticated GETs -> %d pending auth requests held for the request TTL (%d -> %d records)",
		n, grew, before.Records(), after.Records())

	// A sweep is what reclaims them, and it only reclaims expired ones.
	if removed := e.store.SweepExpired(); removed != 0 {
		t.Fatalf("the sweep reclaimed %d unexpired requests", removed)
	}
}
