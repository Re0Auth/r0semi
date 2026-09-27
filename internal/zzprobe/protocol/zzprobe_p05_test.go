//go:build audit5

package protocol

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The dedicated guard for P0-5: an unparsable body must not be able to switch off
// the pre-flights, and the scope gate must read every scope the request asks for.
//
// The mechanism P0-5 recorded: `requestParams` answered `url.Values{}` when
// ParseForm failed, and net/http reports a body it could not decode only on the
// FIRST call — it still commits `r.Form` from the query string, and the next call
// returns nil. So the duplicate-parameter refusal (RFC 6749 §3.1, ADR-0005 point 4)
// saw an empty set and passed, while the library, parsing a second time, read the
// real parameters. The device scope gate then read `form.Get("scope")` (the FIRST
// value, `account.id`, registered) while the library's decoder took the LAST
// (`phigros.score.read`, not registered) — and minted a live access token for it.
//
// Everything below is asserted through the real entry points, and every case has a
// control that must stay working, so a blanket refusal cannot make this pass.
func TestZZProbeScopeDupBypass(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	const redirect = "https://device.example/cb"
	// The device client is registered for account.id only.
	unregistered := "phigros.score.read"

	// --- controls: the honest shapes still work ---------------------------

	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+
		authValues(e, "https://client.example/cb", []string{"account.id"}).Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("control failed: an honest authorize answered %d: %s", resp.StatusCode, bodyOf(t, resp))
	}
	_ = bodyOf(t, resp)

	okResp, okRaw := e.postForm(t, "/oauth/device_authorization", url.Values{
		"client_id": {e.deviceID},
		"scope":     {"account.id"},
	}, "", "")
	if okResp.StatusCode != http.StatusOK {
		t.Fatalf("control failed: an honest device authorization answered %d %s", okResp.StatusCode, okRaw)
	}

	// --- the seam: unparsable body, everything in the query ---------------

	// (1) authorize. The duplicated `scope` is what the pre-flight refuses.
	dupQuery := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.deviceID},
		"redirect_uri":          {redirect},
		"scope":                 {"account.id", unregistered},
		"state":                 {"state-probe"},
		"nonce":                 {"nonce-probe"},
		"code_challenge":        {pkceValue(strings.Repeat("v", 64))},
		"code_challenge_method": {"S256"},
	}
	seam := postUnparsableBody(t, e, "/oauth/authorize", dupQuery)
	assertRefused(t, "authorize with an unparsable body and a duplicated scope", seam)
	if id := redirectAuthRequestID(t, seam); id != "" {
		ar, err := e.store.AuthRequestByID(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range ar.GetScopes() {
			if s == unregistered {
				t.Errorf("an unregistered scope %q reached the auth request %s", s, id)
			}
		}
	}

	// (2) device_authorization. This is the one that minted a live token.
	seam = postUnparsableBody(t, e, "/oauth/device_authorization", url.Values{
		"client_id": {e.deviceID},
		"scope":     {"account.id", unregistered},
	})
	assertRefused(t, "device_authorization with an unparsable body and a duplicated scope", seam)
	if strings.Contains(string(seam.body), "device_code") {
		t.Errorf("the seam still issued a device authorization: %s", seam.body)
	}

	// (3) A scope that cannot be parsed at all — Go's ParseQuery refuses a
	// semicolon separator — is the same class, and must not let the request
	// through with the parameters the library can still read out of the query.
	seam = send(t, e, http.MethodPost,
		"/oauth/device_authorization?client_id="+url.QueryEscape(e.deviceID)+"&scope=account.id;"+unregistered,
		"x=%zz")
	assertRefused(t, "device_authorization with a semicolon separator in the query", seam)

	// (4) The gate reads every scope in the value, not just the first: with the
	// parameters in one well-formed value, the unregistered scope is last.
	seam = send(t, e, http.MethodPost, "/oauth/device_authorization",
		url.Values{"client_id": {e.deviceID}, "scope": {"account.id " + unregistered}}.Encode())
	if seam.status != http.StatusBadRequest {
		t.Errorf("a device authorization for %q answered %d, want 400", unregistered, seam.status)
	}
	if !strings.Contains(seam.body, "invalid_scope") {
		t.Errorf("the refusal does not name invalid_scope: %d %s", seam.status, seam.body)
	}

	// (5) The duplicate rule still holds where it always did, so (1) and (2) are
	// not passing merely because everything is refused.
	dup := url.Values{"client_id": {e.deviceID}, "scope": {"account.id", unregistered}}
	resp2, raw2 := e.postForm(t, "/oauth/device_authorization", dup, "", "")
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("a well-formed duplicated scope answered %d %s", resp2.StatusCode, raw2)
	}

	// (6) And the escalation this class reached — a live token for a scope the
	// client was never registered for — is closed end to end: the honest device
	// grant still completes, and its token carries only the registered scope.
	tokens := deviceGrant(t, e, "usr_probe")
	if strings.Contains(tokens.Scope, unregistered) {
		t.Errorf("the honest device grant carries %q: %s", unregistered, tokens.Scope)
	}
	if tokens.AccessToken == "" {
		t.Fatalf("the honest device grant issued no access token")
	}
}

// seamResponse is a response with its body already read, so the shape of a refusal
// can be inspected after the fact.
type seamResponse struct {
	status int
	header http.Header
	body   string
}

// send posts a raw body to a path with a urlencoded content type.
func send(t *testing.T, e env, method, path, body string) seamResponse {
	t.Helper()
	req, err := http.NewRequest(method, e.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return seamResponse{status: resp.StatusCode, header: resp.Header, body: string(bodyOf(t, resp))}
}

// postUnparsableBody puts every parameter in the query string and sends a body Go
// cannot decode — the seam P0-5 is about.
func postUnparsableBody(t *testing.T, e env, path string, form url.Values) seamResponse {
	t.Helper()
	return send(t, e, http.MethodPost, path+"?"+form.Encode(), "x=%zz")
}

// assertRefused requires the protocol plane's own refusal: a 400 that parses as an
// OAuth error, not a redirect that carries the request onward and not a 5xx.
func assertRefused(t *testing.T, what string, r seamResponse) {
	t.Helper()
	if r.status != http.StatusBadRequest {
		t.Errorf("%s answered %d (location %q), want 400: %s", what, r.status, r.header.Get("Location"), r.body)
	}
	if !strings.Contains(r.body, "invalid_request") {
		t.Errorf("%s did not answer an OAuth invalid_request error: %s", what, r.body)
	}
	if cc := r.header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("%s is cacheable: %q", what, cc)
	}
}

// redirectAuthRequestID returns the auth request a 302 named, or "" when the
// response was not a redirect into the login/consent UI.
func redirectAuthRequestID(t *testing.T, r seamResponse) string {
	t.Helper()
	if r.status < 300 || r.status >= 400 {
		return ""
	}
	u, err := url.Parse(r.header.Get("Location"))
	if err != nil {
		return ""
	}
	return u.Query().Get("authRequestID")
}
