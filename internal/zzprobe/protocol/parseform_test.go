//go:build audit5

package protocol

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// PROBE 20 — the pre-flights read a DIFFERENT parameter set than the library when
// the body fails to parse.
//
// internal/oidchttp/oidchttp.go requestParams:
//
//	if err := r.ParseForm(); err != nil { return url.Values{} }
//	return r.Form
//
// so a body Go cannot parse makes every wrapper check see an empty parameter set.
// The library does not share that fate: net/http's ParseForm commits `r.Form` from
// the query string even when the body parse fails, and the SECOND call to
// ParseForm returns nil because `r.PostForm` is non-nil by then — the library's
// handlers call it a second time (pkg/op/token_request.go
// ParseAuthenticatedTokenRequest) and then decode from `r.Form`.
//
// The wrapper's refusals are therefore skipped for a request the library still
// serves: duplicate parameters (RFC 6749 §3.1, ADR-0005 point 4), the PKCE-value
// syntax check (ADR-0005 point 7) and the two-identity rule are all attached to a
// parameter set the attacker controls the emptiness of.
func TestProbeUnparsableBodyHidesParametersFromThePreFlights(t *testing.T) {
	const redirect = "https://client.example/cb"

	// A request whose every parameter lives in the QUERY, listed twice, with a body
	// the server cannot parse.
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})
	verifier := strings.Repeat("m", 64)

	code := issueCode(t, e, redirect, verifier)

	// Control A: the same exchange with the parameters in the body is accepted, so
	// the flow and the probe path work.
	good, status := e.postToken(t, e.webID, e.webSec, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("control failed: %d %v", status, good)
	}

	// Control B: the same request as a GET is refused outright.
	code = issueCode(t, e, redirect, verifier)
	getURL := e.server.URL + "/oauth/token?" + url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
		"client_id":     {e.webID},
		"client_secret": {e.webSec},
	}.Encode()
	if resp := e.get(t, noRedirect, getURL); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("control failed: GET /oauth/token = %d", resp.StatusCode)
	}

	// The seam: a POST whose QUERY carries the whole exchange and whose body is
	// unparsable, with the duplicates the wrapper is supposed to refuse.
	code = issueCode(t, e, redirect, verifier)
	seamURL := e.server.URL + "/oauth/token?" + url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code, code}, // duplicated: the wrapper refuses this
		"redirect_uri":  {redirect, redirect},
		"code_verifier": {"too-short", verifier}, // the first value is malformed
		"client_id":     {e.webID},
		"client_secret": {e.webSec},
	}.Encode()
	req, err := http.NewRequest(http.MethodPost, seamURL, strings.NewReader("x=%zz"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw := bodyOf(t, resp)

	// What the wrapper does with a well-formed duplicate: 400.
	dup := issueCode(t, e, redirect, verifier)
	_, dupStatus := e.postToken(t, e.webID, e.webSec, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {dup, dup},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	})
	if dupStatus != http.StatusBadRequest {
		t.Fatalf("control failed: a duplicated parameter was not refused in the body: %d", dupStatus)
	}

	if resp.StatusCode == http.StatusOK && strings.Contains(string(raw), "access_token") {
		t.Errorf("a duplicated-parameter exchange with an unparsable body was served: %d %s", resp.StatusCode, raw)
		return
	}
	t.Logf("duplicates through an unparsable body answered %d: %s", resp.StatusCode, raw)

	// Even when the seam does not mint tokens, the parameters were unvalidated:
	// the wrapper's answer must be a protocol error, not a server error.
	if resp.StatusCode >= 500 {
		t.Errorf("the seam produced a %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "error") {
		t.Errorf("the seam answered outside the protocol error shape: %s", raw)
	}
}

// PROBE 21 — the protocol plane enforces the METHOD (POST) but not the LOCATION of
// the parameters, so a POST with everything in the query string is served and the
// code, the refresh token and even the client secret end up in the URL, the
// access log and the browser history — the exact exposure ADR-0005 point 3 exists
// to remove ("凭据不再进入 URL 与访问日志").
func TestProbeTokenEndpointAcceptsItsParametersFromTheQueryString(t *testing.T) {
	const redirect = "https://client.example/cb"
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})
	verifier := strings.Repeat("q", 64)

	code := issueCode(t, e, redirect, verifier)
	u := e.server.URL + "/oauth/token?" + url.Values{
		"grant_type": {
			"authorization_code",
		},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
		"client_id":     {e.webID},
		"client_secret": {e.webSec}, // a secret in a URL
	}.Encode()
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a POST with its parameters in the query was refused: %d %s", resp.StatusCode, raw)
	}
	payload := decodeJSON(t, raw)
	if payload["access_token"] == nil {
		t.Fatalf("no access token: %s", raw)
	}
	t.Logf("the token endpoint served an exchange whose code, secret and verifier were all in the URL: %s", raw)

	// The same shape for a refresh token, which is the credential that matters
	// most: it is long-lived.
	tokens := asTokens(t, decodeJSON(t, raw))
	if tokens.RefreshToken != "" {
		u = e.server.URL + "/oauth/token?" + url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {tokens.RefreshToken},
			"client_id":     {e.webID},
			"client_secret": {e.webSec},
		}.Encode()
		req, err = http.NewRequest(http.MethodPost, u, strings.NewReader(""))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err = noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("the refresh in the query was refused: %d %s", resp.StatusCode, bodyOf(t, resp))
		}
		t.Logf("a long-lived refresh token was accepted from the query string: %d", resp.StatusCode)
	}
}

// PROBE 24 — the net/http semantics that PROTO-1 rests on, isolated from Re0Auth.
//
// Asserted directly, because the whole finding hinges on it: when the BODY fails to
// parse, the first ParseForm returns an error while still committing r.Form from
// the query string, and every later call returns nil. Any wrapper that answers
// "parse error => no parameters" for one caller and "the real parameters" for the
// next is validating a different request than the library serves.
func TestProbeParseFormIsErrorOnceThenNil(t *testing.T) {
	type observation struct {
		firstErr   string
		secondErr  string
		firstForm  url.Values
		secondForm url.Values
		postForm   url.Values
	}
	got := make(chan observation, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var o observation
		err1 := r.ParseForm()
		o.firstForm = r.Form
		if err1 != nil {
			o.firstErr = err1.Error()
		}
		err2 := r.ParseForm()
		o.secondForm = r.Form
		o.postForm = r.PostForm
		if err2 != nil {
			o.secondErr = err2.Error()
		}
		got <- o
	}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/x?scope=account.id&scope=phigros.score.read",
		strings.NewReader("x=%zz"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = bodyOf(t, resp)
	o := <-got

	if o.firstErr == "" {
		t.Fatalf("the first ParseForm reported no error, so the premise is wrong: %v", o.firstForm)
	}
	if o.secondErr != "" {
		t.Fatalf("the second ParseForm still reported %q; the caching premise is wrong", o.secondErr)
	}
	if len(o.firstForm["scope"]) != 2 || len(o.secondForm["scope"]) != 2 {
		t.Fatalf("the query string was not committed to r.Form: first=%v second=%v", o.firstForm, o.secondForm)
	}
	if len(o.postForm) != 0 {
		t.Fatalf("the unparsable body contributed parameters: %v", o.postForm)
	}
	t.Logf("first ParseForm: err=%q form=%v | second: err=%q form=%v",
		o.firstErr, o.firstForm, o.secondErr, o.secondForm)
}

// PROBE 25 — the same premise seen from the OP: identical queries, one with a
// parseable body and one without, get different validation and different outcomes.
// This is the differential PROTO-1 is built on, stated as a single assertion.
func TestProbeUnparsableBodyChangesWhatTheOPValidates(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.deviceID},
		"redirect_uri":          {"https://device.example/cb"},
		"scope":                 {"account.id", "phigros.score.read"},
		"state":                 {"state-probe"},
		"code_challenge":        {pkceValue(strings.Repeat("v", 64))},
		"code_challenge_method": {"S256"},
	}.Encode()

	body := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.deviceID},
		"redirect_uri":          {"https://device.example/cb"},
		"scope":                 {"account.id", "phigros.score.read"},
		"state":                 {"state-probe"},
		"code_challenge":        {pkceValue(strings.Repeat("v", 64))},
		"code_challenge_method": {"S256"},
	}.Encode()
	wellFormed, err := http.Post(e.server.URL+"/oauth/authorize", "application/x-www-form-urlencoded",
		strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	wellRaw := bodyOf(t, wellFormed)

	req, err := http.NewRequest(http.MethodPost, e.server.URL+"/oauth/authorize?"+query,
		strings.NewReader("x=%zz"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	broken, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	brokenRaw := bodyOf(t, broken)

	t.Logf("well-formed body: %d %s", wellFormed.StatusCode, wellRaw)
	t.Logf("unparsable body:  %d %q", broken.StatusCode, broken.Header.Get("Location"))
	if wellFormed.StatusCode == broken.StatusCode {
		t.Fatalf("the two requests were treated alike (%d), so there is no seam to report",
			wellFormed.StatusCode)
	}
	if broken.StatusCode != http.StatusFound {
		t.Fatalf("the unparsable-body request was refused after all (%d): %s", broken.StatusCode, brokenRaw)
	}
}

// issueCode drives authorize -> consent -> callback and returns the code.
func issueCode(t *testing.T, e env, redirect, verifier string) string {
	t.Helper()
	q := authValues(e, redirect, []string{"account.id"})
	q.Set("code_challenge", pkceValue(verifier))
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+q.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: %d %s", resp.StatusCode, bodyOf(t, resp))
	}
	login, err := parseLocation(t, resp)
	if err != nil {
		t.Fatal(err)
	}
	id := login.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("no authRequestID in %q", resp.Header.Get("Location"))
	}
	if err := e.store.CompleteLogin(t.Context(), id, "usr_probe", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	resp = e.get(t, noRedirect, e.server.URL+"/oauth/authorize/callback?id="+urlQueryEscape(id))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback: %d %s", resp.StatusCode, bodyOf(t, resp))
	}
	cb, err := parseLocation(t, resp)
	if err != nil {
		t.Fatal(err)
	}
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q", resp.Header.Get("Location"))
	}
	return code
}
