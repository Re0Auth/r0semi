//go:build audit5

package protocol

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// PROBE 22 — the duplicate-parameter refusal is defeatable, and with it the scope
// gate it was protecting.
//
// serveOAuth calls requestParams(r) five times before the library runs, and
// requestParams is written as
//
//	if err := r.ParseForm(); err != nil { return url.Values{} }
//	return r.Form
//
// The FIRST call — the duplicate check, internal/oidchttp/oidchttp.go:440 — is the
// one that pays the error: net/http's ParseForm returns the body's parse error
// while still committing `r.Form` from the query string, so the duplicate check
// sees an empty set and passes. Every later call finds `r.PostForm` non-nil and
// therefore no error at all, so the PKCE, two-identity and scope checks see the
// real (query-string) parameters. One body the server cannot parse is enough to
// switch the duplicate rule off for that request.
//
// Two consequences, and the second is the interesting one:
//
//  1. RFC 6749 §3.1 / ADR-0005 point 4 ("重复参数一律拒绝") does not hold for such a
//     request, even though TestAdversarialDuplicateParametersAreRejected says it does
//     — that guard sends a well-formed body.
//  2. RFC 6749 §3.1 is not only about tidiness. The scope gate reads ONE value
//     (`q.Get("scope")`), so if the library's decoder collects all of them, a client
//     registered for one scope obtains a grant for another — the A1-1 shape again.
func TestProbeUnparsableBodyDefeatsTheDuplicateParameterRefusal(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	// Control: the same duplicate, in a well-formed request, IS refused.
	duplicated := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.deviceID},
		"redirect_uri":          {"https://device.example/cb"},
		"scope":                 {"account.id", "phigros.score.read"}, // the second is not registered
		"state":                 {"state-probe"},
		"code_challenge":        {pkceValue(strings.Repeat("v", 64))},
		"code_challenge_method": {"S256"},
	}
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+duplicated.Encode())
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("control failed: a duplicated scope parameter was not refused: %d %s",
			resp.StatusCode, bodyOf(t, resp))
	}

	// The seam: the same query on a POST whose body cannot be parsed.
	req, err := http.NewRequest(http.MethodPost, e.server.URL+"/oauth/authorize?"+duplicated.Encode(),
		strings.NewReader("x=%zz"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	seam, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := bodyOf(t, seam)
	t.Logf("the unparsable-body request answered %d %q", seam.StatusCode, seam.Header.Get("Location"))

	if seam.StatusCode != http.StatusFound || strings.Contains(seam.Header.Get("Location"), "error=") {
		t.Logf("the duplicate check still refused it (%d): %s", seam.StatusCode, body)
		return
	}
	t.Errorf("a request with a duplicated `scope` was accepted because its body was unparsable: %d %q (ADR-0005 point 4). Body: %s",
		seam.StatusCode, seam.Header.Get("Location"), body)

	// It was accepted: which scopes did the library record?
	login, err := parseLocation(t, seam)
	if err != nil {
		t.Fatal(err)
	}
	id := login.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("no authRequestID in %q", seam.Header.Get("Location"))
	}
	ar, err := e.store.AuthRequestByID(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	scopes := ar.GetScopes()
	t.Logf("the accepted auth request carries scopes %v (the pre-flight checked %q)",
		scopes, duplicated["scope"][0])
	for _, s := range scopes {
		if s != "account.id" {
			t.Errorf("an unregistered scope %q reached the auth request", s)
		}
	}
	if len(scopes) == 0 {
		t.Errorf("the grant silently became EMPTY (ADR-0005 point 2 forbids an empty scope set)")
	}
}

// PROBE 23 — the same seam on the device endpoint. The pre-flight there reads one
// value of `scope` (internal/oidchttp/oidchttp.go validateDeviceAuthorization ->
// form.Get + strings.Fields), and the library stores the request's scopes verbatim
// (pkg/op/device.go createDeviceAuthorization -> StoreDeviceAuthorization), so a
// second scope value that the pre-flight never saw would be persisted and, from
// there, approved and minted — the escalation A1-1 closed for the well-formed case.
func TestProbeUnparsableBodyDefeatsTheDeviceScopeGate(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	form := url.Values{
		"client_id": {e.deviceID},
		"scope":     {"account.id", "phigros.score.read"},
	}

	// Control: duplicated scope in a well-formed body is refused.
	resp, raw := e.postForm(t, "/oauth/device_authorization", form, "", "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("control failed: duplicated scope = %d %s", resp.StatusCode, raw)
	}

	// The seam: everything in the query, body unparsable.
	req, err := http.NewRequest(http.MethodPost,
		e.server.URL+"/oauth/device_authorization?"+form.Encode(), strings.NewReader("x=%zz"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	seam, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := bodyOf(t, seam)
	t.Logf("the unparsable-body device request answered %d %s", seam.StatusCode, body)
	if seam.StatusCode != http.StatusOK {
		return
	}
	issued := decodeJSON(t, body)
	userCode, _ := issued["user_code"].(string)
	deviceCode, _ := issued["device_code"].(string)
	if userCode == "" || deviceCode == "" {
		t.Fatalf("no user_code/device_code in %s", body)
	}
	state, err := e.store.DeviceByUserCode(t.Context(), userCode)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("the stored device authorization carries scopes %v", state.Scopes)
	for _, s := range state.Scopes {
		if s != "account.id" {
			t.Errorf("a client registered only for account.id obtained a device authorization for %q", s)
		}
	}

	// The scope the gate was supposed to stop does not stop at the authorization:
	// the human approves (the consent page renders the catalogue, not the client's
	// registration), and the token carries it.
	if err := e.store.ApproveDevice(t.Context(), userCode, "usr_probe", nil); err != nil {
		t.Fatalf("approval: %v", err)
	}
	pollResp, pollRaw := e.postForm(t, "/oauth/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {e.deviceID},
	}, "", "")
	if pollResp.StatusCode != http.StatusOK {
		t.Fatalf("the approved device code could not be exchanged: %d %s", pollResp.StatusCode, pollRaw)
	}
	minted := asTokens(t, decodeJSON(t, pollRaw))
	t.Logf("the minted token's scope is %q", minted.Scope)
	if !strings.Contains(minted.Scope, "phigros.score.read") {
		t.Fatalf("the unregistered scope did not reach a live token: %s", pollRaw)
	}
	if minted.AccessToken == "" {
		t.Fatalf("no access token: %s", pollRaw)
	}

	// And the access token is live against the business plane's introspector.
	info, err := e.handler.Introspect(t.Context(), minted.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(info.Scopes))
	for _, s := range info.Scopes {
		got = append(got, s.String())
	}
	t.Logf("the live token introspects as active=%v client=%s scopes=%v", info.Active, info.ClientID, got)
	for _, s := range got {
		if s == "phigros.score.read" {
			t.Errorf("a live token carries the scope the client is not registered for")
		}
	}
}
