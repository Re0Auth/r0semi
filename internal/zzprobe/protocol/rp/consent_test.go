//go:build audit5

package rp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// rfc7636Challenge is BASE64URL(SHA256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")),
// the example pair from RFC 7636 appendix B. It is fixed so the probe can redeem
// the code it is handed.
const rfc7636Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

// The consent interaction seam: the handle a browser holds after /oauth/authorize
// must be usable by that browser and no other, and a decision must be single-use.
// These are guards for properties the shipped tests also assert
// (internal/httpapi/consent_owner_test.go); they are here as the RP-side record
// that the seam holds when driven over the real routes.

// authorizeRP drives /oauth/authorize for the test client and returns the consent
// handle.
func authorizeRP(t *testing.T, c *http.Client, base, state string) string {
	t.Helper()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"cli"},
		"redirect_uri":          {"https://app.example/cb"},
		"scope":                 {"account.id"},
		"state":                 {state},
		"code_challenge":        {rfc7636Challenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	resp := rpGet(t, c, base+"/oauth/authorize?"+q)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	handle := loc.Query().Get("id")
	if handle == "" {
		t.Fatalf("no consent handle in %q", resp.Header.Get("Location"))
	}
	return handle
}

func rpSignIn(t *testing.T, c *http.Client, base, code string) {
	t.Helper()
	state, status := rpStart(t, c, base, "github", "")
	if status != http.StatusFound {
		t.Fatalf("start = %d", status)
	}
	if got, loc, body := rpCallback(t, c, base, "github", "code="+code+"&state="+url.QueryEscape(state)); got != http.StatusSeeOther {
		t.Fatalf("sign in = %d loc=%q body=%q", got, loc, body)
	}
}

func consentView(t *testing.T, c *http.Client, base, handle string) (csrf string, status int) {
	t.Helper()
	resp := rpGet(t, c, base+"/v1/authorization_requests/"+handle)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	csrf, _ = body["csrf_token"].(string)
	return csrf, resp.StatusCode
}

func consentDecide(t *testing.T, c *http.Client, base, handle, csrf, decision string) (int, string) {
	t.Helper()
	code, redirect, err := consentDecideRaw(c, base, handle, csrf, decision)
	if err != nil {
		t.Fatal(err)
	}
	return code, redirect
}

// consentDecideRaw is the goroutine-safe half: no *testing.T, so concurrent
// probes can call it.
func consentDecideRaw(c *http.Client, base, handle, csrf, decision string) (int, string, error) {
	payload, _ := json.Marshal(map[string]any{"decision": decision, "scopes": []string{"account.id"}})
	req, err := http.NewRequest(http.MethodPost, base+"/v1/authorization_requests/"+handle+"/decision", bytes.NewReader(payload))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	redirect, _ := body["redirect_to"].(string)
	return resp.StatusCode, redirect, nil
}

// The direction that has to work, including when the browser was already signed
// in before the authorization request was made (the login hook is what binds the
// handle, so a signed-in browser depends on it still running).
func TestRPConsentHandleIsUsableByItsOwnBrowser(t *testing.T) {
	env := newRPEnv(t)
	browser := rpBrowser(t)
	rpSignIn(t, browser, env.base, "c")

	handle := authorizeRP(t, browser, env.base, "st-1")
	csrf, status := consentView(t, browser, env.base, handle)
	if status != http.StatusOK || csrf == "" {
		t.Fatalf("consent view = %d csrf=%q", status, csrf)
	}
	code, redirect := consentDecide(t, browser, env.base, handle, csrf, "approve")
	if code != http.StatusOK || redirect == "" {
		t.Fatalf("decision = %d redirect=%q", code, redirect)
	}
	if !strings.HasPrefix(redirect, "/") {
		t.Fatalf("the decision redirected off-origin: %q", redirect)
	}
	// Following the OP's own redirect has to land the client on its registered
	// redirect_uri with the code and the caller's state.
	resp := rpGet(t, browser, env.base+redirect)
	_ = resp.Body.Close()
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "code=") || !strings.Contains(loc, "state=st-1") {
		t.Fatalf("the approved flow did not deliver a code to the client: %d %q", resp.StatusCode, loc)
	}
	if !strings.HasPrefix(loc, "https://app.example/cb") {
		t.Fatalf("the code went to %q", loc)
	}
	// The decision consumed the handle.
	if _, again := consentView(t, browser, env.base, handle); again != http.StatusNotFound {
		t.Errorf("the consent handle was still readable after approval: %d", again)
	}
}

// A handle is bound to the browser that created it: a relayed link is not enough
// to read or decide somebody else's authorization request.
func TestRPConsentHandleFromAnotherBrowserIsRefused(t *testing.T) {
	env := newRPEnv(t)
	owner := rpBrowser(t)
	rpSignIn(t, owner, env.base, "c")
	handle := authorizeRP(t, owner, env.base, "st-1")

	other := rpBrowser(t)
	rpSignIn(t, other, env.base, "other-code")
	if _, status := consentView(t, other, env.base, handle); status != http.StatusNotFound {
		t.Errorf("another browser read the handle: %d", status)
	}
	csrfOther, _ := consentView(t, other, env.base, authorizeRP(t, other, env.base, "st-2"))
	if code, _ := consentDecide(t, other, env.base, handle, csrfOther, "approve"); code != http.StatusNotFound {
		t.Errorf("another browser decided the handle: %d", code)
	}
	// Anti-vacuity: the owner still can.
	if csrf, status := consentView(t, owner, env.base, handle); status != http.StatusOK || csrf == "" {
		t.Fatalf("the owner lost access to its own handle: %d", status)
	}
}

// The decision is a write, so it needs the session's CSRF token.
func TestRPConsentDecisionNeedsTheSessionsCSRFToken(t *testing.T) {
	env := newRPEnv(t)
	browser := rpBrowser(t)
	rpSignIn(t, browser, env.base, "c")
	handle := authorizeRP(t, browser, env.base, "st-1")

	if code, _ := consentDecide(t, browser, env.base, handle, "", "approve"); code != http.StatusForbidden {
		t.Errorf("a decision with no CSRF token = %d, want 403", code)
	}
	// A token from another session must not work either.
	other := rpBrowser(t)
	rpSignIn(t, other, env.base, "other-code")
	csrfOther, _ := consentView(t, other, env.base, authorizeRP(t, other, env.base, "st-2"))
	if code, _ := consentDecide(t, browser, env.base, handle, csrfOther, "approve"); code != http.StatusForbidden {
		t.Errorf("a decision with another session's CSRF token = %d, want 403", code)
	}
	// Anti-vacuity.
	csrf, status := consentView(t, browser, env.base, handle)
	if status != http.StatusOK {
		t.Fatalf("control view = %d", status)
	}
	if code, _ := consentDecide(t, browser, env.base, handle, csrf, "approve"); code != http.StatusOK {
		t.Errorf("control decision = %d", code)
	}
}

// rfc7636Verifier is the RFC 7636 appendix B code verifier, paired with the
// challenge authorizeRP sends. Using a known pair is what lets this probe
// exchange the code it is handed.
const rfc7636Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

// The redirect ApproveAuthorization returns is the browser's next URL, and it can
// be visited again: a reload, a back button, or a replay from history fetches it
// a second time. Each visit mints another authorization code at the store
// (internal/store/memory/oidc.go SaveAuthCode keys by code hash, so a second code
// is added rather than replacing the first).
//
// The one-grant property is not broken by this -- only the first code redeemed
// claims the auth request (pinned separately by
// internal/zzprobe/concurrency/single_use_test.go) -- but the extras are issued,
// delivered, and left behind until the request TTL, and the code a browser was
// shown first is dead without anyone being told.
func TestRPConsentApprovalRedirectIsReplayable(t *testing.T) {
	env := newRPEnv(t)
	browser := rpBrowser(t)
	rpSignIn(t, browser, env.base, "c")

	sum := sha256.Sum256([]byte(rfc7636Verifier))
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != rfc7636Challenge {
		t.Fatalf("the probe's challenge/verifier pair is wrong: %s", got)
	}

	handle := authorizeRP(t, browser, env.base, "st-replay")
	csrf, status := consentView(t, browser, env.base, handle)
	if status != http.StatusOK {
		t.Fatalf("consent view = %d", status)
	}
	code, redirect := consentDecide(t, browser, env.base, handle, csrf, "approve")
	if code != http.StatusOK || redirect == "" {
		t.Fatalf("decision = %d redirect=%q", code, redirect)
	}

	var codes []string
	for i := 0; i < 2; i++ {
		resp := rpGet(t, browser, env.base+redirect)
		_ = resp.Body.Close()
		u, err := url.Parse(resp.Header.Get("Location"))
		if err != nil || u.Query().Get("code") == "" {
			t.Fatalf("visit %d of the approval redirect returned %q", i, resp.Header.Get("Location"))
		}
		codes = append(codes, u.Query().Get("code"))
	}
	if codes[0] != codes[1] {
		t.Errorf("the approval redirect was replayable: two visits produced two authorization codes")
	}

	// What the extra code is worth: the first redemption claims the request.
	first := exchangeCode(t, env.base, codes[0])
	second := exchangeCode(t, env.base, codes[1])
	if codes[0] != codes[1] {
		t.Logf("first code -> %d, second code -> %d", first, second)
	}
	if first != http.StatusOK {
		t.Errorf("the code the browser was handed did not exchange: %d", first)
	}
	if second == http.StatusOK && codes[0] != codes[1] {
		t.Errorf("one consent produced two live token grants")
	}
}

// exchangeCode redeems a code in the RP env's client, with the PKCE verifier the
// challenge was built from.
func exchangeCode(t *testing.T, base, code string) int {
	t.Helper()
	form := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"cli"}, "code": {code},
		"redirect_uri": {"https://app.example/cb"}, "code_verifier": {rfc7636Verifier},
	}.Encode()
	resp, err := http.Post(base+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// A handle decides once. Concurrent decisions are the interesting case: the
// session check is a read of session state, and the handle is only unbound after
// the store call returns.
func TestRPConsentDecisionConcurrency(t *testing.T) {
	env := newRPEnv(t)
	browser := rpBrowser(t)
	rpSignIn(t, browser, env.base, "c")
	handle := authorizeRP(t, browser, env.base, "st-1")
	csrf, status := consentView(t, browser, env.base, handle)
	if status != http.StatusOK {
		t.Fatalf("consent view = %d", status)
	}

	const workers = 8
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		ok        int
		redirects = map[string]bool{}
		failures  []error
	)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			code, redirect, err := consentDecideRaw(browser, env.base, handle, csrf, "approve")
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures = append(failures, err)
				return
			}
			if code == http.StatusOK {
				ok++
				redirects[redirect] = true
			}
		}()
	}
	close(start)
	wg.Wait()

	for _, err := range failures {
		t.Errorf("concurrent decision failed at the transport: %v", err)
	}
	if ok == 0 {
		t.Fatal("no decision succeeded: the probe never reached the path")
	}
	if ok > 1 {
		t.Errorf("%d of %d concurrent decisions succeeded; distinct redirects=%d", ok, workers, len(redirects))
		for r := range redirects {
			t.Logf("redirect: %s", r)
		}
	}
	t.Log(fmt.Sprintf("%d/%d decisions succeeded, %d distinct redirects", ok, workers, len(redirects)))

	// What the extra successes actually bought: follow the redirect the decisions
	// returned and collect the authorization codes the client would receive.
	codes := map[string]int{}
	for redirect := range redirects {
		for i := 0; i < 3; i++ {
			resp := rpGet(t, browser, env.base+redirect)
			_ = resp.Body.Close()
			loc := resp.Header.Get("Location")
			u, err := url.Parse(loc)
			if err != nil || !strings.HasPrefix(loc, "https://app.example/cb") {
				t.Errorf("following the approved redirect reached %q (%d)", loc, resp.StatusCode)
				continue
			}
			codes[u.Query().Get("code")]++
		}
	}
	if len(codes) > 1 {
		t.Errorf("one consent produced %d distinct authorization codes: %v", len(codes), codes)
	}
	for code, n := range codes {
		t.Logf("code %q was delivered %d times", code, n)
	}
}
