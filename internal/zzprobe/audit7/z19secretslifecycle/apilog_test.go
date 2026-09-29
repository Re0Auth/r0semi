//go:build audit7

package z19secretslifecycle

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A non-following client: the probes care about the status and the process log,
// not about rendering the SPA behind a redirect.
var probeClient = &http.Client{
	Timeout:       10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func httpGet(rawURL string, timeout time.Duration) (int, string, error) {
	c := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := c.Get(rawURL)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(b), nil
}

func postForm(t *testing.T, target string, form url.Values) (int, string) {
	t.Helper()
	resp, err := probeClient.Post(target, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read %s: %v", target, err)
	}
	return resp.StatusCode, string(b)
}

// Z19-3 — the end-to-end version of the library-log seam: does any credential
// the process holds or is handed reach the process log while the real binary
// serves real protocol traffic?
//
// The in-process half of this is already tracked
// (internal/oidchttp/adversary_test.go::TestAdversarialProtocolErrorsDoNotLogCredentials
// captures the default slog handler inside httptest). What that fixture cannot
// show is the composition root: cmd/re0auth installs the logger
// (internal/config/logging.go::SetupLogging), the storage is the real
// memory-mode store, and the vault's own error strings, the audit sink's
// pseudonymisation and the operator/erasure planes are all wired. This probe
// plants recognisable keys and drives the endpoints that consume a credential,
// then asserts none of them appear anywhere in the process's log.
func TestZ19CredentialBatteryDoesNotReachTheProcessLog(t *testing.T) {
	const (
		clientSecret  = "Z19-CLIENT-SECRET-7be2"
		codeSecret    = "Z19-AUTHZ-CODE-8d10"
		refreshSecret = "Z19-REFRESH-TOKEN-3aa4"
		bearerSecret  = "Z19-BEARER-TOKEN-5c66"
		deviceSecret  = "Z19-DEVICE-CODE-92f1"
	)
	srv, env := startServer(t, map[string]string{"client_secret": clientSecret})

	api := srv.base
	// The client secret the process is configured with, as the OP sees it.
	form := func(extra map[string]string) url.Values {
		v := url.Values{"client_id": {"cli"}, "client_secret": {clientSecret}}
		for k, val := range extra {
			v.Set(k, val)
		}
		return v
	}

	// One request per endpoint that consumes a credential, plus the shapes that
	// make the library log an error.
	requests := []struct {
		name string
		call func() (int, string)
	}{
		{"code with a credential-shaped value", func() (int, string) {
			return postForm(t, api+"/oauth/token", form(map[string]string{
				"grant_type": "authorization_code", "code": codeSecret,
				"redirect_uri": api + "/callback",
			}))
		}},
		{"refresh with a credential-shaped value", func() (int, string) {
			return postForm(t, api+"/oauth/token", form(map[string]string{
				"grant_type": "refresh_token", "refresh_token": refreshSecret,
			}))
		}},
		{"introspection of a credential-shaped token", func() (int, string) {
			return postForm(t, api+"/oauth/introspect", form(map[string]string{"token": bearerSecret}))
		}},
		{"revocation of a credential-shaped token", func() (int, string) {
			return postForm(t, api+"/oauth/revoke", form(map[string]string{"token": bearerSecret}))
		}},
		{"device poll with a credential-shaped code", func() (int, string) {
			return postForm(t, api+"/oauth/token", url.Values{
				"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
				"device_code": {deviceSecret}, "client_id": {"cli"},
			})
		}},
		{"business plane with a credential-shaped bearer", func() (int, string) {
			req, err := http.NewRequest(http.MethodGet, api+"/v1/me", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+bearerSecret)
			resp, err := probeClient.Do(req)
			if err != nil {
				t.Fatalf("GET /v1/me: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			return resp.StatusCode, string(b)
		}},
		{"authorize with a bad client", func() (int, string) {
			q := url.Values{
				"client_id": {"no-such-client"}, "response_type": {"code"},
				"redirect_uri": {api + "/callback"}, "scope": {"openid"},
				"state": {"st-" + codeSecret}, "code_challenge": {"x"}, "code_challenge_method": {"S256"},
			}
			code, body, err := httpGet(api+"/oauth/authorize?"+q.Encode(), 10*time.Second)
			if err != nil {
				t.Fatalf("GET /oauth/authorize: %v", err)
			}
			return code, body
		}},
	}
	for _, r := range requests {
		status, body := r.call()
		t.Logf("%-52s -> %d %s", r.name, status, truncate(body, 120))
	}

	time.Sleep(500 * time.Millisecond) // let the log drain
	logText := srv.log.String()

	planted := map[string]string{
		"the KEK (environment)":           env["RE0AUTH_KEK"],
		"the OP token key (environment)":  env["RE0AUTH_OIDC_TOKEN_KEY"],
		"the signing key (environment)":   env["RE0AUTH_OIDC_SIGNING_KEY"],
		"the client secret (environment)": clientSecret,
		"an authorization code presented": codeSecret,
		"a refresh token presented":       refreshSecret,
		"a bearer token presented":        bearerSecret,
		"a device code presented":         deviceSecret,
		"a state carrying a credential":   "st-" + codeSecret,
	}
	for what, value := range planted {
		if strings.Contains(logText, value) {
			t.Errorf("DISCLOSURE: %s appears in the process log.\nlog:\n%s", what, logText)
		}
	}
	if t.Failed() {
		return
	}
	t.Logf("the whole process log (%d bytes) carries none of the %d planted values",
		len(logText), len(planted))

	// Control: the battery really exercised the process — the log is the startup
	// log plus whatever the OP wrote, and the process is still alive.
	if !strings.Contains(logText, "listening") {
		t.Errorf("control: no startup log, so the process under test is not the one probed:\n%s", logText)
	}
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
