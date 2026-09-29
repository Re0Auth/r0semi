//go:build audit7

// Upstream Kit / reference-source probe: cascade revocation and the token that
// identifies the session.
//
// upstreamkit's own contract says the source resolves the subject from the token
// and MAY consume it, because "the binding is removed either way"
// (upstreamkit/server.go:80-92). Re0Auth's side deliberately removes nothing
// unless the source confirmed (internal/federation/revocation.go:103-165). The
// reference source resolves the subject by *consuming* the refresh token
// (referencesource/cascade.go:80-86), so the two halves disagree on the failure
// path: the upstream call fails, the binding stays, and Re0Auth's retry — the
// only remedy it has — can no longer name the session.
package z14kitrptaptap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/referencesource"
	"github.com/Re0Auth/r0semi/upstreamkit"
	"github.com/Re0Auth/r0semi/vault"
)

const (
	probeGame         = "phigros"
	probeSource       = "z14probe"
	probeSubject      = "openid_z14_probe"
	probeClientID     = "re0auth"
	probeClientSecret = "z14-probe-secret"
	probeCallback     = "https://re0auth.test/auth/upstream/phigros/z14probe/callback"
	probeVerifier     = "z14-probe-code-verifier-0123456789abcdefghijkl"
)

// probeLogin is a source login that establishes a session (so the Kit's Consent
// hook can read it) and that advertises the cascade capability while its
// upstream call always fails.
type probeLogin struct {
	mu    sync.Mutex
	calls int
}

// Mount implements referencesource.Login. The route exists only so the probe can
// put a subject into the shared session the way a real QR login does.
func (l *probeLogin) Mount(mux *http.ServeMux, establish referencesource.Establish) {
	mux.HandleFunc("GET /login/probe", func(w http.ResponseWriter, r *http.Request) {
		err := establish(r.Context(), referencesource.Principal{
			Subject: probeSubject, Display: "probe user",
			Credential: []byte(`{"native":"credential"}`),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// RevokeUpstream implements referencesource.UpstreamRevoker. It always fails,
// which is the "the source could not be reached, or refused" case Re0Auth's
// CascadeRevoke keeps the binding for.
func (l *probeLogin) RevokeUpstream(context.Context, string, []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	return errors.New("probe: the upstream session could not be ended")
}

func (l *probeLogin) callCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

func probeVault(t *testing.T) vault.Service {
	t.Helper()
	wrapper, err := vault.NewLocalKeyWrapper("z14probe", bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := vault.NewService(vault.NewMemoryRepo(), wrapper, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// startProbeSource serves a reference source at a fixed loopback issuer, the
// same construction the package's own tests use.
func startProbeSource(t *testing.T, login *probeLogin, v vault.Service) (*httptest.Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	issuer := "http://" + ln.Addr().String()
	src, err := referencesource.New(referencesource.Config{
		Discovery: upstreamkit.Config{
			Game: probeGame, Source: probeSource, DisplayName: "Z14 probe source",
			Issuer: issuer, TokenClass: upstreamkit.TokenRevocable,
		},
		Provider: probeGame,
		Downstream: referencesource.Client{
			ID: probeClientID, Secret: probeClientSecret, RedirectURIs: []string{probeCallback},
		},
	}, referencesource.Deps{
		Logins: []referencesource.Login{login},
		Vault:  v,
		Reader: referencesource.StaticReader{},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(src.Handler())
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, issuer
}

func newProbeClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func newProbeRequest(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target, r)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func mustDo(t *testing.T, c *http.Client, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp, string(body)
}

// TestZ14FailedCascadeBurnsTheRefreshTokenSoTheRetryNeverReachesUpstream drives
// the whole real path: a session at the source, an authorization code through
// the Kit's /oauth/authorize, a token pair through /oauth/token, then the same
// cascade revocation twice — the retry Re0Auth makes after a failure.
//
// The assertion is the revoker's call count. A source that resolved the subject
// without consuming the token reaches RevokeUpstream on both attempts; this one
// reaches it once and answers the second attempt from a token that no longer
// resolves.
func TestZ14FailedCascadeBurnsTheRefreshTokenSoTheRetryNeverReachesUpstream(t *testing.T) {
	login := &probeLogin{}
	v := probeVault(t)
	_, issuer := startProbeSource(t, login, v)
	c := newProbeClient(t)

	// 1. A source session, the way a real login establishes one.
	resp, body := mustDo(t, c, newProbeRequest(t, http.MethodGet, issuer+"/login/probe", ""))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("login probe: status %d body=%q", resp.StatusCode, body)
	}

	// 2. The Kit's authorize endpoint, with PKCE.
	sum := sha256.Sum256([]byte(probeVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {probeClientID},
		"redirect_uri":          {probeCallback},
		"scope":                 {upstreamkit.AccountScope},
		"state":                 {"z14-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	resp, body = mustDo(t, c, newProbeRequest(t, http.MethodGet, issuer+"/oauth/authorize?"+q.Encode(), ""))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: status %d body=%q", resp.StatusCode, body)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("authorize redirected without a code: %s", loc)
	}

	// 3. The token exchange, with the source's own client credentials.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {probeCallback},
		"code_verifier": {probeVerifier},
	}
	tokReq := newProbeRequest(t, http.MethodPost, issuer+"/oauth/token", form.Encode())
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokReq.SetBasicAuth(probeClientID, probeClientSecret)
	resp, body = mustDo(t, c, tokReq)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token: status %d body=%q", resp.StatusCode, body)
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil {
		t.Fatalf("token body %q: %v", body, err)
	}
	if tok.RefreshToken == "" || tok.AccessToken == "" {
		t.Fatalf("token response held no token pair: %q", body)
	}

	// 4. Cascade revocation, twice, exactly the way Re0Auth sends it
	//    (internal/federation/revocation.go:148-155): the refresh token names the
	//    durable authorization, so that is what it prefers.
	cascade := func() (int, string) {
		revForm := url.Values{"token": {tok.RefreshToken}, "token_type_hint": {"refresh_token"}}
		req := newProbeRequest(t, http.MethodPost, issuer+"/oauth/cascade_revocation", revForm.Encode())
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(probeClientID, probeClientSecret)
		r, b := mustDo(t, c, req)
		return r.StatusCode, b
	}
	firstStatus, firstBody := cascade()
	firstCalls := login.callCount()
	secondStatus, secondBody := cascade()
	secondCalls := login.callCount()

	t.Logf("cascade #1: %d %s (RevokeUpstream calls=%d)", firstStatus, strings.TrimSpace(firstBody), firstCalls)
	t.Logf("cascade #2: %d %s (RevokeUpstream calls=%d)", secondStatus, strings.TrimSpace(secondBody), secondCalls)

	// The binding must still be there: Re0Auth removes nothing unless the source
	// confirmed, so the credential in the vault is the only way to try again.
	useErr := v.Use(t.Context(), vault.Identity{Subject: probeSubject, Provider: probeGame}, func([]byte) error { return nil })
	t.Logf("the credential is still in the source's vault after both attempts: %v", useErr == nil)

	if firstCalls != 1 {
		t.Fatalf("setup: the first cascade reached RevokeUpstream %d times, want 1", firstCalls)
	}
	if secondCalls == firstCalls {
		t.Errorf("a failed cascade made every later attempt impossible: the second, identical request never reached RevokeUpstream (calls stayed at %d).\n"+
			"cascade #1 = %d %s, cascade #2 = %d %s.\n"+
			"referencesource/cascade.go:80-86 resolves the subject with tokens.ConsumeRefresh, which is destructive, and it runs before the upstream call; Re0Auth keeps the binding on failure (internal/federation/revocation.go:153-155), so the retry it is designed to make can no longer name the session. The user's \"sign out everywhere\" is then permanently unservable without unbinding and re-binding.",
			secondCalls, firstStatus, strings.TrimSpace(firstBody), secondStatus, strings.TrimSpace(secondBody))
	}
}
