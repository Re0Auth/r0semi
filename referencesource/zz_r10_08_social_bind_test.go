//go:build audit5

package referencesource_test

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/testoidc"
	"github.com/Re0Auth/r0semi/vault"
)

// R10-08: the social login's callback has no browser binding.
//
// The OAuth `state` is stored server-side keyed by its own value, so it is a
// bearer token: whoever presents it is treated as the initiator, and
// `establish` writes the IdP's subject into the PRESENTER's session and vault.
// An attacker can start a login in their own browser, hand the resulting
// callback URL to a victim, and have the attacker's upstream account bound into
// the victim's session (login CSRF / forced login). PKCE does not help — the
// verifier lives only in the server-side state.
//
// The probes below fail on the code as found. The package's own TapTap login
// already carries the fix's shape: a bind cookie that only the initiating
// browser holds.

func bindBrowser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func callbackURL(base, state, code string) string {
	return base + "/login/google/callback?state=" + url.QueryEscape(state) + "&code=" + code
}

func r10SocialCredentialExists(t *testing.T, repo vault.Service, subject string) bool {
	t.Helper()
	exists, err := repo.Exists(context.Background(), vault.Identity{Subject: subject, Provider: "phigros"})
	if err != nil {
		t.Fatal(err)
	}
	return exists
}

// TestR10_08CallbackFromADifferentBrowserIsRejected is the finding itself.
func TestR10_08CallbackFromADifferentBrowserIsRejected(t *testing.T) {
	provider := testoidc.New()
	defer provider.Close()
	_, srv, deps := socialSource(t, provider)

	attacker := bindBrowser(t)
	loc := startSocial(t, attacker, srv.URL)
	provider.SetNonce(loc.Query().Get("nonce"))
	state := loc.Query().Get("state")

	victim := bindBrowser(t)
	resp, err := victim.Get(callbackURL(srv.URL, state, "abc"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("R10-08: a callback presented by a different browser than the one that started the "+
			"login was accepted (%d); the attacker's upstream subject is written into the victim's "+
			"session and vault. No bind cookie is issued or checked", resp.StatusCode)
	}
	if r10SocialCredentialExists(t, deps.Vault, "google:oidc-user-1") {
		t.Fatal("R10-08: the rejected callback still enrolled the attacker's credential")
	}
}

// TestR10_08ForgedBindCookieIsRejected: possessing a cookie NAME is not enough;
// the value has to match the state's binding.
func TestR10_08ForgedBindCookieIsRejected(t *testing.T) {
	provider := testoidc.New()
	defer provider.Close()
	_, srv, deps := socialSource(t, provider)

	attacker := bindBrowser(t)
	resp, err := attacker.Get(srv.URL + "/login/google/start?return_to=/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("start did not redirect: %v", err)
	}
	provider.SetNonce(loc.Query().Get("nonce"))
	state := loc.Query().Get("state")

	var bindName string
	for _, c := range resp.Cookies() {
		if strings.Contains(c.Name, "bind") {
			bindName = c.Name
			break
		}
	}
	if bindName == "" {
		t.Fatal("R10-08: the start response set no bind cookie, so a callback cannot be tied to " +
			"the browser that started it")
	}

	u, _ := url.Parse(srv.URL)
	victim := bindBrowser(t)
	victim.Jar.SetCookies(u, []*http.Cookie{{
		Name: bindName, Value: "forged-bind-value", Path: "/login/",
	}})
	cbResp, err := victim.Get(callbackURL(srv.URL, state, "abc"))
	if err != nil {
		t.Fatal(err)
	}
	cbResp.Body.Close()
	if cbResp.StatusCode == http.StatusOK {
		t.Fatal("R10-08: a forged bind-cookie value was accepted")
	}
	if r10SocialCredentialExists(t, deps.Vault, "google:oidc-user-1") {
		t.Fatal("R10-08: the forged callback still enrolled the credential")
	}
}

// TestR10_08InitiatingBrowserStillCompletes is the control: the fix must not
// refuse the browser that actually started the login.
func TestR10_08InitiatingBrowserStillCompletes(t *testing.T) {
	provider := testoidc.New()
	defer provider.Close()
	_, srv, _ := socialSource(t, provider)

	browser := bindBrowser(t)
	loc := startSocial(t, browser, srv.URL)
	provider.SetNonce(loc.Query().Get("nonce"))

	if got := socialCallback(t, browser, srv.URL, loc.Query().Get("state"), "abc"); got != "google:oidc-user-1" {
		t.Fatalf("the initiating browser was refused: subject = %q", got)
	}
}

// TestR10_08BindCookieIsScopedAndNotEchoed pins the cookie's shape: HttpOnly, a
// path that covers the callback, and a session (not persistent) cookie.
func TestR10_08BindCookieIsScopedAndNotEchoed(t *testing.T) {
	provider := testoidc.New()
	defer provider.Close()
	_, srv, _ := socialSource(t, provider)

	browser := bindBrowser(t)
	resp, err := browser.Get(srv.URL + "/login/google/start?return_to=/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var bind *http.Cookie
	for _, c := range resp.Cookies() {
		if strings.Contains(c.Name, "bind") {
			bind = c
		}
	}
	if bind == nil {
		t.Fatal("R10-08: the start response set no bind cookie")
	}
	if !bind.HttpOnly {
		t.Fatal("the bind cookie is not HttpOnly")
	}
	if bind.SameSite != http.SameSiteLaxMode {
		t.Fatalf("bind cookie SameSite = %v", bind.SameSite)
	}
	if !strings.HasPrefix(bind.Path, "/login") {
		t.Fatalf("bind cookie Path = %q, want a /login prefix so it reaches the callback", bind.Path)
	}
	if bind.MaxAge != 0 {
		t.Fatalf("bind cookie MaxAge = %d, want a session cookie", bind.MaxAge)
	}
}
