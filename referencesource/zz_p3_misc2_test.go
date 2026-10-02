package referencesource_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/referencesource"
)

// newProbeBrowser is a client with its own cookie jar: the identity of one
// browser, which is what the probes below are about.
func newProbeBrowser(t *testing.T) *http.Client {
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

// loginState asks the source's /login who this browser is, the way a person
// checking the page would.
func loginState(t *testing.T, browser *http.Client, base string) string {
	t.Helper()
	resp, err := browser.Get(base + "/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/login: status %d", resp.StatusCode)
	}
	var out struct {
		State   string `json:"state"`
		Subject string `json:"subject"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.State + "/" + out.Subject
}

func readAllString(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// S06-10 is not probed here. The fix the issue names — pass the anonymous
// `return_to` through `safeurl.RelativePath` before storing and echoing it —
// cannot be applied from this package: `safeurl` lives in `internal/safeurl`,
// and `referencesource` is a public library, so the import makes
// internal/archtest's TestPublicLibrariesDoNotDependOnInternal fail
// (docs/architecture.md §4). The options — promote `safeurl` to a public package,
// or give the public libraries their own copy — are a layering decision for the
// repository owner, recorded as NEEDS-DECISION in _p3_progress_misc2.md.

// Z14-6 probe. The TapTap attempt is created on POST /login/taptap/challenge,
// which returns the attempt id to the caller; GET /login/taptap/poll?id=<id>
// then completes the login for whoever sent it. Nothing used to say those two
// requests came from the same browser, so the id was the whole capability: a
// second browser that only loaded the poll URL — a link, an image, a redirect —
// was logged in as the account the initiator had approved at TapTap.
//
// The control in the same test is the initiating browser, which must still
// complete: a "fix" that rejected every poll would pass the victim half and
// break the login.
func TestZ14_6TapTapPollIsBoundToTheStartingBrowser(t *testing.T) {
	_, srv, tap, clock, _ := newTapTapSource(t)

	// The attacker's browser starts a real attempt and its TapTap account is
	// approved upstream.
	attacker := newProbeBrowser(t)
	challenge := startLogin(t, attacker, srv.URL)
	tap.approve()
	clock.advance(2 * time.Second)

	// The victim: a separate browser with no relationship to the attempt.
	victim := newProbeBrowser(t)
	if got := loginState(t, victim, srv.URL); got != "anonymous/" {
		t.Fatalf("setup: the victim browser is already %q", got)
	}

	resp, err := victim.Get(srv.URL + "/login/taptap/poll?id=" + url.QueryEscape(challenge.ID))
	if err != nil {
		t.Fatal(err)
	}
	victimBody := readAllString(t, resp)
	victimState := loginState(t, victim, srv.URL)
	if victimState != "anonymous/" {
		t.Errorf("a browser that only loaded GET /login/taptap/poll?id=%s ended as %q (poll said %s).\n"+
			"The attempt id is returned to the initiator and the poll acts on it for any caller "+
			"(referencesource/taptap.go); establish overwrites the caller's session subject "+
			"(referencesource/source.go). The poll must present the binding the challenge set on "+
			"the browser that started the attempt.", challenge.ID, victimState, strings.TrimSpace(victimBody))
	}

	// The attempt must survive the stranger's poll: it is the owner's, and the
	// owner's own poll still confirms.
	if progress := pollLogin(t, attacker, srv.URL, challenge.ID); progress.State != "confirmed" {
		t.Errorf("the initiating browser's poll = %q, want confirmed: a rejected stranger must not "+
			"cost the owner the attempt", progress.State)
	}
	if got := loginState(t, attacker, srv.URL); got != "confirmed/openid-1" {
		t.Errorf("the initiating browser ended as %q, want confirmed/openid-1", got)
	}
}

// Z14-6, second half: the binding is a cookie, and it must not travel in the
// challenge body. The body is handed to the page that started the challenge —
// i.e. to the attacker, who is the initiator — so a binding echoed there is a
// binding the attacker can put in a link. A forged cookie value must be refused
// too, which is what proves the poll checks the value and not merely the
// presence of a cookie.
func TestZ14_6TapTapBindingIsSecretAndChecked(t *testing.T) {
	_, srv, tap, clock, _ := newTapTapSource(t)

	attacker := newProbeBrowser(t)
	resp, err := attacker.Post(srv.URL+"/login/taptap/challenge", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := readAllString(t, resp)
	var challenge referencesource.LoginChallenge
	if err := json.Unmarshal([]byte(raw), &challenge); err != nil || challenge.ID == "" {
		t.Fatalf("challenge body %q: %v", raw, err)
	}

	// The binding the challenge set on this browser.
	bind := ""
	if u, err := url.Parse(srv.URL + "/login/taptap/challenge"); err == nil {
		for _, c := range attacker.Jar.Cookies(u) {
			if strings.Contains(c.Name, "taptap") {
				bind = c.Value
			}
		}
	}
	if bind == "" {
		t.Fatal("the challenge set no TapTap binding cookie")
	}
	if strings.Contains(raw, bind) {
		t.Errorf("the challenge body contains the binding cookie value: the value exists to be " +
			"withheld from the page that started the challenge, which is the attacker's own page")
	}

	tap.approve()
	clock.advance(2 * time.Second)

	// A forged cookie value must not confirm. The client has no jar, so the only
	// cookie on the request is the forged one.
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/login/taptap/poll?id="+url.QueryEscape(challenge.ID), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "refsrc_taptap_bind", Value: "bind_forged"})
	forgedClient := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	forged, err := forgedClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	forgedBody := readAllString(t, forged)
	if strings.Contains(forgedBody, `"confirmed"`) {
		t.Errorf("a forged binding cookie confirmed the attempt: %s", strings.TrimSpace(forgedBody))
	}

	// The owner, with the real cookie, still confirms.
	if progress := pollLogin(t, attacker, srv.URL, challenge.ID); progress.State != "confirmed" {
		t.Errorf("owner poll = %q, want confirmed", progress.State)
	}
}
