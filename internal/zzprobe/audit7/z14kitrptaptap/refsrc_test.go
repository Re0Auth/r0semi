//go:build audit7

// Reference-source probe: the TapTap device login completes for whoever loads
// the poll URL, not for the browser that started the attempt.
//
// TapTapLogin.Start returns a LoginChallenge carrying an opaque attempt id
// (referencesource/taptap.go:129-136); the frontend then polls
// GET /login/taptap/poll?id=<id> (referencesource/taptap.go:108-110,219-226),
// and a confirmed poll hands the upstream account to establish, which writes the
// subject into the *caller's* session (referencesource/source.go:293-304). The
// session cookie is SameSite=Lax (referencesource/source.go:newSessions), so a
// cross-site top-level GET navigation carries it. Nothing binds the attempt to
// the browser that created it.
//
// This is the demo source, not a release artifact, so the impact is limited to
// deployments that copy it — but it is the implementation others copy, which is
// exactly why the shape is worth pinning down.
package z14kitrptaptap

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/referencesource"
	"github.com/Re0Auth/r0semi/tapsign"
	"github.com/Re0Auth/r0semi/taptapoauth"
	"github.com/Re0Auth/r0semi/upstreamkit"
)

// probeEnroller is a TapTap device flow whose user has already approved.
type probeEnroller struct{}

func (probeEnroller) Start(context.Context) (taptapoauth.DeviceAuth, error) {
	return taptapoauth.DeviceAuth{
		DeviceID:        "dev-1",
		DeviceCode:      "dc-1",
		VerificationURL: "https://tap.example/verify",
		Interval:        time.Millisecond,
		ExpiresAt:       time.Now().Add(time.Hour),
	}, nil
}

func (probeEnroller) Poll(context.Context, taptapoauth.DeviceAuth) (tapsign.TapTapToken, error) {
	return tapsign.TapTapToken{
		Kid: "kid-1", MacKey: "mac-1",
		OpenID: probeUpstreamSubject, UnionID: "union-1",
	}, nil
}

const probeUpstreamSubject = "openid_attacker_z14"

// probeSigner is a tapsign.Service that always succeeds and never talks upstream.
type probeSigner struct{}

func (probeSigner) Verify(context.Context, tapsign.Credential) error { return nil }
func (probeSigner) Rotate(_ context.Context, c tapsign.Credential) (tapsign.Credential, error) {
	return c, nil
}
func (probeSigner) Revoke(context.Context, tapsign.Credential) error { return nil }
func (probeSigner) Redeem(context.Context, tapsign.TapTapToken) (tapsign.Credential, error) {
	return tapsign.Credential{SessionToken: "st-1", ObjectID: "obj-1"}, nil
}

// startTapSource serves the reference source with the real TapTap login wired to
// the fake enroller/redeemer above.
func startTapSource(t *testing.T) *httptest.Server {
	t.Helper()
	login, err := referencesource.NewTapTapLogin(referencesource.TapTapConfig{}, referencesource.TapTapDeps{
		Enroller: probeEnroller{},
		Redeem:   probeSigner{},
	})
	if err != nil {
		t.Fatalf("NewTapTapLogin: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	issuer := "http://" + ln.Addr().String()
	src, err := referencesource.New(referencesource.Config{
		Discovery: upstreamkit.Config{
			Game: probeGame, Source: probeSource, DisplayName: "Z14 taptap probe",
			Issuer: issuer, TokenClass: upstreamkit.TokenRevocable,
		},
		Provider: probeGame,
		Downstream: referencesource.Client{
			ID: probeClientID, Secret: probeClientSecret, RedirectURIs: []string{probeCallback},
		},
	}, referencesource.Deps{
		Logins: []referencesource.Login{login},
		Vault:  probeVault(t),
		Reader: referencesource.StaticReader{},
	})
	if err != nil {
		t.Fatalf("referencesource.New: %v", err)
	}
	srv := httptest.NewUnstartedServer(src.Handler())
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// sessionState asks /login who the caller's cookie says they are.
func sessionState(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	resp, body := mustDo(t, c, newProbeRequest(t, http.MethodGet, base+"/login", ""))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/login: status %d body=%q", resp.StatusCode, body)
	}
	var out struct {
		State   string `json:"state"`
		Subject string `json:"subject"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("/login body %q: %v", body, err)
	}
	return out.State + "/" + out.Subject
}

// TestZ14ControlTheRealTapTapLoginCompletesForTheBrowserThatStartedIt is the
// control: the browser that requested the challenge and then polled it is logged
// in as the TapTap account. Without this, "another browser got logged in" could
// be a probe that never worked.
func TestZ14ControlTheRealTapTapLoginCompletesForTheBrowserThatStartedIt(t *testing.T) {
	srv := startTapSource(t)
	owner := newProbeClient(t)

	resp, body := mustDo(t, owner, newProbeRequest(t, http.MethodPost, srv.URL+"/login/taptap/challenge", ""))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge: status %d body=%q", resp.StatusCode, body)
	}
	var challenge struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &challenge); err != nil || challenge.ID == "" {
		t.Fatalf("challenge body %q: %v", body, err)
	}

	resp, body = mustDo(t, owner, newProbeRequest(t, http.MethodGet, srv.URL+"/login/taptap/poll?id="+challenge.ID, ""))
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"confirmed"`) {
		t.Fatalf("owner poll: status %d body=%q", resp.StatusCode, body)
	}
	if got := sessionState(t, owner, srv.URL); got != "confirmed/"+probeUpstreamSubject {
		t.Fatalf("control: the browser that started the attempt ended as %q", got)
	}
	t.Logf("control: the initiating browser ended as %q", probeUpstreamSubject)
}

// TestZ14AnotherBrowserGetsLoggedInByThePollURL: a second browser that never
// started an attempt, never scanned a QR code and holds no credential becomes
// the attacker's TapTap account simply by loading the poll URL.
//
// The poll URL is the only thing it needs, and the attempt id is handed to the
// attacker's own frontend with the challenge. A control request with an unknown
// id leaves the second browser anonymous, proving the effect comes from the
// attempt and not from polling being a no-op.
func TestZ14AnotherBrowserGetsLoggedInByThePollURL(t *testing.T) {
	srv := startTapSource(t)

	attacker := newProbeClient(t)
	resp, body := mustDo(t, attacker, newProbeRequest(t, http.MethodPost, srv.URL+"/login/taptap/challenge", ""))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge: status %d body=%q", resp.StatusCode, body)
	}
	var challenge struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &challenge); err != nil || challenge.ID == "" {
		t.Fatalf("challenge body %q: %v", body, err)
	}

	// The victim: a fresh browser with no relationship to the attempt.
	victim := newProbeClient(t)
	if got := sessionState(t, victim, srv.URL); got != "anonymous/" {
		t.Fatalf("setup: the victim browser was already %q", got)
	}
	resp, body = mustDo(t, victim, newProbeRequest(t, http.MethodGet, srv.URL+"/login/taptap/poll?id="+challenge.ID, ""))
	t.Logf("victim poll: %d %s", resp.StatusCode, strings.TrimSpace(body))
	victimState := sessionState(t, victim, srv.URL)

	// Control: an unknown attempt id must NOT log the browser in.
	control := newProbeClient(t)
	_, _ = mustDo(t, control, newProbeRequest(t, http.MethodGet, srv.URL+"/login/taptap/poll?id=lgn_does_not_exist", ""))
	controlState := sessionState(t, control, srv.URL)
	if controlState != "anonymous/" {
		t.Fatalf("control: an unknown attempt id logged the browser in as %q", controlState)
	}

	if victimState != "anonymous/" {
		t.Errorf("a browser that only loaded GET /login/taptap/poll?id=%s was logged in as %q.\n"+
			"The attempt id is generated for the attacker's own frontend (referencesource/taptap.go:129-136) and the "+
			"poll route acts on it with no binding to the browser that started the attempt "+
			"(referencesource/taptap.go:219-226); establish overwrites the caller's session subject "+
			"(referencesource/source.go:293-304). The session cookie is SameSite=Lax, so a cross-site top-level GET "+
			"navigation carries it. The control with an unknown id stayed anonymous.", challenge.ID, victimState)
		return
	}
	t.Logf("the poll URL did not cross browsers")
}
