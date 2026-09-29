//go:build audit7

package z19secretslifecycle

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/Re0Auth/r0semi/idp"
)

// failingTransport fails every request without touching the network, so the probe
// is deterministic on this machine (no dial, no DNS, no graph.qq.com).
type failingTransport struct{ err error }

func (t failingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// The URL is captured so the probe can show what the credential rode in on,
	// but nothing is dialled.
	return nil, t.err
}

// Z19-1 — QQ's profile fetch puts the upstream ACCESS TOKEN in the request URL,
// and net/http's own error value then carries that URL back to the caller.
//
// idp/idp.go:651 and :671 build
//
//	https://graph.qq.com/oauth2.0/me?unionid=1&access_token=<token>
//	https://graph.qq.com/user/get_user_info?fmt=json&access_token=<token>&…
//
// and getText (:720-722) wraps the transport failure with %w. `http.Client.Do`
// returns a *url.Error whose Error() is `Get "<full url>": <cause>` — so the
// token is embedded in an error value. The project reasons about exactly this
// class elsewhere and refuses to take the risk: httpclient/outbound.go:288-292
// keeps hosts only ("this error is logged, and a URL on the wire here can carry
// a code or a token").
//
// Today's only caller (internal/auth/auth.go:669-673) drops the error and answers
// a bounded redirect, which is why this is not already a log disclosure — but the
// credential is one `slog.Error("…", "err", err)` away from the process log, and
// it also survives in the heap as part of the error string. The GitHub control
// below shows the difference is where the token travels, not how the error is
// built: the same failing transport yields an error with no token when the token
// goes in the Authorization header.
func TestZ19QQUserInfoCarriesTheAccessTokenInTheURLError(t *testing.T) {
	const token = "Z19-QQ-ACCESS-TOKEN-6ff3"

	newClient := func(t *testing.T, p idp.Provider) *idp.Client {
		t.Helper()
		cause := errors.New("z19 probe: transport refused")
		reg, err := idp.NewRegistry(idp.RegistryConfig{
			RedirectBase: "https://re0auth.test",
			HTTPClient:   &http.Client{Transport: failingTransport{err: cause}},
			Credentials: []idp.Credentials{{
				Provider: p, ClientID: "cid", ClientSecret: "csec",
			}},
		})
		if err != nil {
			t.Fatalf("NewRegistry(%s): %v", p, err)
		}
		c, ok := reg.Get(p)
		if !ok {
			t.Fatalf("the registry did not build the %s client", p)
		}
		return c
	}

	// Control: the GitHub path reaches its userinfo call (the error is the
	// transport's) and the token is NOT in the error, because it travels in the
	// Authorization header.
	gh := newClient(t, idp.GitHub)
	_, gerr := gh.Identity(context.Background(), &oauth2.Token{AccessToken: token}, "")
	if gerr == nil {
		t.Fatal("control: the GitHub userinfo call reported no error")
	}
	if !strings.Contains(gerr.Error(), "transport refused") {
		t.Fatalf("control: the GitHub probe did not reach the transport: %v", gerr)
	}
	if strings.Contains(gerr.Error(), token) {
		t.Fatalf("control is wrong: the header path put the token in the error: %v", gerr)
	}
	t.Logf("control (GitHub, Authorization header): %v", gerr)

	// Subject: QQ's profile fetch, where the token is a query parameter.
	qq := newClient(t, idp.QQ)
	_, qerr := qq.Identity(context.Background(), &oauth2.Token{AccessToken: token}, "")
	if qerr == nil {
		t.Fatal("the QQ userinfo call reported no error")
	}
	if !strings.Contains(qerr.Error(), "graph.qq.com") {
		t.Fatalf("the QQ probe did not reach the QQ profile fetch: %v", qerr)
	}
	if strings.Contains(qerr.Error(), token) {
		t.Errorf("DISCLOSURE: the QQ access token is embedded in the returned error value, "+
			"because the URL it was sent in is echoed by net/http's url.Error. "+
			"Any caller that logs this error prints a live upstream credential.\nerror: %v", qerr)
	} else {
		t.Logf("no leak: %v", qerr)
	}
}
