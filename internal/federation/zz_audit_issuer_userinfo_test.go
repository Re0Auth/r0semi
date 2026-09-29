//go:build audit || audit6

package federation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// zz_audit_issuer_userinfo_test.go —audit probe.
//
// Question: every outbound data-plane URL is built from an operator-supplied
// base (Source.Issuer, Source.RawBase, the revocation endpoints). validateRawBase
// rejects a base that carries a query or fragment *because* that "silently changes
// what every raw request means ... the subject's upstream token is sent to
// whatever that string resolves to" (federation.go:193-206). Does anything reject
// the strictly worse form: userinfo, where the string LOOKS like host A and the
// request goes to host B?
func TestZZAuditIssuerAcceptsUserinfoSoTheTokenGoesElsewhere(t *testing.T) {
	var (
		sawAuth string
		sawHost string
		sawPath string
	)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth, sawHost, sawPath = r.Header.Get("Authorization"), r.Host, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()

	real := up.URL // http://127.0.0.1:PORT
	u, err := url.Parse(real)
	if err != nil {
		t.Fatal(err)
	}

	// The operator-facing string. It reads as "api.next-phi.example" first; the
	// authority (u.Host) is the loopback test server.
	looksLike := u.Scheme + "://api.next-phi.example@" + u.Host

	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: looksLike,
		TokenClass: tokenClassRevocable,
		Resources:  []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatalf("NewRegistry refused the userinfo issuer: %v", err)
	}
	b := backend{store: NewMemoryBindingStore(), vault: newVault(t)}
	svc := mustService(t, Config{Registry: reg, Doer: up.Client()}, b)
	b.bind(t, "usr_1", sourceName, "upstream-secret", "", time.Time{})

	if _, err := svc.Fetch(context.Background(), FetchRequest{User: "usr_1", Game: game, Resource: "profile"}); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	t.Logf("registry accepted issuer %q", looksLike)
	t.Logf("upstream saw Host=%q Path=%q %q", sawHost, sawPath, sawAuth)

	if sawAuth == "" {
		t.Fatal("the fixture never received the request")
	}

	// The same shape on the raw base: accepted, while the query form is refused.
	rawUserinfo := u.Scheme + "://api.next-phi.example@" + u.Host + "/v1"
	if err := validateRawBase(rawUserinfo); err != nil {
		t.Logf("validateRawBase refused userinfo %q: %v", rawUserinfo, err)
	} else {
		t.Logf("validateRawBase ACCEPTED userinfo %q (RawBase + caller path would send the bearer token to %s)",
			rawUserinfo, u.Host)
	}
	if err := validateRawBase(u.Scheme + "://" + u.Host + "/v1?x=1"); err == nil {
		t.Errorf("validateRawBase accepted a query on the base")
	} else {
		t.Logf("for contrast, validateRawBase refused the query form: %v", err)
	}
}
