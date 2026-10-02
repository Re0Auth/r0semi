package taptapoauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// AUDIT9 / S07-1 — the user-info call carries a MAC Authorization header through
// the injected Doer. That Doer must not be able to follow a cross-host redirect
// with the credential attached, or replay the request at a host the operator
// never configured.
func TestAudit9CredentialHeadersDoNotFollowACrossHostRedirect(t *testing.T) {
	var leaked http.Header
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	// A different HOSTNAME for the same loopback address, so net/http sees a
	// cross-host redirect and applies its cross-domain header policy.
	targetURL := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetURL, http.StatusFound)
	}))
	defer origin.Close()

	c := newClient(
		Config{UserInfoEndpoint: origin.URL + "/userinfo", ClientID: "cid"},
		origin.Client(), // CheckRedirect is nil: the stdlib default policy
	)
	req, err := http.NewRequest(http.MethodGet, origin.URL+"/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", `MAC id="kid",ts="1",nonce="n",mac="secret"`)

	if resp, err := c.doer.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("the adapter's Doer followed a cross-host redirect")
	}
	if leaked != nil {
		if got := leaked.Get("Authorization"); got != "" {
			t.Fatalf("the MAC credential reached the redirect target: %q", got)
		}
	}
}
