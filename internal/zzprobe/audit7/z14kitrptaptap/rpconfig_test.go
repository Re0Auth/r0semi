//go:build audit7

// RP probe: an explicitly configured OAuth endpoint is silently discarded when
// its sibling is not set.
//
// idp.Credentials documents auth_url/token_url as overrides "which is how tests
// (and self-hosted or proxied endpoints) are wired" (idp/idp.go:181-183), and
// pinToIssuer's own error message tells the operator to "set auth_url/token_url
// explicitly for a provider that hosts its endpoints elsewhere"
// (idp/idp.go:503-505). But oauthConfig only honours the override when BOTH are
// non-empty (idp/idp.go:468); otherwise discovery runs and `cfg.Endpoint =
// endpoint` (idp/idp.go:479) replaces whatever was configured. A half-configured
// provider therefore gets the document's endpoint — and, when that document is
// off-origin, a rejection naming the setting the operator already supplied.
package z14kitrptaptap

import (
	"net/url"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/idp"
)

// probeCustomRegistry wires one custom OIDC provider with the given explicit
// endpoints. Empty fields mean "not configured".
func probeCustomRegistry(t *testing.T, f *fakeOP, authURL, tokenURL string) *idp.Client {
	t.Helper()
	const name idp.Provider = "acmeprobe"
	reg, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase:     "https://re0auth.test",
		HTTPClient:       f.srv.Client(),
		ProviderCacheTTL: time.Nanosecond,
		Credentials: []idp.Credentials{{
			Provider:     name,
			ClientID:     probeAudience,
			ClientSecret: "probe-secret",
			Issuer:       f.srv.URL,
			AuthURL:      authURL,
			TokenURL:     tokenURL,
		}},
	})
	if err != nil {
		t.Fatalf("idp.NewRegistry: %v", err)
	}
	c, ok := reg.Get(name)
	if !ok {
		t.Fatalf("provider %q was not registered", name)
	}
	return c
}

func loginPath(t *testing.T, c *idp.Client) string {
	t.Helper()
	raw, err := c.AuthCodeURL(t.Context(), "state", c.NewVerifier(), c.NewNonce())
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("the login URL is not a URL: %q", raw)
	}
	return u.Path
}

// TestZ14ControlBothExplicitEndpointsAreHonoured is the control: when auth_url
// and token_url are both set, discovery is skipped and the configured path is
// the one the browser gets. This is what proves the red probe below is about the
// half-configured case and not about the override being broken in general.
func TestZ14ControlBothExplicitEndpointsAreHonoured(t *testing.T) {
	f := newFakeOP(t)
	c := probeCustomRegistry(t, f, f.srv.URL+"/real-authorize", f.srv.URL+"/real-token")

	path := loginPath(t, c)
	if path != "/real-authorize" {
		t.Fatalf("control: with both endpoints explicit the login went to %q, want /real-authorize", path)
	}
	if discovery, _ := f.hits(); discovery != 0 {
		t.Fatalf("control: discovery ran %d times although both endpoints were configured", discovery)
	}
	t.Logf("control: both endpoints explicit -> %q, discovery calls=%d", path, 0)
}

// TestZ14HalfExplicitEndpointIsSilentlyDiscarded: auth_url alone is ignored and
// the discovered endpoint is used instead.
//
// The configured path is unambiguous — the fake OP's document never mentions
// /real-authorize — so a login that lands on /authorize can only have come from
// the document. That is the failure: the operator's explicit setting is dropped
// with no diagnostic, which is also unhelpful for the off-origin case the
// setting exists to solve.
func TestZ14HalfExplicitEndpointIsSilentlyDiscarded(t *testing.T) {
	f := newFakeOP(t)
	c := probeCustomRegistry(t, f, f.srv.URL+"/real-authorize", "")

	path := loginPath(t, c)
	discovery, _ := f.hits()
	t.Logf("auth_url=%s was configured; the browser got %q; discovery calls=%d", f.srv.URL+"/real-authorize", path, discovery)

	if path != "/real-authorize" {
		t.Errorf("an explicitly configured auth_url was discarded: the login went to %q, a path the discovery "+
			"document named, not the configured %q.\n"+
			"idp/idp.go:468 only honours the override when auth_url AND token_url are both non-empty; otherwise "+
			"idp/idp.go:479 replaces the whole endpoint with the discovered one. The operator gets no error and no "+
			"log line; the login silently runs against a different endpoint, and when the discovered one is "+
			"off-origin the refusal (idp/idp.go:502-506) recommends setting auth_url/token_url — the setting that "+
			"was already supplied.", path, "/real-authorize")
		return
	}
	t.Logf("the explicit auth_url was honoured")
}
