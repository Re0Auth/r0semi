//go:build audit || audit6

package federation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/httpclient"
)

// zz_audit_fallbackclient_test.go — audit probe.
//
// Question (round 6): NewService's own note said a caller that supplies only a Doer
// "still gets a bounded client for the exchange". Bounded in TIME, yes
// (httpclient's 20s). Is it bounded in ADDRESS? The fallback was
// NewOutboundClient(OutboundConfig{}) — and DenyPrivateAddresses is the ZERO value
// of httpclient.TransportConfig, i.e. false. It was not: a source whose issuer
// resolved to a loopback (or metadata-service) address got the authorization code
// and the client secret posted there.
//
// This file used to assert the defect. It now asserts the fix (S06-9): the
// fallback carries the guard, and Config.AllowPrivateUpstreams — the same
// declaration the composition root's own client carries via
// `upstream.allow_private_addresses` — is the only way past it. The test keeps its
// original name so the round-9 coverage matrix still points at it.
func TestZZAuditFallbackExchangeClientHasNoAddressGuard(t *testing.T) {
	var exchanged int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			http.NotFound(w, r)
			return
		}
		exchanged++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "rt",
		})
	}))
	defer up.Close()

	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: up.URL,
		ClientID: "cid", ClientSecret: "sec", TokenClass: tokenClassRevocable,
		Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A Doer that is not an *http.Client, so the fallback is what performs the
	// exchange. It is only here to satisfy NewService.
	doer := httpclient.DoerFunc(func(req *http.Request) (*http.Response, error) {
		return http.DefaultClient.Do(req)
	})

	bind := func(cfg Config) (Binding, error) {
		t.Helper()
		b := backend{store: NewMemoryBindingStore(), vault: newVault(t)}
		svc := mustService(t, cfg, b)
		ctx := context.Background()
		ch, err := svc.BeginBind(ctx, "usr_1", game, sourceName, "/app/sources")
		if err != nil {
			return Binding{}, err
		}
		binding, _, err := svc.CompleteBind(ctx, "usr_1", ch.ID, "upstream-code")
		return binding, err
	}

	fallback, ferr := bind(Config{
		Registry: reg, Doer: doer, BaseURL: "https://re0auth.test",
	})
	guarded, gerr := bind(Config{
		Registry: reg, Doer: doer, BaseURL: "https://re0auth.test",
		HTTPClient: httpclient.NewOutboundClient(httpclient.OutboundConfig{
			Transport: httpclient.TransportConfig{DenyPrivateAddresses: true},
		}),
	})
	permitted, perr := bind(Config{
		Registry: reg, Doer: doer, BaseURL: "https://re0auth.test",
		AllowPrivateUpstreams: true,
	})

	t.Logf("fallback HTTPClient (default):                       binding=%+v err=%v", fallback, ferr)
	t.Logf("guarded  HTTPClient (DenyPrivateAddresses: true):     binding=%+v err=%v", guarded, gerr)
	t.Logf("fallback HTTPClient (AllowPrivateUpstreams: true):    binding=%+v err=%v", permitted, perr)
	t.Logf("token endpoint reached %d time(s)", exchanged)

	if ferr == nil {
		t.Fatalf("the fallback client reached the loopback token endpoint (%d exchange(s)): the address "+
			"guard is off", exchanged)
	}
	if !strings.Contains(ferr.Error(), "allow_private_addresses") {
		t.Errorf("the fallback client refused the loopback endpoint for another reason: %v", ferr)
	}
	if gerr == nil || !strings.Contains(gerr.Error(), "allow_private_addresses") {
		t.Errorf("the explicit guard did not refuse the loopback token endpoint: %v", gerr)
	}
	if perr != nil {
		t.Fatalf("AllowPrivateUpstreams did not let the fallback client through, so the two refusals above "+
			"prove nothing: %v", perr)
	}
	if permitted.User != "usr_1" {
		t.Errorf("the permitted exchange did not store the binding: %+v", permitted)
	}
	if exchanged != 1 {
		t.Errorf("the loopback token endpoint was reached %d time(s), want exactly the permitted one", exchanged)
	}
}
