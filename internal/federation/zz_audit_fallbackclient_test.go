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

// zz_audit_fallbackclient_test.go —audit probe.
//
// Question: NewService's own note at service.go:288-298 says a caller that
// supplies only a Doer "still gets a bounded client for the exchange". Bounded in
// TIME, yes (httpclient's 20s). Is it bounded in ADDRESS? The fallback is
// NewOutboundClient(OutboundConfig{}) —and DenyPrivateAddresses is the ZERO value
// of httpclient.TransportConfig, i.e. false.
//
// The probe drives a real token exchange (CompleteBind) against a loopback token
// endpoint, once through the fallback client and once through a client that
// actually has the guard, so the endpoint is the same and only the guard differs.
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

	t.Logf("fallback HTTPClient (NewOutboundClient(OutboundConfig{})): binding=%+v err=%v", fallback, ferr)
	t.Logf("guarded  HTTPClient (DenyPrivateAddresses: true):          binding=%+v err=%v", guarded, gerr)
	t.Logf("token endpoint reached %d time(s)", exchanged)

	if ferr != nil {
		t.Fatalf("the fallback client refused the loopback token endpoint, so there is nothing to report: %v", ferr)
	}
	if gerr == nil {
		t.Fatal("the guard did not refuse the loopback token endpoint: the probe is not discriminating")
	}
	if !strings.Contains(gerr.Error(), "allow_private_addresses") {
		t.Errorf("the guarded control failed for another reason: %v", gerr)
	}
}
