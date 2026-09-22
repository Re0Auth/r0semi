package upstreamkit_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/upstreamkit"
)

// cascadeKit builds a minimal kit, with or without the cascade hook, and hands
// back the address where the hook records what it was asked to do.
func cascadeKit(t *testing.T, withHook bool) (base string, calls *[]upstreamkit.CascadeRevocationRequest) {
	t.Helper()
	registry := oauth.DefaultRegistry()
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("re0auth", "Re0Auth", oauth.ClientConfidential, testSecret,
		[]string{testRedirect}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	as, err := oauth.NewService(clients, oauth.NewMemoryStore(), audit.NewMemoryLogger(), oauth.Config{
		Issuer: "https://upstream.test", Scopes: registry,
	})
	if err != nil {
		t.Fatal(err)
	}

	recorded := &[]upstreamkit.CascadeRevocationRequest{}
	hooks := upstreamkit.Hooks{
		OAuth: as,
		Scope: registry,
		Consent: func(context.Context, upstreamkit.ConsentRequest) (upstreamkit.ConsentDecision, error) {
			return upstreamkit.ConsentDecision{Subject: testSubject}, nil
		},
		Account: func(_ context.Context, subject string) (upstreamkit.AccountInfo, error) {
			return upstreamkit.AccountInfo{Subject: subject}, nil
		},
		Resources: map[string]upstreamkit.ResourceHandler{},
	}
	if withHook {
		hooks.CascadeRevoke = func(_ context.Context, req upstreamkit.CascadeRevocationRequest) error {
			*recorded = append(*recorded, req)
			return nil
		}
	}

	kit, err := upstreamkit.New(upstreamkit.Config{
		Game: "phigros", Source: "reference", DisplayName: "Reference Backend",
		Issuer: "https://upstream.test", TokenClass: upstreamkit.TokenRevocable,
	}, hooks)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(kit.Handler())
	t.Cleanup(srv.Close)
	return srv.URL, recorded
}

func discoveryDoc(t *testing.T, base string) map[string]any {
	t.Helper()
	resp, err := http.Get(base + "/.well-known/re0auth-upstream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func advertisedCascade(t *testing.T, doc map[string]any) string {
	t.Helper()
	oauthSection, _ := doc["oauth"].(map[string]any)
	endpoint, _ := oauthSection["cascade_revocation_endpoint"].(string)
	return endpoint
}

// The document and the code have to say the same thing, and the code wins.
//
// A source that advertises a capability it does not have is the exact failure
// mode the rest of this protocol is built to avoid — the same one as advertising
// DPoP while issuing plain bearer tokens — so the hook, not the config, decides
// what appears.
func TestCascadeIsAdvertisedOnlyWhenImplemented(t *testing.T) {
	t.Run("no hook", func(t *testing.T) {
		base, calls := cascadeKit(t, false)
		if got := advertisedCascade(t, discoveryDoc(t, base)); got != "" {
			t.Fatalf("discovery advertised %q without a hook", got)
		}

		// And the route agrees: nothing to call.
		resp, err := http.PostForm(base+"/oauth/cascade_revocation", url.Values{"token": {"x"}})
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("unimplemented cascade = %d, want 404", resp.StatusCode)
		}
		if len(*calls) != 0 {
			t.Fatal("the hook ran despite the capability being absent")
		}
	})

	t.Run("with hook", func(t *testing.T) {
		base, calls := cascadeKit(t, true)
		endpoint := advertisedCascade(t, discoveryDoc(t, base))
		if !strings.HasSuffix(endpoint, "/oauth/cascade_revocation") {
			t.Fatalf("cascade endpoint = %q", endpoint)
		}

		resp, err := http.PostForm(base+"/oauth/cascade_revocation", url.Values{
			"token":           {"upstream-refresh-token"},
			"token_type_hint": {"refresh_token"},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("cascade = %d, want 200", resp.StatusCode)
		}
		if len(*calls) != 1 {
			t.Fatalf("hook calls = %d, want one", len(*calls))
		}
		got := (*calls)[0]
		// The token is not being revoked; it is how the source learns whose session
		// to end. Passing it through intact is what makes that possible.
		if got.Token != "upstream-refresh-token" || got.TokenTypeHint != "refresh_token" {
			t.Fatalf("hook received %+v", got)
		}
	})
}

// A source that cannot do it must not be able to claim it succeeded.
func TestCascadeReportsAHookFailure(t *testing.T) {
	registry := oauth.DefaultRegistry()
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("re0auth", "Re0Auth", oauth.ClientConfidential, testSecret,
		[]string{testRedirect}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	as, err := oauth.NewService(clients, oauth.NewMemoryStore(), audit.NewMemoryLogger(), oauth.Config{
		Issuer: "https://upstream.test", Scopes: registry,
	})
	if err != nil {
		t.Fatal(err)
	}

	kit, err := upstreamkit.New(upstreamkit.Config{
		Game: "phigros", Source: "reference", DisplayName: "Reference Backend",
		Issuer: "https://upstream.test", TokenClass: upstreamkit.TokenRevocable,
	}, upstreamkit.Hooks{
		OAuth: as, Scope: registry,
		Consent: func(context.Context, upstreamkit.ConsentRequest) (upstreamkit.ConsentDecision, error) {
			return upstreamkit.ConsentDecision{Subject: testSubject}, nil
		},
		Account: func(_ context.Context, subject string) (upstreamkit.AccountInfo, error) {
			return upstreamkit.AccountInfo{Subject: subject}, nil
		},
		Resources: map[string]upstreamkit.ResourceHandler{},
		CascadeRevoke: func(context.Context, upstreamkit.CascadeRevocationRequest) error {
			return errors.New("upstream is unreachable")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(kit.Handler())
	t.Cleanup(srv.Close)

	resp, err := http.PostForm(srv.URL+"/oauth/cascade_revocation", url.Values{"token": {"x"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 400 {
		t.Fatalf("a failed cascade answered %d, want an error", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] == nil {
		t.Fatalf("failure was not reported as an OAuth error: %v", body)
	}
}
