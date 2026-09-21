package upstreamkit_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/upstreamkit"
	"github.com/Re0Auth/r0semi/upstreamkit/conformance"
)

const (
	accountScope = "account.read"
	profileScope = "phigros.profile.read"

	testRedirect = "https://re0auth.test/auth/upstream/reference/callback"
	testSecret   = "secret"
	testSubject  = "upstream-user-1"
)

func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// referenceUpstream builds a compliant source using the kit plus a real
// oauth.Service, and returns its base URL, that service, and the registered
// client.
func referenceUpstream(t *testing.T) (string, oauth.Service, oauth.Client) {
	t.Helper()
	ctx := context.Background()

	registry, err := oauth.NewRegistry(
		oauth.Descriptor{Scope: accountScope, Title: "Account", Risk: oauth.RiskLow},
		oauth.Descriptor{Scope: profileScope, Title: "Profile", Risk: oauth.RiskMedium},
	)
	if err != nil {
		t.Fatal(err)
	}
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("re0auth", "Re0Auth", oauth.ClientConfidential, testSecret,
		[]string{testRedirect}, []oauth.Scope{accountScope, profileScope})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(ctx, client); err != nil {
		t.Fatal(err)
	}
	svc, err := oauth.NewService(clients, oauth.NewMemoryStore(), audit.NewMemoryLogger(), oauth.Config{
		Issuer: "https://upstream.test",
		Scopes: registry,
	})
	if err != nil {
		t.Fatal(err)
	}

	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	kit, err := upstreamkit.New(upstreamkit.Config{
		Game: "phigros", Source: "reference", DisplayName: "Reference Backend",
		Issuer: srv.URL, TokenClass: upstreamkit.TokenRevocable,
		Resources: []upstreamkit.Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	}, upstreamkit.Hooks{
		OAuth: svc,
		Scope: registry,
		Consent: func(context.Context, upstreamkit.ConsentRequest) (upstreamkit.ConsentDecision, error) {
			return upstreamkit.ConsentDecision{Subject: testSubject}, nil
		},
		Account: func(_ context.Context, subject string) (upstreamkit.AccountInfo, error) {
			return upstreamkit.AccountInfo{Subject: subject, DisplayName: "Tester"}, nil
		},
		Resources: map[string]upstreamkit.ResourceHandler{
			"profile": func(_ context.Context, subject string) (any, error) {
				return map[string]any{"game": "phigros", "user_id": subject, "rks": 12.34}, nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler = kit.Handler()
	return srv.URL, svc, client
}

func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func TestDiscoveryDocument(t *testing.T) {
	base, _, _ := referenceUpstream(t)
	resp, err := http.Get(base + "/.well-known/re0auth-upstream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var disc upstreamkit.Discovery
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		t.Fatal(err)
	}
	if disc.Game != "phigros" || disc.TokenClass != upstreamkit.TokenRevocable || disc.OAuth.Issuer != base {
		t.Fatalf("discovery = %+v", disc)
	}
}

// The kit's own authorization-code + PKCE flow works end to end.
func TestKitAuthorizeFlow(t *testing.T) {
	base, _, client := referenceUpstream(t)
	const verifier = "verifier-verifier-verifier-verifier-verifier"

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {client.ID},
		"redirect_uri":          {testRedirect},
		"scope":                 {accountScope + " " + profileScope},
		"state":                 {"st-1"},
		"code_challenge":        {challenge(verifier)},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := noRedirectClient().Get(base + "/oauth/authorize?" + q)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" || loc.Query().Get("state") != "st-1" {
		t.Fatalf("redirect = %s", loc)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}
	req, _ := http.NewRequest(http.MethodPost, base+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ID, testSecret)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("token status = %d body = %s", resp.StatusCode, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken == "" {
		t.Fatal("no access token")
	}
}

func TestReferenceUpstreamPassesConformance(t *testing.T) {
	base, svc, client := referenceUpstream(t)
	ctx := context.Background()

	findings := conformance.Run(ctx, base, conformance.Options{})
	assertNoErrors(t, findings)

	// Mint a token at the service level so the data-plane checks can run.
	const verifier = "conformance-conformance-conformance-conformance"
	auth, err := svc.Authorize(ctx, oauth.AuthorizationRequest{
		ClientID: client.ID, RedirectURI: testRedirect, Subject: testSubject,
		Scopes:        []oauth.Scope{accountScope, profileScope},
		CodeChallenge: challenge(verifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := svc.Exchange(ctx, oauth.CodeExchangeRequest{
		ClientID: client.ID, ClientSecret: testSecret, Code: auth.Code,
		RedirectURI: testRedirect, CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}

	findings = conformance.Run(ctx, base, conformance.Options{AccessToken: tok.AccessToken})
	assertNoErrors(t, findings)
	assertRan(t, findings, "account.read")
}

// assertRan checks that a data-plane check did not get skipped.
func assertRan(t *testing.T, findings []conformance.Finding, check string) {
	t.Helper()
	for _, f := range findings {
		if f.Check == check && f.Level == conformance.LevelSkipped {
			t.Fatalf("check %s was skipped: %s", check, f.Message)
		}
	}
}

func assertNoErrors(t *testing.T, findings []conformance.Finding) {
	t.Helper()
	for _, f := range findings {
		if f.Level == conformance.LevelError {
			t.Errorf("conformance error: %s: %s", f.Check, f.Message)
		}
	}
}
