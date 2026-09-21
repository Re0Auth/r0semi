// Command referencesource runs the reference Re0Auth data source as a real
// process, so Re0Auth can bind to it over HTTP rather than in-process.
//
// Login is configured by environment:
//
//	GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET   Google OAuth login
//	GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET   GitHub OAuth login
//	TAPTAP_CLIENT_ID / TAPTAP_LEANCLOUD_APP_KEY   TapTap device-code (QR) login
//
// With none set, a fixed demo principal is used so the process can still be
// exercised. Either way this is an ordinary HTTP server that Re0Auth talks to
// over OAuth 2.0; it shares no code path, no database and no credential store
// with Re0Auth.
package main

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/httpclient"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/referencesource"
	"github.com/Re0Auth/r0semi/tapsign"
	"github.com/Re0Auth/r0semi/taptapoauth"
	"github.com/Re0Auth/r0semi/upstreamkit"
	"github.com/Re0Auth/r0semi/vault"
)

func main() {
	addr := envOr("REFERENCE_SOURCE_ADDR", "127.0.0.1:8081")
	issuer := envOr("REFERENCE_SOURCE_ISSUER", "http://"+addr)
	re0authBase := envOr("RE0AUTH_BASE_URL", "http://127.0.0.1:8080")

	vaultSvc, err := newVault()
	if err != nil {
		log.Fatal(err)
	}

	deps := referencesource.Deps{
		Vault: vaultSvc,
		Reader: referencesource.StaticReader{
			"profile": map[string]any{"game": "phigros", "rks": 0},
			"scores":  []any{},
		},
	}

	tap, err := newTapTapLogin()
	if err != nil {
		log.Fatal(err)
	}
	social, err := newSocialLogin(issuer)
	if err != nil {
		log.Fatal(err)
	}
	if tap != nil {
		deps.Logins = append(deps.Logins, tap)
	}
	if social != nil {
		deps.Logins = append(deps.Logins, social)
	}
	if len(deps.Logins) == 0 {
		deps.Auth = referencesource.StaticAuthenticator{Principal: referencesource.Principal{
			Subject: "demo-openid", Display: "demo", Credential: []byte("demo-credential"),
		}}
		log.Print("no login provider configured; using a fixed demo principal")
	} else {
		log.Printf("%d login surface(s) enabled", len(deps.Logins))
	}

	src, err := referencesource.New(referencesource.Config{
		Discovery: upstreamkit.Config{
			Game:        "phigros",
			Source:      "taptap-reference",
			DisplayName: "Phigros (reference source)",
			Issuer:      issuer,
			TokenClass:  upstreamkit.TokenRevocable,
			Resources: []upstreamkit.Resource{
				{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"},
				{Name: "scores", Schema: "re0auth.phigros.scores/1", Scope: "phigros.score.read"},
			},
			Contact: "mailto:admin@example.invalid",
		},
		Provider: "phigros",
		Downstream: referencesource.Client{
			ID:           "re0auth",
			Secret:       envOr("REFERENCE_SOURCE_CLIENT_SECRET", "dev-secret"),
			RedirectURIs: []string{re0authBase + "/auth/upstream/phigros/taptap-reference/callback"},
		},
	}, deps)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("reference source %q listening on %s (issuer %s)", src.Discovery().Source, addr, issuer)
	log.Fatal(http.ListenAndServe(addr, src.Handler()))
}

func newTapTapLogin() (*referencesource.TapTapLogin, error) {
	clientID := os.Getenv("TAPTAP_CLIENT_ID")
	if clientID == "" {
		return nil, nil
	}
	appKey := os.Getenv("TAPTAP_LEANCLOUD_APP_KEY")
	if appKey == "" {
		return nil, errors.New("referencesource: TAPTAP_LEANCLOUD_APP_KEY is required when TAPTAP_CLIENT_ID is set")
	}
	// Retry transient upstream failures. Only idempotent methods are retried, so
	// the device-code and redeem POSTs are deliberately sent once.
	doer := httpclient.Retry(&http.Client{Timeout: 15 * time.Second}, httpclient.RetryOptions{})
	// Defaults are the China-region TapTap endpoints.
	enroller, err := taptapoauth.NewService(taptapoauth.Config{
		DeviceCodeEndpoint: envOr("TAPTAP_DEVICE_CODE_ENDPOINT", "https://www.taptap.com/oauth2/v1/device/code"),
		TokenEndpoint:      envOr("TAPTAP_TOKEN_ENDPOINT", "https://www.taptap.cn/oauth2/v1/token"),
		UserInfoEndpoint:   envOr("TAPTAP_USER_INFO_ENDPOINT", "https://open.tapapis.cn/account/basic-info/v1"),
		ClientID:           clientID,
	}, doer)
	if err != nil {
		return nil, err
	}
	redeem, err := tapsign.NewService(tapsign.Config{
		BaseURL: envOr("TAPTAP_LEANCLOUD_BASE_URL", "https://rak3ffdi.cloud.tds1.tapapis.cn/1.1"),
		AppID:   clientID,
		AppKey:  appKey,
	}, doer, audit.NewMemoryLogger())
	if err != nil {
		return nil, err
	}
	return referencesource.NewTapTapLogin(
		referencesource.TapTapConfig{},
		referencesource.TapTapDeps{Enroller: enroller, Redeem: redeem},
	)
}

func newSocialLogin(issuer string) (*referencesource.SocialLogin, error) {
	var credentials []idp.Credentials
	if id := os.Getenv("GOOGLE_CLIENT_ID"); id != "" {
		credentials = append(credentials, idp.Credentials{
			Provider: idp.Google, ClientID: id, ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		})
	}
	if id := os.Getenv("GITHUB_CLIENT_ID"); id != "" {
		credentials = append(credentials, idp.Credentials{
			Provider: idp.GitHub, ClientID: id, ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		})
	}
	if len(credentials) == 0 {
		return nil, nil
	}
	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: issuer,
		CallbackPath: "/login/{provider}/callback",
		HTTPClient:   &http.Client{Timeout: 10 * time.Second},
		Credentials:  credentials,
	})
	if err != nil {
		return nil, err
	}
	return referencesource.NewSocialLogin(referencesource.SocialConfig{}, referencesource.SocialDeps{Registry: registry})
}

func newVault() (vault.Service, error) {
	// A dev KEK. A real deployment uses KMS/HSM, which is why the wrapper is
	// injected rather than hard-coded.
	wrapper, err := vault.NewLocalKeyWrapper("dev", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		return nil, err
	}
	// NOTE: in-memory, so credentials do not survive a restart. That is honest
	// for a reference source, not for production.
	return vault.NewService(vault.NewMemoryRepo(), wrapper, audit.NewMemoryLogger())
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
