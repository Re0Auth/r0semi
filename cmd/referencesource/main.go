// Command referencesource runs the reference Re0Auth data source as a real
// process, so Re0Auth can bind to it over HTTP rather than in-process.
//
// Login is configured in config/referencesource.toml (see the .example file):
// TapTap device-code (QR) and/or social OAuth (Google, GitHub, ...). With
// neither configured, a fixed demo principal is used so the process can still be
// exercised.
//
// Either way this is an ordinary HTTP server that Re0Auth talks to over OAuth
// 2.0; it shares no code path, no database and no credential store with Re0Auth.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/httpclient"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/config"
	"github.com/Re0Auth/r0semi/referencesource"
	"github.com/Re0Auth/r0semi/tapsign"
	"github.com/Re0Auth/r0semi/taptapoauth"
	"github.com/Re0Auth/r0semi/vault"
)

var configFlag = flag.String("config", "", "path to the TOML config file (default: REFERENCE_SOURCE_CONFIG, then config/referencesource.toml)")

// die reports why the process cannot start, and exits non-zero.
//
// It replaces log.Fatalf so the reason is a structured field rather than a
// sentence, and so the stage is machine-readable: "which part refused to start"
// is the first question anyone asks.
func die(stage string, err error) {
	slog.Error("cannot start", "stage", stage, "err", err)
	os.Exit(1)
}

func main() {
	flag.Parse()

	// Before anything that logs. A bad level or format is a configuration error
	// like any other: refuse to start rather than run with a setting the operator
	// did not choose. This is the one message that cannot go through slog, because
	// slog is what failed to configure.
	if err := config.SetupLogging("REFERENCE_SOURCE"); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "referencesource:", err)
		os.Exit(1)
	}

	configPath, explicit := config.Path(*configFlag, "REFERENCE_SOURCE_CONFIG", defaultConfigPath)
	switch {
	case configPath != "":
		slog.Info("configuration file", "path", configPath)
	case explicit:
		slog.Error("cannot start", "stage", "config", "reason", "config file does not exist", "path", *configFlag)
		os.Exit(1)
	default:
		slog.Info("no configuration file; configuring from the environment only")
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		die("config", err)
	}

	vaultService, err := newVault()
	if err != nil {
		die("vault", err)
	}
	slog.Warn("this source's vault and sessions are in-memory; credentials do not survive a restart")

	deps := referencesource.Deps{
		Vault: vaultService,
		Reader: referencesource.StaticReader{
			"profile": map[string]any{"game": cfg.Discovery.Game, "rks": 0},
			"scores":  []any{},
		},
	}

	if cfg.tapTap != nil {
		login, err := newTapTapLogin(*cfg.tapTap)
		if err != nil {
			die("taptap login", err)
		}
		deps.Logins = append(deps.Logins, login)
		slog.Info("tapTap device-code (QR) login enabled")
	}
	if len(cfg.social) > 0 {
		login, err := newSocialLogin(cfg)
		if err != nil {
			die("social login", err)
		}
		deps.Logins = append(deps.Logins, login)
		slog.Info("social login enabled", "providers", len(cfg.social))
	}
	if len(deps.Logins) == 0 {
		deps.Auth = referencesource.StaticAuthenticator{Principal: referencesource.Principal{
			Subject: "demo-openid", Display: "demo", Credential: []byte("demo-credential"),
		}}
		slog.Warn("no login provider configured; using a fixed demo principal")
	}

	src, err := referencesource.New(referencesource.Config{
		Discovery: cfg.Discovery,
		Provider:  cfg.Provider,
		Downstream: referencesource.Client{
			ID:     cfg.ClientID,
			Secret: cfg.ClientSecret,
			RedirectURIs: []string{
				cfg.Re0AuthBaseURL + "/auth/upstream/" + cfg.Discovery.Game + "/" + cfg.Discovery.Source + "/callback",
			},
		},
	}, deps)
	if err != nil {
		die("source", err)
	}

	slog.Info("listening", "source", src.Discovery().Source, "addr", cfg.Addr, "issuer", cfg.Issuer)
	die("serve", http.ListenAndServe(cfg.Addr, src.Handler()))
}

func newTapTapLogin(tap tapTapSettings) (*referencesource.TapTapLogin, error) {
	// Retry transient upstream failures. Only idempotent methods are retried, so
	// the device-code and redeem POSTs are deliberately sent once.
	doer := httpclient.Retry(&http.Client{Timeout: 15 * time.Second}, httpclient.RetryOptions{})
	enroller, err := taptapoauth.NewService(taptapoauth.Config{
		DeviceCodeEndpoint: tap.DeviceCodeEndpoint,
		TokenEndpoint:      tap.TokenEndpoint,
		UserInfoEndpoint:   tap.UserInfoEndpoint,
		ClientID:           tap.ClientID,
	}, doer)
	if err != nil {
		return nil, err
	}
	redeem, err := tapsign.NewService(tapsign.Config{
		BaseURL: tap.LeanCloudBaseURL,
		AppID:   tap.ClientID,
		AppKey:  tap.AppKey,
	}, doer, audit.NewMemoryLogger())
	if err != nil {
		return nil, err
	}
	return referencesource.NewTapTapLogin(
		referencesource.TapTapConfig{},
		referencesource.TapTapDeps{Enroller: enroller, Redeem: redeem},
	)
}

func newSocialLogin(cfg settings) (*referencesource.SocialLogin, error) {
	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: cfg.Issuer,
		CallbackPath: "/login/{provider}/callback",
		HTTPClient:   &http.Client{Timeout: 10 * time.Second},
		Credentials:  cfg.social,
	})
	if err != nil {
		return nil, err
	}
	return referencesource.NewSocialLogin(referencesource.SocialConfig{}, referencesource.SocialDeps{Registry: registry})
}

func newVault() (vault.Service, error) {
	// A dev KEK. A real deployment supplies one from outside the process, which is why the wrapper is
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
