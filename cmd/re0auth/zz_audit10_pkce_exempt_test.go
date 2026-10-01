package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// The PKCE exemption is wired from `[client] allow_missing_pkce` through
// configuredClient and the startup drift check. These tests pin the three places a
// transcription error would otherwise hide: the config key, the client it builds,
// and the refusal to start when the registry disagrees.

func TestConfiguredClientPKCEExemptionIsOptIn(t *testing.T) {
	cfg := settings{
		clientID:        "cli",
		clientName:      "CLI",
		clientSecret:    "s3cret",
		clientRedirects: []string{"https://app.example/cb"},
		clientScopes:    []string{"account.id"},
	}

	plain, err := configuredClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if plain.AllowMissingPKCE {
		t.Fatal("configuredClient granted the PKCE exemption without allow_missing_pkce")
	}

	cfg.clientAllowMissingPKCE = true
	exempt, err := configuredClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !exempt.AllowMissingPKCE {
		t.Fatal("configuredClient dropped allow_missing_pkce = true")
	}
	if exempt.ID != "cli" || !exempt.Authenticate("s3cret") {
		t.Fatalf("the exempt client lost its identity: %+v", exempt)
	}
}

func TestConfiguredClientRefusesExemptPublicClient(t *testing.T) {
	// No secret: this is a public client, and a public client without PKCE has no
	// binding at all at the token endpoint.
	cfg := settings{
		clientID:               "spa",
		clientName:             "SPA",
		clientRedirects:        []string{"https://app.example/cb"},
		clientScopes:           []string{"account.id"},
		clientAllowMissingPKCE: true,
	}
	if _, err := configuredClient(cfg); err == nil {
		t.Fatal("configuredClient granted the PKCE exemption to a public client")
	} else if !strings.Contains(err.Error(), "allow_missing_pkce") {
		t.Fatalf("the refusal does not name the field: %v", err)
	}
	// The same client without the exemption is fine, and so is a confidential one
	// with it.
	cfg.clientAllowMissingPKCE = false
	if _, err := configuredClient(cfg); err != nil {
		t.Fatalf("a plain public client was refused: %v", err)
	}
}

func TestClientDriftNamesThePKCEExemption(t *testing.T) {
	registered, err := oauth.NewClient("cli", "CLI", oauth.ClientConfidential, "s3cret",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}

	// The file turns the exemption on, the registry does not.
	drift := clientDrift(registered, registered.WithAllowMissingPKCE(true))
	if len(drift) != 1 || !strings.Contains(drift[0], "allow_missing_pkce") {
		t.Fatalf("drift = %v, want the PKCE exemption named", drift)
	}
	// The file turns it back off: a stricter value must not be ignored either.
	drift = clientDrift(registered.WithAllowMissingPKCE(true), registered)
	if len(drift) != 1 || !strings.Contains(drift[0], "allow_missing_pkce") {
		t.Fatalf("drift = %v, want the PKCE exemption named", drift)
	}
	// Unchanged: no drift at all.
	if drift := clientDrift(registered, registered); len(drift) != 0 {
		t.Fatalf("identical clients drifted: %v", drift)
	}
}

func TestLoadConfigReadsAllowMissingPKCE(t *testing.T) {
	t.Setenv("RE0AUTH_KEK", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	dir := t.TempDir()

	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(dir, "re0auth.toml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	base := "[server]\nissuer = \"https://auth.example\"\ncookie_secure = true\n\n[client]\nid = \"cli\"\n"

	cfg, err := loadConfig(write(t, base))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.clientAllowMissingPKCE {
		t.Fatal("allow_missing_pkce defaulted to true")
	}

	cfg, err = loadConfig(write(t, base+"allow_missing_pkce = true\n"))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !cfg.clientAllowMissingPKCE {
		t.Fatal("allow_missing_pkce = true was not read from the file")
	}
}
