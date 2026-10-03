package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R10-08 / KIT-R10-08: the reference source's session and social-bind cookies
// have no Secure flag, and no configuration could set one. The loader now takes
// [server] cookie_secure and refuses an https issuer with it false, the same rule
// cmd/re0auth enforces for its session cookie.

const r10CookieSecureTOML = `
[server]
issuer = "https://src.example"
cookie_secure = COOKIE_SECURE

[client]
secret_env = "R10_08_CLIENT_SECRET"

[source]
provider = "phigros"

[[source.resources]]
name   = "profile"
schema = "re0auth.phigros.profile/1"
scope  = "phigros.profile.read"
`

func r10WriteConfig(t *testing.T, cookieSecure string) string {
	t.Helper()
	t.Setenv("R10_08_CLIENT_SECRET", "test-secret")
	t.Setenv("REFERENCE_SOURCE_ISSUER", "")
	t.Setenv("REFERENCE_SOURCE_COOKIE_SECURE", "")
	path := filepath.Join(t.TempDir(), "referencesource.toml")
	body := strings.Replace(r10CookieSecureTOML, "COOKIE_SECURE", cookieSecure, 1)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestR10_08HTTPSIssuerRequiresSecureCookies(t *testing.T) {
	path := r10WriteConfig(t, "false")
	_, err := loadConfig(path)
	if err == nil {
		t.Fatal("an https issuer with cookie_secure=false was accepted; the session and bind cookies " +
			"would travel without the Secure attribute")
	}
	if !strings.Contains(err.Error(), "cookie_secure") {
		t.Fatalf("the refusal does not name cookie_secure: %v", err)
	}

	path = r10WriteConfig(t, "true")
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("an https issuer with cookie_secure=true was refused: %v", err)
	}
	if !cfg.CookieSecure {
		t.Fatal("cookie_secure=true was not carried into the settings")
	}
}
