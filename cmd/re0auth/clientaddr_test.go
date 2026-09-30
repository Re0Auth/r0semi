package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/httpapi"
)

// The client-address switch is a deployment-level statement about its own reverse
// proxy: who may speak for a client (trusted_proxies) and what that proxy writes
// (client_addr_header). The rate limiter's bucket key comes from it, so a
// configuration that cannot take effect must be refused rather than accepted and
// silently ignored.
func TestClientAddrHeaderResolution(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(make([]byte, 32))

	writeConfig := func(t *testing.T, serverExtra string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "re0auth.toml")
		body := "[server]\nissuer = \"https://re0auth.test\"\n" + serverExtra +
			"\n[storage]\ndriver = \"memory\"\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	base := func(t *testing.T) {
		t.Helper()
		t.Setenv("RE0AUTH_ISSUER", "https://re0auth.test")
		t.Setenv("RE0AUTH_COOKIE_SECURE", "true")
		t.Setenv("RE0AUTH_KEK", valid)
		t.Setenv("RE0AUTH_OIDC_TOKEN_KEY", valid)
		t.Setenv("DATABASE_URL", "")
		t.Setenv("RE0AUTH_AUDIT_KEY", "")
		unsetEnv(t, "RE0AUTH_TRUSTED_PROXIES")
		t.Setenv("RE0AUTH_CLIENT_ADDR_HEADER", "")
	}

	t.Run("unset means no header is read", func(t *testing.T) {
		base(t)
		cfg, err := loadConfig(writeConfig(t, ""))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ClientAddrHeader != httpapi.ClientAddrPeer {
			t.Fatalf("ClientAddrHeader = %v, want the peer", cfg.ClientAddrHeader)
		}
	})

	t.Run("declared with a trust list", func(t *testing.T) {
		base(t)
		cfg, err := loadConfig(writeConfig(t,
			"client_addr_header = \"x-forwarded-for\"\ntrusted_proxies = [\"10.0.0.0/8\"]\n"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ClientAddrHeader != httpapi.ClientAddrXForwardedFor {
			t.Fatalf("ClientAddrHeader = %v, want x-forwarded-for", cfg.ClientAddrHeader)
		}
		if len(cfg.TrustedProxies) != 1 {
			t.Fatalf("TrustedProxies = %v, want one entry", cfg.TrustedProxies)
		}
	})

	t.Run("declaring a header with no trusted proxy is refused", func(t *testing.T) {
		// It could never take effect — the header is only read from a trusted peer —
		// and a deployment that believes it has per-client buckets when every client
		// shares one is exactly the state this refuses.
		base(t)
		_, err := loadConfig(writeConfig(t, "client_addr_header = \"x-forwarded-for\"\n"))
		if err == nil {
			t.Fatal("a header with no trusted proxy was accepted")
		}
		if !strings.Contains(err.Error(), "trusted_proxies") {
			t.Fatalf("the refusal does not name the missing setting: %v", err)
		}
	})

	t.Run("an unknown header name is refused", func(t *testing.T) {
		base(t)
		_, err := loadConfig(writeConfig(t,
			"client_addr_header = \"x-real-ip\"\ntrusted_proxies = [\"10.0.0.0/8\"]\n"))
		if err == nil {
			t.Fatal("an unknown header name was accepted")
		}
		if !strings.Contains(err.Error(), "x-forwarded-for") {
			t.Fatalf("the refusal does not name the accepted values: %v", err)
		}
	})

	t.Run("the environment beats the file", func(t *testing.T) {
		base(t)
		t.Setenv("RE0AUTH_TRUSTED_PROXIES", "10.0.0.0/8")
		t.Setenv("RE0AUTH_CLIENT_ADDR_HEADER", "x-forwarded-for")
		cfg, err := loadConfig(writeConfig(t, "client_addr_header = \"none\"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ClientAddrHeader != httpapi.ClientAddrXForwardedFor {
			t.Fatalf("ClientAddrHeader = %v, want the environment's x-forwarded-for", cfg.ClientAddrHeader)
		}
	})

	t.Run("the environment cannot declare a header without a trust list either", func(t *testing.T) {
		base(t)
		t.Setenv("RE0AUTH_CLIENT_ADDR_HEADER", "x-forwarded-for")
		if _, err := loadConfig(writeConfig(t, "")); err == nil {
			t.Fatal("the environment declared a header with no trusted proxy")
		}
	})
}
