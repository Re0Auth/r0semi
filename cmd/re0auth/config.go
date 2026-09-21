package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/federation"
)

// config is the composition root's whole input. Everything is environment
// driven: a deployment describes itself, and nothing is inferred.
type config struct {
	Addr         string
	Issuer       string
	DatabaseURL  string
	KEK          string
	CookieSecure bool

	clientID        string
	clientName      string
	clientSecret    string
	clientRedirects []string
	clientScopes    []string

	idpCredentials []idp.Credentials
	sources        []federation.Source
}

func loadConfig() (config, error) {
	cfg := config{
		Addr:         envOr("RE0AUTH_ADDR", "127.0.0.1:8080"),
		Issuer:       strings.TrimRight(os.Getenv("RE0AUTH_ISSUER"), "/"),
		DatabaseURL:  os.Getenv("DATABASE_URL"),
		KEK:          os.Getenv("RE0AUTH_KEK"),
		CookieSecure: os.Getenv("RE0AUTH_COOKIE_SECURE") == "true",
	}
	switch {
	case cfg.Issuer == "":
		return config{}, errors.New("RE0AUTH_ISSUER is required (e.g. https://re0auth.example)")
	case cfg.KEK == "":
		return config{}, errors.New("RE0AUTH_KEK is required (32 bytes, base64 or hex)")
	}

	cfg.clientID = envOr("RE0AUTH_CLIENT_ID", "cli")
	cfg.clientName = envOr("RE0AUTH_CLIENT_NAME", "First-party client")
	cfg.clientSecret = os.Getenv("RE0AUTH_CLIENT_SECRET")
	redirects := envOr("RE0AUTH_CLIENT_REDIRECTS", cfg.Issuer+"/callback")
	cfg.clientRedirects = splitList(redirects)
	cfg.clientScopes = splitList(envOr("RE0AUTH_CLIENT_SCOPES", "account.id"))

	credentials, err := loadIdP()
	if err != nil {
		return config{}, err
	}
	cfg.idpCredentials = credentials

	sources, err := loadSources()
	if err != nil {
		return config{}, err
	}
	cfg.sources = sources
	return cfg, nil
}

// idpEnv maps an environment prefix to a provider. A provider with no client id
// is simply absent, so the frontend only offers what is configured.
var idpEnv = []struct {
	prefix   string
	provider idp.Provider
}{
	{"GITHUB", idp.GitHub},
	{"GOOGLE", idp.Google},
	{"DISCORD", idp.Discord},
	{"MICROSOFT", idp.Microsoft},
	{"QQ", idp.QQ},
}

func loadIdP() ([]idp.Credentials, error) {
	var out []idp.Credentials
	for _, entry := range idpEnv {
		clientID := os.Getenv(entry.prefix + "_CLIENT_ID")
		if clientID == "" {
			continue
		}
		cred := idp.Credentials{
			Provider:     entry.provider,
			ClientID:     clientID,
			ClientSecret: os.Getenv(entry.prefix + "_CLIENT_SECRET"),
		}
		// Optional overrides, for self-hosted or proxied endpoints.
		cred.AuthURL = os.Getenv(entry.prefix + "_AUTH_URL")
		cred.TokenURL = os.Getenv(entry.prefix + "_TOKEN_URL")
		cred.UserInfoURL = os.Getenv(entry.prefix + "_USERINFO_URL")
		cred.Issuer = os.Getenv(entry.prefix + "_ISSUER")
		out = append(out, cred)
	}
	return out, nil
}

// loadSources reads RE0AUTH_SOURCES, a JSON array of data sources. It is JSON
// rather than a bespoke format so a deployment can generate it.
func loadSources() ([]federation.Source, error) {
	raw := os.Getenv("RE0AUTH_SOURCES")
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var sources []federation.Source
	if err := json.Unmarshal([]byte(raw), &sources); err != nil {
		return nil, fmt.Errorf("RE0AUTH_SOURCES is not a valid source array: %w", err)
	}
	return sources, nil
}

// decodeKEK accepts base64 (standard or raw) or hex, because operators paste it
// from whichever tool generated it.
func decodeKEK(value string) ([]byte, error) {
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	if decoded, err := hex.DecodeString(value); err == nil {
		return decoded, nil
	}
	return nil, errors.New("RE0AUTH_KEK must be base64 or hex")
}

func splitList(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
