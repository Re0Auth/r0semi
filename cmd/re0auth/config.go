package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/config"
	"github.com/Re0Auth/r0semi/internal/federation"
)

// The server configuration has two layers:
//
//   - a TOML file describes structure: endpoints, drivers, which providers
//     exist, which sources exist;
//   - the environment supplies secrets and may override the settings that differ
//     per deployment (issuer, address, DSN, KEK).
//
// A secret is NEVER written in the file. The file names the environment variable
// that holds it (`*_env`), so "where does this key come from" stays auditable and
// a committed config cannot leak a credential.

// file is the on-disk schema.
type file struct {
	Server  serverSection         `toml:"server"`
	Storage storageSection        `toml:"storage"`
	Vault   vaultSection          `toml:"vault"`
	Client  clientSection         `toml:"client"`
	IdP     map[string]idpSection `toml:"idp"`
	Sources []sourceSection       `toml:"sources"`
}

type serverSection struct {
	Issuer       string `toml:"issuer"`
	Addr         string `toml:"addr"`
	CookieSecure bool   `toml:"cookie_secure"`
	// RateLimit is requests per second per client address; zero disables the
	// limiter. RateLimitBurst is how many may arrive at once before the rate
	// applies.
	//
	// Pointers so that "absent" (take the default) is distinguishable from an
	// explicit zero (turn it off). With plain numbers those are the same value,
	// and the deployment that wanted limiting off would silently get the default.
	RateLimit      *float64 `toml:"rate_limit"`
	RateLimitBurst *int     `toml:"rate_limit_burst"`
}

type storageSection struct {
	// Driver is "memory" or "postgres". Empty means postgres when DSNEnv is set.
	Driver string `toml:"driver"`
	// DSNEnv names the variable holding the connection string, never the DSN.
	DSNEnv string `toml:"dsn_env"`
}

type vaultSection struct {
	// KEKEnv names the variable holding the 32-byte key encryption key.
	KEKEnv string `toml:"kek_env"`
	// KEKID labels the key in the stored records. It is how a record says which
	// key wrapped it, so it MUST change when the key material does.
	KEKID string `toml:"kek_id"`
	// Retired names KEKs that can still unwrap records but never wrap new ones.
	// They are what a rotation needs in order to read what it is re-wrapping, and
	// they can be deleted once -rotate-keys reports nothing left to do.
	Retired []retiredKeySection `toml:"retired"`
}

// retiredKeySection is one KEK that is kept only so records it wrapped stay
// readable.
type retiredKeySection struct {
	// KEKID must be the id that key had while it was current: that id is what the
	// records remember, not the one it has now.
	KEKID  string `toml:"kek_id"`
	KEKEnv string `toml:"kek_env"`
}

type clientSection struct {
	ID           string   `toml:"id"`
	Name         string   `toml:"name"`
	SecretEnv    string   `toml:"secret_env"`
	RedirectURIs []string `toml:"redirect_uris"`
	Scopes       []string `toml:"scopes"`
}

type idpSection struct {
	ClientID        string `toml:"client_id"`
	ClientSecretEnv string `toml:"client_secret_env"`
	// Overrides for self-hosted or proxied endpoints.
	AuthURL     string `toml:"auth_url"`
	TokenURL    string `toml:"token_url"`
	UserInfoURL string `toml:"userinfo_url"`
	Issuer      string `toml:"issuer"`
}

type sourceSection struct {
	Game        string `toml:"game"`
	Source      string `toml:"source"`
	DisplayName string `toml:"display_name"`
	Issuer      string `toml:"issuer"`
	TokenClass  string `toml:"token_class"`
	Status      string `toml:"status"`
	RawBase     string `toml:"raw_base"`
	// CascadeRevocation is where the source ends a whole upstream session, e.g.
	// "https://api.next-phi.example/oauth/cascade_revocation". Leave it out unless
	// the source's discovery document advertises cascade_revocation_endpoint:
	// setting it makes Re0Auth offer the action, and offering it where it does not
	// exist is a button that fails.
	CascadeRevocation string            `toml:"cascade_revocation"`
	ClientID          string            `toml:"client_id"`
	ClientSecretEnv   string            `toml:"client_secret_env"`
	Resources         []resourceSection `toml:"resources"`
}

type resourceSection struct {
	Name   string `toml:"name"`
	Schema string `toml:"schema"`
	Scope  string `toml:"scope"`
}

// settings is the resolved form the composition root consumes.
type settings struct {
	Addr        string
	Issuer      string
	DatabaseURL string
	KEK         []byte
	KEKID       string
	// RetiredKEKs can only unwrap. Empty unless a rotation is in progress or has
	// been left unfinished.
	RetiredKEKs  []retiredKEK
	CookieSecure bool
	// RateLimit is per client address, per second. Zero means no limiter.
	RateLimit      float64
	RateLimitBurst int

	clientID        string
	clientName      string
	clientSecret    string
	clientRedirects []string
	clientScopes    []string

	idpCredentials []idp.Credentials
	sources        []federation.Source
}

// retiredKEK is a key that can only unwrap, kept for as long as records written
// before a rotation still point at it.
type retiredKEK struct {
	ID  string
	KEK []byte
}

// knownIdP is the closed set of provider names accepted in the [idp] table.
var knownIdP = map[string]idp.Provider{
	"github":    idp.GitHub,
	"google":    idp.Google,
	"discord":   idp.Discord,
	"microsoft": idp.Microsoft,
	"qq":        idp.QQ,
}

// defaultConfigPath is where a deployment is expected to keep its config. The
// file is optional: with none, everything comes from the environment.
const defaultConfigPath = "config/re0auth.toml"

// authorizationRequestTTL is how long a pending consent handle stays valid.
//
// It must outlive the federation bind flow: the consent screen sends the player
// to the data source's own authorization page and back, and the handle has to
// still be there when they return. federation's bind TTL defaults to 10 minutes,
// so this leaves room for a QR scan and a slow login.
const authorizationRequestTTL = 30 * time.Minute

// Defaults for the per-address limiter. Deliberately coarse: this is load
// shedding, not quota enforcement, and per-client limits are a later refinement.
const (
	defaultRateLimit      = 50.0
	defaultRateLimitBurst = 100
)

// loadConfig reads the TOML file at path (empty = environment only), applies the
// environment overrides, resolves every secret by name, and validates the
// result. It fails closed: a half-configured server never starts.
func loadConfig(path string) (settings, error) {
	var f file
	if err := config.Read(path, &f); err != nil {
		return settings{}, err
	}

	cfg := settings{
		Addr:         config.FirstNonEmpty(os.Getenv("RE0AUTH_ADDR"), f.Server.Addr, "127.0.0.1:8080"),
		Issuer:       strings.TrimRight(config.FirstNonEmpty(os.Getenv("RE0AUTH_ISSUER"), f.Server.Issuer), "/"),
		CookieSecure: config.Bool("RE0AUTH_COOKIE_SECURE", f.Server.CookieSecure),
		KEKID:        config.FirstNonEmpty(os.Getenv("RE0AUTH_KEK_ID"), f.Vault.KEKID, "kek-1"),
		DatabaseURL:  os.Getenv("DATABASE_URL"),
	}
	if cfg.Issuer == "" {
		return settings{}, errors.New("server.issuer is required (or RE0AUTH_ISSUER); e.g. https://re0auth.example")
	}
	if !strings.HasPrefix(cfg.Issuer, "http://") && !strings.HasPrefix(cfg.Issuer, "https://") {
		return settings{}, fmt.Errorf("server.issuer %q must be an absolute http(s) URL", cfg.Issuer)
	}

	// Rate limiting. Resolved before anything else that could fail, so a typo in
	// these numbers is reported rather than quietly replaced by a default.
	rateLimit := defaultRateLimit
	if f.Server.RateLimit != nil {
		rateLimit = *f.Server.RateLimit
	}
	rateBurst := defaultRateLimitBurst
	if f.Server.RateLimitBurst != nil {
		rateBurst = *f.Server.RateLimitBurst
	}
	limitValue, err := config.Float("RE0AUTH_RATE_LIMIT", rateLimit)
	if err != nil {
		return settings{}, err
	}
	burstValue, err := config.Int("RE0AUTH_RATE_LIMIT_BURST", rateBurst)
	if err != nil {
		return settings{}, err
	}
	cfg.RateLimit, cfg.RateLimitBurst = limitValue, burstValue
	switch {
	case cfg.RateLimit < 0:
		return settings{}, errors.New("server.rate_limit cannot be negative (use 0 to disable the limiter)")
	case cfg.RateLimit == 0:
		// Off, and the burst is meaningless alongside it.
		cfg.RateLimitBurst = 0
	case cfg.RateLimitBurst < 1:
		// Fail closed rather than let the limiter clamp it: a burst of zero is not
		// what anyone means, and silently running with one is worse than saying so.
		return settings{}, errors.New("server.rate_limit_burst must be at least 1 when rate_limit is set")
	}

	// Storage. An explicit driver wins; otherwise a named DSN means postgres.
	driver := f.Storage.Driver
	if driver == "" {
		if f.Storage.DSNEnv != "" {
			driver = "postgres"
		} else {
			driver = "memory"
		}
	}
	switch driver {
	case "memory":
		cfg.DatabaseURL = ""
	case "postgres":
		if cfg.DatabaseURL == "" {
			dsn, err := config.Secret(f.Storage.DSNEnv, "storage.dsn_env")
			if err != nil {
				return settings{}, err
			}
			cfg.DatabaseURL = dsn
		}
	default:
		return settings{}, fmt.Errorf("storage.driver %q must be \"memory\" or \"postgres\"", driver)
	}

	// Vault: the KEK is required, and its length is checked here so a bad key
	// fails before anything else is wired.
	kekValue := os.Getenv("RE0AUTH_KEK")
	if kekValue == "" {
		if f.Vault.KEKEnv == "" {
			return settings{}, errors.New("the vault KEK is required: set RE0AUTH_KEK or vault.kek_env")
		}
		resolved, err := config.Secret(f.Vault.KEKEnv, "vault.kek_env")
		if err != nil {
			return settings{}, err
		}
		kekValue = resolved
	}
	cfg.KEK, err = decodeKEK32(kekValue)
	if err != nil {
		return settings{}, err
	}

	// Retired KEKs, resolved and length-checked here for the same reason: a
	// malformed one would otherwise surface as "every credential is unreadable"
	// at rotation time.
	for i, retired := range f.Vault.Retired {
		field := fmt.Sprintf("vault.retired[%d]", i)
		switch {
		case retired.KEKID == "":
			return settings{}, fmt.Errorf("%s.kek_id is required", field)
		case retired.KEKID == cfg.KEKID:
			return settings{}, fmt.Errorf(
				"%s.kek_id %q is the current key's id; a retired key must be a different key",
				field, retired.KEKID)
		}
		value, err := config.Secret(retired.KEKEnv, field+".kek_env")
		if err != nil {
			return settings{}, err
		}
		key, err := decodeKEK32(value)
		if err != nil {
			return settings{}, fmt.Errorf("%s: %w", field, err)
		}
		cfg.RetiredKEKs = append(cfg.RetiredKEKs, retiredKEK{ID: retired.KEKID, KEK: key})
	}

	// Downstream client.
	cfg.clientID = config.FirstNonEmpty(os.Getenv("RE0AUTH_CLIENT_ID"), f.Client.ID, "cli")
	cfg.clientName = config.FirstNonEmpty(os.Getenv("RE0AUTH_CLIENT_NAME"), f.Client.Name, "First-party client")
	cfg.clientRedirects = f.Client.RedirectURIs
	if len(cfg.clientRedirects) == 0 {
		cfg.clientRedirects = []string{cfg.Issuer + "/callback"}
	}
	cfg.clientScopes = f.Client.Scopes
	if len(cfg.clientScopes) == 0 {
		cfg.clientScopes = []string{"account.id"}
	}
	if f.Client.SecretEnv != "" {
		value, err := config.Secret(f.Client.SecretEnv, "client.secret_env")
		if err != nil {
			return settings{}, err
		}
		cfg.clientSecret = value
	}

	if err := loadIdP(&cfg, f.IdP); err != nil {
		return settings{}, err
	}
	if err := loadSources(&cfg, f.Sources); err != nil {
		return settings{}, err
	}
	return cfg, nil
}

func loadIdP(cfg *settings, sections map[string]idpSection) error {
	if len(sections) == 0 {
		return nil
	}
	names := make([]string, 0, len(sections))
	for name := range sections {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic order, so startup logs are stable

	for _, name := range names {
		provider, ok := knownIdP[name]
		if !ok {
			return fmt.Errorf("idp.%s: unknown provider (known: %s)", name, strings.Join(knownNames(knownIdP), ", "))
		}
		section := sections[name]
		if section.ClientID == "" {
			return fmt.Errorf("idp.%s.client_id is required", name)
		}
		credential := idp.Credentials{
			Provider:    provider,
			ClientID:    section.ClientID,
			AuthURL:     section.AuthURL,
			TokenURL:    section.TokenURL,
			UserInfoURL: section.UserInfoURL,
			Issuer:      section.Issuer,
		}
		if section.ClientSecretEnv != "" {
			value, err := config.Secret(section.ClientSecretEnv, "idp."+name+".client_secret_env")
			if err != nil {
				return err
			}
			credential.ClientSecret = value
		}
		cfg.idpCredentials = append(cfg.idpCredentials, credential)
	}
	return nil
}

func loadSources(cfg *settings, sections []sourceSection) error {
	for i, section := range sections {
		source := federation.Source{
			Game:        section.Game,
			Name:        section.Source,
			DisplayName: section.DisplayName,
			Issuer:      section.Issuer,
			TokenClass:  section.TokenClass,
			Status:      federation.SourceStatus(section.Status),
			RawBase:     section.RawBase,
			// Both are capabilities, and both are opt-in: an empty value means
			// "this source cannot do it", which is what stops Re0Auth offering
			// something that would fail.
			CascadeRevocationEndpoint: section.CascadeRevocation,
			ClientID:                  section.ClientID,
		}
		if section.ClientSecretEnv != "" {
			value, err := config.Secret(section.ClientSecretEnv, fmt.Sprintf("sources[%d].client_secret_env", i))
			if err != nil {
				return err
			}
			source.ClientSecret = value
		}
		for _, res := range section.Resources {
			source.Resources = append(source.Resources, federation.Resource{
				Name: res.Name, Schema: res.Schema, Scope: res.Scope,
			})
		}
		cfg.sources = append(cfg.sources, source)
	}
	// The registry is the authority on what a valid source looks like, so its
	// validation is the source of truth rather than a duplicate here.
	if _, err := federation.NewRegistry(cfg.sources...); err != nil {
		return fmt.Errorf("sources: %w", err)
	}
	return nil
}

// knownNames returns the sorted keys of a provider table, for error messages.
func knownNames(table map[string]idp.Provider) []string {
	out := make([]string, 0, len(table))
	for name := range table {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// decodeKEK32 decodes a KEK and checks its length, so a short or long key fails
// at configuration time rather than at the first unwrap.
func decodeKEK32(value string) ([]byte, error) {
	decoded, err := decodeKEK(value)
	if err != nil {
		return nil, err
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("a vault KEK must be 32 bytes, got %d", len(decoded))
	}
	return decoded, nil
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
	return nil, errors.New("the vault KEK must be base64 or hex")
}
