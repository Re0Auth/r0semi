package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/config"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/store/postgres"
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
	Admin   adminSection          `toml:"admin"`
	IdP     map[string]idpSection `toml:"idp"`
	Sources []sourceSection       `toml:"sources"`
}

// adminSection is the operator allowlist. There is no role table: an account is
// an operator because a deployment names it here, never because it signed up.
type adminSection struct {
	// Subjects are account ids (`usr_…`) allowed to use /v1/admin.
	Subjects []string `toml:"subjects"`
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
	// TrustedProxies are the networks whose X-Forwarded-For header is believed
	// when attributing a request to a client. Empty means none: the peer address
	// is the client. Set it only to your own reverse proxies' addresses.
	TrustedProxies []string `toml:"trusted_proxies"`
	// InternalAddr is where the operational surface is served: Prometheus metrics
	// and the Go runtime's profiling endpoints. Empty disables it entirely — the
	// default, because profiling endpoints belong on a private network and never
	// on the public one. Point it at a loopback or cluster-internal address.
	InternalAddr string `toml:"internal_addr"`
	// IntrospectionClients lists client ids allowed to introspect tokens issued
	// to other clients — resource servers. A client may always introspect its own
	// tokens; empty means nobody else's are visible.
	IntrospectionClients []string `toml:"introspection_clients"`
}

type storageSection struct {
	// Driver is "memory" or "postgres". Empty means postgres when DSNEnv is set.
	Driver string `toml:"driver"`
	// DSNEnv names the variable holding the connection string, never the DSN.
	DSNEnv string `toml:"dsn_env"`

	// Pool sizing. Pointers so "absent" (take the default) is distinguishable
	// from an explicit zero, the same reason server.rate_limit is a pointer: a
	// pool of zero connections is not a configuration anyone means, and treating
	// it as "unset" would hide the mistake behind a working default.
	//
	// The durations are strings in Go's own form ("5s", "30s") rather than
	// numbers, because a bare number has no unit and guessing one is how a
	// 30-second timeout becomes 30 nanoseconds.
	MaxConns         *int    `toml:"max_conns"`
	MinConns         *int    `toml:"min_conns"`
	ConnectTimeout   *string `toml:"connect_timeout"`
	StatementTimeout *string `toml:"statement_timeout"`
}

// poolSettings bounds the Postgres connection pool. It mirrors the shape of the
// file section with real types, so the composition root passes values the driver
// can use without parsing.
type poolSettings struct {
	MaxConns         int32
	MinConns         int32
	ConnectTimeout   time.Duration
	StatementTimeout time.Duration
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
	// Issuer names an OIDC provider. On a built-in provider it overrides the
	// built-in issuer; on any other name it is required and makes that name a
	// custom OIDC provider.
	Issuer string `toml:"issuer"`
	// DisplayName is the sign-in button's label. Empty falls back to the
	// built-in name, then to the provider id.
	DisplayName string `toml:"display_name"`
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
	// AuditKey authenticates the durable audit record chain. It is required
	// whenever the audit log is durable: an unsigned chain is not tamper-evidence.
	AuditKey []byte
	// RetiredKEKs can only unwrap. Empty unless a rotation is in progress or has
	// been left unfinished.
	RetiredKEKs  []retiredKEK
	CookieSecure bool
	// RateLimit is per client address, per second. Zero means no limiter.
	RateLimit      float64
	RateLimitBurst int
	// TrustedProxies are the networks whose X-Forwarded-For is believed when
	// resolving the client address. Empty means no proxy is trusted.
	TrustedProxies []netip.Prefix
	// InternalAddr is the address of the operational listener that serves metrics
	// and profiling. Empty means it is not served at all.
	InternalAddr string
	// IntrospectionClients are the client ids allowed to introspect other
	// clients' tokens. Empty means only a client's own tokens are visible.
	IntrospectionClients []string
	// Pool bounds the Postgres connection pool. Meaningless in memory mode; it is
	// still resolved and validated there, so a typo is reported rather than
	// discovered the day the deployment grows a database.
	Pool poolSettings

	clientID        string
	clientName      string
	clientSecret    string
	clientRedirects []string
	clientScopes    []string

	idpCredentials []idp.Credentials
	sources        []federation.Source
	// adminSubjects is the operator allowlist. Empty means the operator plane is
	// not mounted at all.
	adminSubjects []string
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
		InternalAddr: config.FirstNonEmpty(os.Getenv("RE0AUTH_INTERNAL_ADDR"), f.Server.InternalAddr),
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

	// Trusted proxies. The environment overrides the file, like every other
	// setting. Absent means no proxy is trusted, which is the safe default: the
	// peer address is then the client, and a fabricated X-Forwarded-For is
	// ignored.
	proxyValues := f.Server.TrustedProxies
	if env := strings.TrimSpace(os.Getenv("RE0AUTH_TRUSTED_PROXIES")); env != "" {
		proxyValues = strings.Split(env, ",")
	}
	cfg.TrustedProxies, err = parseTrustedProxies(proxyValues)
	if err != nil {
		return settings{}, err
	}

	// The operational surface must not be the public one. They are separate
	// addresses precisely so profiling endpoints cannot be scraped through the
	// public listener; configuring them the same would defeat that.
	if cfg.InternalAddr != "" && cfg.InternalAddr == cfg.Addr {
		return settings{}, errors.New(
			"server.internal_addr must differ from server.addr: the operational surface is not the public one")
	}

	// Introspection policy. The environment overrides the file, like every other
	// setting. Empty is the safe default: a client sees only its own tokens.
	introspectionValues := f.Server.IntrospectionClients
	if env := strings.TrimSpace(os.Getenv("RE0AUTH_INTROSPECTION_CLIENTS")); env != "" {
		introspectionValues = strings.Split(env, ",")
	}
	for _, raw := range introspectionValues {
		if id := strings.TrimSpace(raw); id != "" {
			cfg.IntrospectionClients = append(cfg.IntrospectionClients, id)
		}
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

	// The connection pool. Resolved even in memory mode, where nothing uses it, so
	// a typo is reported now rather than on the day a deployment grows a database.
	cfg.Pool, err = resolvePool(f.Storage)
	if err != nil {
		return settings{}, err
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

	// The audit chain key. Required exactly when the audit log is durable: the
	// in-memory log is a ring buffer that is not tamper-evident by construction,
	// so there is nothing for a key to protect, while a durable chain signed with
	// no key would be a control that only looks like one.
	if cfg.DatabaseURL != "" {
		value := os.Getenv("RE0AUTH_AUDIT_KEY")
		if value == "" {
			return settings{}, errors.New(
				"RE0AUTH_AUDIT_KEY is required when the audit log is durable (32 bytes, base64 or hex)")
		}
		cfg.AuditKey, err = decodeKey32(value, "the audit chain key")
		if err != nil {
			return settings{}, fmt.Errorf("RE0AUTH_AUDIT_KEY: %w", err)
		}
	}

	// Retired KEKs, resolved and length-checked here for the same reason: a
	// malformed one would otherwise surface as "every credential is unreadable"
	// at rotation time.
	for i, retired := range f.Vault.Retired {
		field := fmt.Sprintf("vault.retired[%d]", i)
		switch retired.KEKID {
		case "":
			return settings{}, fmt.Errorf("%s.kek_id is required", field)
		case cfg.KEKID:
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

	// Operator plane. Off unless a deployment names at least one account: an admin
	// API is not something to expose by accident, and an empty allowlist that
	// still mounted the routes would be a door with no lock.
	if v := strings.TrimSpace(os.Getenv("RE0AUTH_ADMIN_SUBJECTS")); v != "" {
		for _, part := range strings.Split(v, ",") {
			if s := strings.TrimSpace(part); s != "" {
				cfg.adminSubjects = append(cfg.adminSubjects, s)
			}
		}
	} else {
		for _, s := range f.Admin.Subjects {
			if s = strings.TrimSpace(s); s != "" {
				cfg.adminSubjects = append(cfg.adminSubjects, s)
			}
		}
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
		section := sections[name]
		provider, builtIn := knownIdP[name]
		if !builtIn {
			// A custom provider is any OIDC issuer: a self-hosted Keycloak,
			// Authentik, or a Passkey provider. It must name its issuer; the
			// registry discovers the endpoints from it.
			if strings.TrimSpace(section.Issuer) == "" {
				return fmt.Errorf(
					"idp.%s: unknown provider (known: %s); a custom provider must set issuer",
					name, strings.Join(knownNames(knownIdP), ", "))
			}
			provider = idp.Provider(name)
		}
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
			DisplayName: section.DisplayName,
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

// decodeKEK32 decodes a key and checks its length, so a short or long key fails
// at configuration time rather than at the first unwrap.
func decodeKEK32(value string) ([]byte, error) {
	return decodeKey32(value, "a vault KEK")
}

// decodeKey32 is decodeKEK32 with the name of the key in the error, so a bad
// audit key does not report itself as a bad vault KEK.
//
// It accepts the first encoding that yields exactly 32 bytes, rather than the
// first that merely decodes. Base64 is tried first everywhere it appears, and a
// 32-byte key written as hex is 64 characters — all of them in the base64
// alphabet, and a multiple of 4 — so a "try base64, then check the length" order
// decoded it to 48 bytes and rejected it. The hex branch was dead code, and the
// operator was told the KEY was the wrong size when the FORMAT was the problem:
// the obvious remedy, generating a new key, silently makes every stored
// credential unreadable.
//
// There is no ambiguity between the two: 32 bytes of base64 is 43 or 44
// characters, and 32 bytes of hex is 64.
func decodeKey32(value, what string) ([]byte, error) {
	for _, decode := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		hex.DecodeString,
	} {
		if decoded, err := decode(value); err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("%s must be 32 bytes, base64 or hex", what)
}

// parseTrustedProxies parses CIDR prefixes, and bare addresses as single-host
// prefixes. A malformed entry is an error rather than a skipped one: a typo that
// quietly trusted nobody — or, if it were handled differently, everybody — is
// exactly the kind of setting that looks applied and is not.
func parseTrustedProxies(values []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(v); err == nil {
			out = append(out, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return nil, fmt.Errorf("server.trusted_proxies entry %q is not an IP address or CIDR", v)
		}
		addr = addr.Unmap()
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}

// resolvePool merges the defaults, the storage section and the environment into
// the pool the composition root hands to the driver. The precedence is the one
// the whole file promises: environment > file > default.
//
// It validates rather than clamps. postgres.Open will bend a contradictory
// configuration into something runnable — it has to, because it cannot know
// whether it was handed a bug or a deliberate minimum — but a server that starts
// with numbers the operator did not choose is the failure mode this project
// consistently refuses. Say what is wrong and do not start.
func resolvePool(section storageSection) (poolSettings, error) {
	defaults := postgres.DefaultPoolOptions()
	out := poolSettings{
		MaxConns:         defaults.MaxConns,
		MinConns:         defaults.MinConns,
		ConnectTimeout:   defaults.ConnectTimeout,
		StatementTimeout: defaults.StatementTimeout,
	}
	if section.MaxConns != nil {
		out.MaxConns = int32(*section.MaxConns)
	}
	if section.MinConns != nil {
		out.MinConns = int32(*section.MinConns)
	}
	if section.ConnectTimeout != nil {
		d, err := parseDuration(*section.ConnectTimeout, "storage.connect_timeout")
		if err != nil {
			return poolSettings{}, err
		}
		out.ConnectTimeout = d
	}
	if section.StatementTimeout != nil {
		d, err := parseDuration(*section.StatementTimeout, "storage.statement_timeout")
		if err != nil {
			return poolSettings{}, err
		}
		out.StatementTimeout = d
	}

	var err error
	if out.MaxConns, err = envInt32("RE0AUTH_STORAGE_MAX_CONNS", out.MaxConns); err != nil {
		return poolSettings{}, err
	}
	if out.MinConns, err = envInt32("RE0AUTH_STORAGE_MIN_CONNS", out.MinConns); err != nil {
		return poolSettings{}, err
	}
	if out.ConnectTimeout, err = envDuration("RE0AUTH_STORAGE_CONNECT_TIMEOUT", out.ConnectTimeout); err != nil {
		return poolSettings{}, err
	}
	if out.StatementTimeout, err = envDuration("RE0AUTH_STORAGE_STATEMENT_TIMEOUT", out.StatementTimeout); err != nil {
		return poolSettings{}, err
	}

	switch {
	case out.MaxConns < 1:
		return poolSettings{}, errors.New("storage.max_conns must be at least 1")
	case out.MinConns < 0:
		return poolSettings{}, errors.New("storage.min_conns cannot be negative (use 0 for no warm connections)")
	case out.MinConns > out.MaxConns:
		return poolSettings{}, errors.New(
			"storage.min_conns cannot exceed storage.max_conns: a warm set larger than the cap is a contradiction, not a preference")
	case out.ConnectTimeout <= 0:
		return poolSettings{}, errors.New(`storage.connect_timeout must be positive (e.g. "5s")`)
	case out.StatementTimeout < 0:
		return poolSettings{}, errors.New(
			`storage.statement_timeout cannot be negative (use "0s" to leave the server's setting alone)`)
	}
	return out, nil
}

// envInt32 overrides a value from an environment variable, so a deployment that
// configures by environment alone can still size its pool.
func envInt32(name string, target int32) (int32, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return target, nil
	}
	n, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s %q is not an integer", name, raw)
	}
	return int32(n), nil
}

// envDuration is envInt32 for a Go duration string.
func envDuration(name string, target time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return target, nil
	}
	return parseDuration(raw, name)
}

// parseDuration parses a Go duration ("5s", "1m30s"). A value that does not parse
// is an error rather than a silently ignored setting: a timeout that was typed
// and not applied is worse than one that was never typed, because the operator
// believes it is in force.
func parseDuration(raw, what string) (time.Duration, error) {
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s %q is not a duration (e.g. \"5s\", \"1m\")", what, raw)
	}
	return d, nil
}
