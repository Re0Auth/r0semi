package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/config"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/httpapi"
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
	Server   serverSection   `toml:"server"`
	Storage  storageSection  `toml:"storage"`
	Upstream upstreamSection `toml:"upstream"`
	Vault    vaultSection    `toml:"vault"`
	Client   clientSection   `toml:"client"`
	// Clients adds downstream clients beyond the primary [client] section, one
	// [[clients]] entry each. They are registered with the same validation, the
	// same drift refusal and the same PKCE default as [client]; see
	// docs/architecture.md. An entry may also be the only client a deployment has,
	// in which case the [client] section is left out entirely.
	Clients []clientSection       `toml:"clients"`
	Admin   adminSection          `toml:"admin"`
	IdP     map[string]idpSection `toml:"idp"`
	Sources []sourceSection       `toml:"sources"`
}

// upstreamSection governs the outbound clients — the data plane's source calls
// and the identity providers' token, userinfo and discovery calls.
type upstreamSection struct {
	// AllowPrivateAddresses permits outbound connections to loopback, link-local
	// and private addresses. It is a boolean rather than a list because the
	// question is "may this process reach my internal network", and the useful
	// answers are yes and no.
	//
	// Off by default, and it must be turned on deliberately: the endpoints come
	// from configuration, so a compromised or mistaken source registration is
	// enough to point a request at the cloud metadata address or an internal
	// service, and on the raw passthrough the answer comes back to the caller.
	// Self-hosted data sources on a private network are a supported shape, so this
	// is an acknowledgement rather than a prohibition — like expose_internal, and
	// for the same reason.
	AllowPrivateAddresses bool `toml:"allow_private_addresses"`
}

// adminSection is the operator allowlist. There is no role table: an account is
// an operator because a deployment names it here, never because it signed up.
type adminSection struct {
	// Subjects are account ids (`usr_…`) allowed to use /v1/admin.
	Subjects []string `toml:"subjects"`
	// ReauthWindow is how long an operator's login stays fresh enough for a
	// mutating admin call, as a Go duration string ("15m"). Empty takes the
	// default; "0" disables the check.
	ReauthWindow string `toml:"reauth_window"`
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
	// MaxInFlight bounds concurrent requests. Pointer for the same reason as
	// rate_limit: absent takes the default, explicit 0 disables the cap.
	MaxInFlight *int `toml:"max_in_flight"`
	// MaxUpstreamBufferBytes is the joint budget for upstream response bodies the
	// data plane may hold in memory at once, across every in-flight read. Absent
	// takes the default; there is no "unbounded" value, because unbounded is the
	// state that reaches the container's memory limit. Size it against the
	// container limit, not against traffic.
	MaxUpstreamBufferBytes *int `toml:"max_upstream_buffer_bytes"`
	// TrustedProxies are the networks whose X-Forwarded-For header is believed
	// when attributing a request to a client. Empty means none: the peer address
	// is the client. Set it only to your own reverse proxies' addresses.
	TrustedProxies []string `toml:"trusted_proxies"`
	// TrustedProxiesAny acknowledges a universal prefix in TrustedProxies. A
	// 0.0.0.0/0 or ::/0 entry trusts every peer, which makes the list a no-op (the
	// rightmost hop is always "inside" it) and hands the bucket key back to the
	// caller. The default refuses it; this is the one escape hatch, on the same
	// terms as expose_internal.
	//
	// Environment override: RE0AUTH_TRUSTED_PROXIES_ANY=true
	TrustedProxiesAny bool `toml:"trusted_proxies_any"`
	// ClientAddrHeader is the header the deployment's nearest reverse proxy writes
	// with the client address. "none" — the default — reads no header and uses the
	// peer address: the only safe answer when the proxy forwards the caller's own
	// X-Forwarded-For verbatim, and nothing in a request can prove which behaviour
	// the proxy has. "x-forwarded-for" asserts that the nearest proxy OVERWRITES
	// (`proxy_set_header X-Forwarded-For $remote_addr;`) or APPENDS to
	// (`$proxy_add_x_forwarded_for`) that header, and is what turns the rate limiter
	// from per-proxy into per-client. It requires a non-empty trusted_proxies and is
	// refused without one, because it could never take effect then.
	//
	// Environment override: RE0AUTH_CLIENT_ADDR_HEADER="x-forwarded-for"
	ClientAddrHeader string `toml:"client_addr_header"`
	// InternalAddr is where the operational surface is served: Prometheus metrics
	// and the Go runtime's profiling endpoints. Empty disables it entirely — the
	// default, because profiling endpoints belong on a private network and never
	// on the public one. Point it at a loopback or cluster-internal address.
	InternalAddr string `toml:"internal_addr"`
	// ExposeInternal acknowledges that InternalAddr is NOT loopback, so the
	// operational surface is reachable from beyond this host. Required for such
	// an address: a container has to bind 0.0.0.0 to be selected by a Service, so
	// the address cannot be refused outright — but /debug/pprof/ dumps heap and
	// goroutine state, and "the operator meant to write 127.0.0.1" must not be the
	// difference between a private and a public one.
	ExposeInternal bool `toml:"expose_internal"`
	// IntrospectionClients lists client ids allowed to introspect tokens issued
	// to other clients — resource servers. A client may always introspect its own
	// tokens; empty means nobody else's are visible.
	//
	// Every id must name a CONFIDENTIAL client. Introspection is authorized by
	// client authentication alone, and a public client keeps no secret to
	// authenticate with, so an entry naming one would make the endpoint readable
	// by anyone; such a caller is refused with 401 rather than trusted. The
	// variable is RE0AUTH_INTROSPECTION_CLIENTS (comma-separated).
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
	// AllowMissingPKCE exempts this client from the mandatory-PKCE rule, for a
	// client that cannot send a code_challenge (a certification suite, a legacy
	// RP). Default false: every other client still requires PKCE S256.
	AllowMissingPKCE bool `toml:"allow_missing_pkce"`
}

// isZero reports whether the section was left out of the file entirely, which is
// what lets a deployment that configures only [[clients]] entries avoid a stray
// default `[client]`.
func (c clientSection) isZero() bool {
	return c.ID == "" && c.Name == "" && c.SecretEnv == "" &&
		len(c.RedirectURIs) == 0 && len(c.Scopes) == 0 && !c.AllowMissingPKCE
}

// clientSpec is one resolved additional client: the [[clients]] entry with its
// secret already read from the environment. The primary [client] section keeps its
// own settings fields so a single-client deployment is unchanged.
type clientSpec struct {
	ID               string
	Name             string
	Secret           string
	RedirectURIs     []string
	Scopes           []string
	AllowMissingPKCE bool
}

type idpSection struct {
	ClientID        string `toml:"client_id"`
	ClientSecretEnv string `toml:"client_secret_env"`
	// Overrides for self-hosted or proxied endpoints.
	AuthURL     string `toml:"auth_url"`
	TokenURL    string `toml:"token_url"`
	UserInfoURL string `toml:"userinfo_url"`
	// JWKSURL names the key set that verifies id_tokens, for a provider whose
	// discovery document advertises a jwks_uri on another origin than its issuer.
	// Optional: when empty, the discovered jwks_uri must share the issuer's
	// origin. Setting it requires the discovered value to match exactly.
	JWKSURL string `toml:"jwks_uri"`
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
	// StorageDriver is the resolved driver: "postgres" or "memory". It is what the
	// startup log announces, so an operator can see which one won rather than
	// infer it from a warning.
	StorageDriver string
	// StorageReason explains why the in-memory driver was chosen, for the startup
	// warning. Empty when durable. It replaced a fixed because="no DATABASE_URL",
	// which was printed even when DATABASE_URL was set.
	StorageReason string
	KEK           []byte
	KEKID         string
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
	// MaxInFlight caps concurrent requests. Zero disables the cap.
	MaxInFlight int
	// MaxUpstreamBufferBytes is the joint budget, in bytes, for upstream response
	// bodies held in memory at once by the data plane. Always positive: a read
	// that does not fit is shed with 503 rather than allocated.
	MaxUpstreamBufferBytes int
	// AdminReauthWindow bounds how old an operator login may be for a mutating
	// admin call. Zero disables the check.
	AdminReauthWindow time.Duration
	// TrustedProxies are the networks whose X-Forwarded-For is believed when
	// resolving the client address. Empty means no proxy is trusted.
	TrustedProxies []netip.Prefix
	// ClientAddrHeader is which header names the client, if the deployment declared
	// one. ClientAddrPeer — the zero value — reads no header at all.
	ClientAddrHeader httpapi.ClientAddrHeader
	// AllowPrivateUpstreams permits outbound calls to loopback, link-local and
	// private addresses. False (the default) refuses them at dial time, so a
	// source registration or a discovery document cannot aim this process at an
	// internal service or the cloud metadata address.
	AllowPrivateUpstreams bool
	// InternalAddr is the address of the operational listener that serves metrics
	// and profiling. Empty means it is not served at all.
	InternalAddr string
	// ExposeInternal is the operator's acknowledgement that InternalAddr reaches
	// beyond this host. False refuses a non-loopback address at startup.
	ExposeInternal bool
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
	// clientAllowMissingPKCE is the operator's explicit exemption from mandatory
	// PKCE for this client. False unless `[client] allow_missing_pkce = true`.
	clientAllowMissingPKCE bool
	// extraClients are the resolved [[clients]] entries, in file order. Each goes
	// through the same validation, registration and drift refusal as [client].
	extraClients []clientSpec
	// noPrimaryClient is set when the file has no [client] section at all and
	// [[clients]] entries take its place: the default `cli` client is then NOT
	// seeded, because a registration nobody asked for is still a registration.
	noPrimaryClient bool

	idpCredentials []idp.Credentials
	// insecureIdPIssuers names the providers whose issuer is not https, in file
	// order. The startup path warns about each one: an http issuer puts the
	// authorization redirect, discovery, JWKS fetch and the token exchange — which
	// carries the client secret and the authorization code — on the wire in
	// cleartext. It is recorded rather than refused because a local/plaintext OIDC
	// provider is a legitimate deployment shape, and there is no acknowledgement
	// switch for it yet (S08-9).
	insecureIdPIssuers []string
	sources            []federation.Source
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
	// defaultMaxInFlightMemory is the cap when there is no connection pool to size
	// it against: high enough not to shape ordinary traffic, low enough that a
	// burst of slow requests cannot exhaust memory before the limiter reacts.
	defaultMaxInFlightMemory = 512
	// In a durable deployment the cap is derived from the pool instead, because
	// that is where concurrency actually queues: requests beyond the pool wait on
	// pgx for a connection, and the only bound there is the client hanging up. 8×
	// leaves room for the requests that never reach the database, and the floor
	// keeps a small pool from shaping ordinary traffic.
	maxInFlightPerConn = 8
	minMaxInFlight     = 64

	// defaultMaxUpstreamBufferBytes is the joint budget for upstream response
	// bodies held in memory at once, in bytes. 64 MiB is a quarter of the 512Mi
	// memory limit in deploy/k8s/base/deployment.yaml, and it is the number that
	// actually bounds the data plane: a request cap cannot, because the two data
	// plane paths may hold up to 4 MiB each (federation.maxBody) while every other
	// endpoint holds a few hundred bytes. Sixteen worst-case reads fit; a body that
	// declares a small Content-Length reserves only its own size, so ordinary
	// traffic is not shaped by it at all.
	defaultMaxUpstreamBufferBytes = 64 << 20

	// defaultAdminReauthWindow is how long an operator login stays fresh enough
	// for a mutating admin call. Long enough not to re-login mid-incident, short
	// enough that a stolen session does not keep operator power for a working day.
	defaultAdminReauthWindow = 15 * time.Minute
)

// defaultMaxInFlightFor returns the concurrency cap a deployment gets when it has
// not chosen one.
//
// It is a function of the pool rather than a constant because the number's job is
// to bound work in progress, and in a durable deployment work in progress means
// requests waiting on the database. A cap set far above the pool does not bound
// anything: it converts a fast refusal into a slow wait for a connection the
// process does not have. An in-memory deployment has no pool, so it keeps the flat
// default.
func defaultMaxInFlightFor(durable bool, maxConns int32) int {
	if !durable {
		return defaultMaxInFlightMemory
	}
	inFlight := int(maxConns) * maxInFlightPerConn
	if inFlight < minMaxInFlight {
		inFlight = minMaxInFlight
	}
	return inFlight
}

// configSecretEnvNames lists the environment variables a config file declares as
// secret holders, one `role=NAME` line per declaration, sorted.
//
// It decodes the same schema loadConfig does but resolves nothing — deliberately.
// loadConfig fails when a secret's value is missing, and "which variables does this
// file need" is asked precisely while a deployment is still being assembled, or
// while a backup target is being rebuilt.
//
// The left-hand side of each line is where the name is declared, so the output is
// readable on its own and a script can pick out a specific role (backup-keys.sh
// does, for a renamed vault.kek_env). What it answers is the part nothing else can
// know: a config may rename the KEK's variable, declare idp and source client
// secrets, and list the retired KEKs of a rotation in flight — none of which are in
// the environment under a name anyone can guess.
func configSecretEnvNames(path string) ([]string, error) {
	var f file
	if err := config.Read(path, &f); err != nil {
		return nil, err
	}
	var lines []string
	// The declaration is printed verbatim, so it must be shaped like a NAME. The
	// mistake this schema invites is pasting the secret into the *_env slot
	// instead of the variable's name; before this check that mistake was printed
	// to stdout — and scripts/backup-keys.sh put it in a shell variable and the CI
	// transcript (S08-6 / Z19V-2). The refusal names the field (the position an
	// operator needs) and never repeats the offending value: a value that happens
	// to be alphanumeric still matches the shape, which is exactly why the check
	// is on shape and the error is on position.
	add := func(role, name string) error {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil
		}
		if !isEnvVarName(name) {
			return fmt.Errorf(
				"%s is not an environment variable name: that slot names the variable holding the "+
					"secret, not the secret itself (the value is not printed here)", role)
		}
		lines = append(lines, role+"="+name)
		return nil
	}
	if err := add("vault.kek_env", f.Vault.KEKEnv); err != nil {
		return nil, err
	}
	for i, retired := range f.Vault.Retired {
		if err := add(fmt.Sprintf("vault.retired[%d].kek_env", i), retired.KEKEnv); err != nil {
			return nil, err
		}
	}
	// Map iteration is randomised, so the provider names are sorted before use: an
	// output whose order changes run to run is not diffable.
	providers := make([]string, 0, len(f.IdP))
	for name := range f.IdP {
		providers = append(providers, name)
	}
	sort.Strings(providers)
	for _, name := range providers {
		if err := add("idp."+name+".client_secret_env", f.IdP[name].ClientSecretEnv); err != nil {
			return nil, err
		}
	}
	for i, source := range f.Sources {
		if err := add(fmt.Sprintf("sources[%d].client_secret_env", i), source.ClientSecretEnv); err != nil {
			return nil, err
		}
	}
	sort.Strings(lines)
	return lines, nil
}

// isEnvVarName reports whether s is shaped like the name of an environment
// variable rather than a value pasted into a name slot: a leading letter or
// underscore, then letters, digits or underscores. It deliberately accepts an
// all-alphanumeric string, because a secret can look like one; what it rejects is
// the base64/hex/DSN shapes the mistake actually produces.
func isEnvVarName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return s != ""
}

// resolveClientSpec turns one [[clients]] entry into the shape the registry is
// seeded from, reading its secret from the named environment variable. A secret is
// named in the file, never written there, exactly as for [client].
//
// An entry must name an id and at least one redirect URI: guessing a redirect for
// a client the operator listed explicitly is how a client ends up allowlisted on
// an origin nobody intended. Name and scopes keep [client]'s defaults.
func resolveClientSpec(index int, entry clientSection) (clientSpec, error) {
	id := strings.TrimSpace(entry.ID)
	if id == "" {
		return clientSpec{}, fmt.Errorf("clients[%d]: id is required", index)
	}
	if len(entry.RedirectURIs) == 0 {
		return clientSpec{}, fmt.Errorf("clients[%d] (%s): redirect_uris is required "+
			"(no default redirect is guessed for a client that was listed explicitly)", index, id)
	}
	spec := clientSpec{
		ID:               id,
		Name:             strings.TrimSpace(entry.Name),
		RedirectURIs:     entry.RedirectURIs,
		Scopes:           entry.Scopes,
		AllowMissingPKCE: entry.AllowMissingPKCE,
	}
	if spec.Name == "" {
		spec.Name = id
	}
	if len(spec.Scopes) == 0 {
		spec.Scopes = []string{"account.id"}
	}
	if entry.SecretEnv != "" {
		value, err := config.Secret(entry.SecretEnv, fmt.Sprintf("clients[%d].secret_env", index))
		if err != nil {
			return clientSpec{}, err
		}
		spec.Secret = value
	}
	return spec, nil
}

// resolveStorage resolves the storage driver and the DSN onto cfg. It is shared by
// loadConfig and loadMigrateConfig so the two cannot disagree about which variable
// holds the DSN or about when "declared but unset" is an error.
//
// The DSN's environment variable: a file that names one (`dsn_env`) is
// authoritative — the literal DATABASE_URL is only the default NAME, so a stale
// DATABASE_URL in the environment must not shadow the variable the operator
// declared. The value is read through config.Secret, so "declared but unset" is an
// error rather than a silent downgrade to memory (S08-2).
func resolveStorage(cfg *settings, f file) error {
	dsnEnv := f.Storage.DSNEnv
	if dsnEnv == "" {
		dsnEnv = "DATABASE_URL"
	}
	driver := config.FirstNonEmpty(strings.TrimSpace(os.Getenv("RE0AUTH_STORAGE_DRIVER")), f.Storage.Driver)
	switch driver {
	case "":
		if f.Storage.DSNEnv != "" || os.Getenv("DATABASE_URL") != "" {
			driver = "postgres"
		} else {
			driver = "memory"
			cfg.StorageReason = "no DATABASE_URL is configured"
		}
	case "memory":
		driver = "memory"
		cfg.StorageReason = "storage.driver is memory"
	case "postgres":
		// Resolved below, exactly like the inferred case.
	default:
		return fmt.Errorf("storage.driver %q must be \"memory\" or \"postgres\"", driver)
	}
	if driver == "postgres" {
		dsn, err := config.Secret(dsnEnv, "storage.dsn_env")
		if err != nil {
			return err
		}
		cfg.DatabaseURL = dsn
	} else {
		cfg.DatabaseURL = ""
	}
	cfg.StorageDriver = driver
	return nil
}

// loadMigrateConfig resolves only what a schema rollback needs: the DSN and the
// pool. -migrate-down is a recovery action, and it used to run the whole
// serving-period validation first: a deployment whose KEK or audit chain key was
// missing or being recovered could not roll back at all, for a reason that has
// nothing to do with the rollback (Z12-5).
//
// It still refuses every value it actually uses — an unknown driver, a DSN variable
// that is unset, an out-of-range pool size — through the same helpers loadConfig
// uses, so "the narrow loader" is narrower only in what it ignores.
func loadMigrateConfig(path string) (settings, error) {
	var f file
	if err := config.Read(path, &f); err != nil {
		return settings{}, err
	}
	var cfg settings
	if err := resolveStorage(&cfg, f); err != nil {
		return settings{}, err
	}
	pool, err := resolvePool(f.Storage)
	if err != nil {
		return settings{}, err
	}
	cfg.Pool = pool
	return cfg, nil
}

// loadConfig reads the TOML file at path (empty = environment only), applies the
// environment overrides, resolves every secret by name, and validates the
// result. It fails closed: a half-configured server never starts.
func loadConfig(path string) (settings, error) {
	var f file
	if err := config.Read(path, &f); err != nil {
		return settings{}, err
	}

	cookieSecure, err := config.Bool("RE0AUTH_COOKIE_SECURE", f.Server.CookieSecure)
	if err != nil {
		return settings{}, err
	}
	exposeInternal, err := config.Bool("RE0AUTH_INTERNAL_EXPOSE", f.Server.ExposeInternal)
	if err != nil {
		return settings{}, err
	}
	cfg := settings{
		Addr:           config.FirstNonEmpty(os.Getenv("RE0AUTH_ADDR"), f.Server.Addr, "127.0.0.1:8080"),
		Issuer:         strings.TrimRight(config.FirstNonEmpty(os.Getenv("RE0AUTH_ISSUER"), f.Server.Issuer), "/"),
		CookieSecure:   cookieSecure,
		KEKID:          config.FirstNonEmpty(f.Vault.KEKID, os.Getenv("RE0AUTH_KEK_ID"), "kek-1"),
		InternalAddr:   config.FirstNonEmpty(os.Getenv("RE0AUTH_INTERNAL_ADDR"), f.Server.InternalAddr),
		ExposeInternal: exposeInternal,
	}
	if cfg.Issuer == "" {
		return settings{}, errors.New("server.issuer is required (or RE0AUTH_ISSUER); e.g. https://re0auth.example")
	}
	if !strings.HasPrefix(cfg.Issuer, "http://") && !strings.HasPrefix(cfg.Issuer, "https://") {
		return settings{}, fmt.Errorf("server.issuer %q must be an absolute http(s) URL", cfg.Issuer)
	}
	// The session cookie's Secure flag has to agree with the issuer's scheme.
	//
	// This pair used to be documented rather than checked — the troubleshooting
	// guide described the symptom ("signed in, no session") — and a documented
	// foot-gun is one an operator walks into at the least convenient moment. The
	// https-without-Secure direction is the one worth refusing: it is the
	// production-shaped mistake, the cookie travels unprotected, and nothing else
	// in the process looks at both settings.
	//
	// The other direction (http issuer, Secure cookie) is NOT refused: browsers
	// send Secure cookies over plain http to localhost, so that is a working local
	// setup asking for the production cookie shape, not a misconfiguration.
	if strings.HasPrefix(cfg.Issuer, "https://") && !cfg.CookieSecure {
		return settings{}, errors.New(
			"server.cookie_secure must be true when server.issuer is https; " +
				"the session cookie would be sent without the Secure attribute")
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
	case math.IsNaN(cfg.RateLimit) || math.IsInf(cfg.RateLimit, 0):
		// NaN and ±Inf parse fine (`strconv.ParseFloat` accepts "nan"/"inf", and
		// lowercase `nan`/`inf` are legal TOML floats) and every comparison below
		// is false for them, so the value reached the limiter and admitted
		// everything. Refuse at load, naming the field and never the spelling
		// (Z12-6, docs/issues/P2-medium.md).
		return settings{}, errors.New(
			"server.rate_limit must be a finite number (use 0 to disable the limiter)")
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

	// The concurrency cap is resolved *after* the pool, because an unchosen cap is
	// derived from it — see defaultMaxInFlightFor. -1 is "not chosen": the parser
	// below rejects every other negative value, so it cannot collide with one.
	maxInFlight := -1
	if f.Server.MaxInFlight != nil {
		maxInFlight = *f.Server.MaxInFlight
	}
	maxInFlight, err = config.Int("RE0AUTH_MAX_IN_FLIGHT", maxInFlight)
	if err != nil {
		return settings{}, err
	}
	if maxInFlight < -1 {
		return settings{}, errors.New("server.max_in_flight cannot be negative (use 0 to disable the cap)")
	}

	// The data plane's buffer budget. -1 is "not chosen", like max_in_flight; every
	// other negative value is refused, and there is no value that means unbounded.
	bufferedBytes := -1
	if f.Server.MaxUpstreamBufferBytes != nil {
		bufferedBytes = *f.Server.MaxUpstreamBufferBytes
	}
	bufferedBytes, err = config.Int("RE0AUTH_MAX_UPSTREAM_BUFFER_BYTES", bufferedBytes)
	if err != nil {
		return settings{}, err
	}
	if bufferedBytes < -1 {
		return settings{}, errors.New(
			"server.max_upstream_buffer_bytes cannot be negative (there is no unbounded setting: " +
				"that is the state which reaches the container's memory limit)")
	}
	if bufferedBytes == 0 {
		// An explicit 0 is a chosen value — the field is a pointer precisely so
		// absent and zero differ — but federation.NewService reads 0 as "not
		// chosen" and replaces it with the 64 MiB default, so before this the
		// operator's number was neither applied nor refused (S08-8). Refuse it here,
		// like the negative branch: leaving the budget unset is how the default is
		// asked for.
		return settings{}, errors.New(
			"server.max_upstream_buffer_bytes must be at least 1 byte (there is no \"off\": the budget " +
				"is what bounds upstream bodies held in memory). Leave it unset to take the default")
	}
	if bufferedBytes == -1 {
		bufferedBytes = defaultMaxUpstreamBufferBytes
	}
	cfg.MaxUpstreamBufferBytes = bufferedBytes

	// Trusted proxies. The environment overrides the file, like every other
	// setting, and an explicitly empty value clears the file's list (config.List).
	// Absent means no proxy is trusted, which is the safe default: the peer
	// address is then the client, and a fabricated X-Forwarded-For is ignored.
	cfg.TrustedProxies, err = parseTrustedProxies(
		config.List("RE0AUTH_TRUSTED_PROXIES", f.Server.TrustedProxies))
	if err != nil {
		return settings{}, err
	}
	// A universal prefix (0.0.0.0/0, ::/0) does not widen the trust list, it
	// EMPTIES it: with every peer trusted, the rightmost entry is always inside
	// the list, so the service falls back to the peer address on every request and
	// the bucket key becomes caller-chosen again. It is the one value that turns
	// the setting into a no-op, and it needs the same explicit acknowledgement as
	// expose_internal and allow_private_addresses — a list that is wide by accident
	// is the failure this project refuses everywhere else.
	if hasUniversalPrefix(cfg.TrustedProxies) {
		ack, err := config.Bool("RE0AUTH_TRUSTED_PROXIES_ANY", f.Server.TrustedProxiesAny)
		if err != nil {
			return settings{}, err
		}
		if !ack {
			return settings{}, errors.New(
				"server.trusted_proxies contains a universal prefix (0.0.0.0/0 or ::/0), which trusts every " +
					"peer and makes the setting a no-op: the bucket key becomes caller-chosen again. Name the " +
					"actual proxy networks, or acknowledge it with server.trusted_proxies_any = true " +
					"(RE0AUTH_TRUSTED_PROXIES_ANY=true)")
		}
	}

	// Which header the nearest proxy writes, if any. The trust list alone is not a
	// statement that a header is trustworthy: a proxy that forwards the caller's own
	// X-Forwarded-For verbatim leaves every entry caller-written, and a parser cannot
	// tell that apart from a rewritten one. So the deployment says which header it
	// writes, and "none" is the default.
	headerValue := f.Server.ClientAddrHeader
	if raw := strings.TrimSpace(os.Getenv("RE0AUTH_CLIENT_ADDR_HEADER")); raw != "" {
		headerValue = raw
	}
	cfg.ClientAddrHeader, err = httpapi.ParseClientAddrHeader(headerValue)
	if err != nil {
		return settings{}, fmt.Errorf("server.client_addr_header %w", err)
	}
	if cfg.ClientAddrHeader != httpapi.ClientAddrPeer && len(cfg.TrustedProxies) == 0 {
		// Fail closed rather than accept a setting that can never take effect: with
		// no trusted proxy the header is never read, so the configuration would look
		// applied and silently do nothing — which is how a deployment ends up
		// believing it has per-client budgets when every client shares one.
		return settings{}, errors.New(
			"server.client_addr_header = \"x-forwarded-for\" requires server.trusted_proxies: " +
				"without a trusted proxy the header is never read, so the setting would look applied and do nothing")
	}

	// Outbound address policy. The environment overrides the file, like every
	// other setting, and the default is to refuse: this is the switch that turns
	// a configured endpoint into a route into the deployment's own network, so
	// turning it on is an acknowledgement rather than a default.
	if raw := strings.TrimSpace(os.Getenv("RE0AUTH_ALLOW_PRIVATE_UPSTREAMS")); raw != "" {
		allow, err := config.Bool("RE0AUTH_ALLOW_PRIVATE_UPSTREAMS", false)
		if err != nil {
			return settings{}, err
		}
		cfg.AllowPrivateUpstreams = allow
	} else {
		cfg.AllowPrivateUpstreams = f.Upstream.AllowPrivateAddresses
	}

	// The operational surface must not be the public one. They are separate
	// addresses precisely so profiling endpoints cannot be scraped through the
	// public listener; configuring them the same would defeat that.
	if cfg.InternalAddr != "" && cfg.InternalAddr == cfg.Addr {
		return settings{}, errors.New(
			"server.internal_addr must differ from server.addr: the operational surface is not the public one")
	}
	// Being a different address is not enough on its own. `internal_addr =
	// "0.0.0.0:9090"` is also "different", and it hands /metrics and
	// /debug/pprof/ — heap, goroutine dumps, CPU profiles — to anything that can
	// reach the host. A container has a real reason to want that binding (a
	// Kubernetes Service can only select a pod that listens on a pod IP), so it is
	// allowed, but only once the operator says so: the acknowledgement is the
	// place the NetworkPolicy or firewall that makes it safe gets recorded.
	if cfg.InternalAddr != "" && !internalAddrIsLocal(cfg.InternalAddr) && !cfg.ExposeInternal {
		return settings{}, fmt.Errorf(
			"server.internal_addr %q is reachable from beyond this host, and /metrics and /debug/pprof/ "+
				"are served on it (pprof dumps heap and goroutine state). Bind a loopback address, or "+
				"set server.expose_internal = true (RE0AUTH_INTERNAL_EXPOSE=true) once a network "+
				"control in front of it — a NetworkPolicy, a firewall, a private interface — is in place",
			cfg.InternalAddr)
	}

	// Introspection policy. The environment overrides the file, like every other
	// setting, and an explicitly empty value clears the file's list (config.List).
	// Empty is the safe default: a client sees only its own tokens.
	for _, raw := range config.List("RE0AUTH_INTROSPECTION_CLIENTS", f.Server.IntrospectionClients) {
		if id := strings.TrimSpace(raw); id != "" {
			cfg.IntrospectionClients = append(cfg.IntrospectionClients, id)
		}
	}

	// Storage. An explicit driver wins; a named DSN means postgres; and a
	// DATABASE_URL in the environment is itself a statement that the deployment
	// wants to be durable — a deployment that only sets the variable (the README
	// quickstart shape) must not silently run in memory.
	//
	// The reason is recorded on the settings so reportDurability can say WHY, rather
	// than the fixed because="no DATABASE_URL" it used to print even when the
	// variable was set.
	if err := resolveStorage(&cfg, f); err != nil {
		return settings{}, err
	}

	// The connection pool. Resolved even in memory mode, where nothing uses it, so
	// a typo is reported now rather than on the day a deployment grows a database.
	cfg.Pool, err = resolvePool(f.Storage)
	if err != nil {
		return settings{}, err
	}

	// The concurrency cap, now that both the pool and the driver are known: a
	// deployment that chose one gets it, and one that did not gets a number sized
	// to what it can actually serve concurrently.
	if maxInFlight < 0 {
		maxInFlight = defaultMaxInFlightFor(cfg.DatabaseURL != "", cfg.Pool.MaxConns)
	}
	cfg.MaxInFlight = maxInFlight

	// Vault: the KEK is required, and its length is checked here so a bad key
	// fails before anything else is wired.
	//
	// The file's `kek_env` NAMES the variable holding the key, and
	// docs/operations.md tells operators they may rename it and must not assume it
	// is called RE0AUTH_KEK. Reading the hardcoded name first made the rename a
	// silent no-op: the process came up on whatever RE0AUTH_KEK still held, logged
	// nothing, and every unwrap after the first write failed with "authentication
	// failed" — with the old key still in the environment, that is discovered only
	// when records stop being readable (S08-1). RE0AUTH_KEK is the default NAME,
	// used when the file names no other.
	kekName := strings.TrimSpace(f.Vault.KEKEnv)
	if kekName == "" {
		kekName = "RE0AUTH_KEK"
	}
	// The accident this refuses: the file was renamed, the orchestrator still
	// injects the old variable. Two different keys under two names is not a
	// preference to resolve quietly — the one that is read decides whether every
	// existing record stays readable.
	if kekName != "RE0AUTH_KEK" {
		if stale := os.Getenv("RE0AUTH_KEK"); stale != "" && stale != os.Getenv(kekName) {
			return settings{}, fmt.Errorf(
				"vault.kek_env names %q, but RE0AUTH_KEK is also set and holds a different key; "+
					"remove the stale variable, or point both at the same key, before starting", kekName)
		}
	}
	// The id that labels records has to come from the same declaration as the key.
	// Renaming the key means bumping kek_id in the same edit; an orchestrator still
	// injecting the old RE0AUTH_KEK_ID would otherwise label records written with
	// the NEW key as the OLD one — the mirror image of the stale-KEK accident
	// above, and just as unreadable once the environment is corrected (Z12V-1).
	if id := strings.TrimSpace(f.Vault.KEKID); id != "" {
		if stale := strings.TrimSpace(os.Getenv("RE0AUTH_KEK_ID")); stale != "" && stale != id {
			return settings{}, fmt.Errorf(
				"vault.kek_id is %q, but RE0AUTH_KEK_ID is also set and names %q; "+
					"the id must match the key material: remove the stale variable, or point both "+
					"at the same id, before starting", id, stale)
		}
	}
	kekValue, err := config.Secret(kekName, "vault.kek_env")
	if err != nil {
		if kekName == "RE0AUTH_KEK" {
			// Name both spellings: an operator with neither set needs the file key
			// and the variable, not the position alone.
			return settings{}, errors.New("the vault KEK is required: set RE0AUTH_KEK or vault.kek_env")
		}
		return settings{}, err
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
			// The id is free text from the file (or RE0AUTH_KEK_ID) and is not
			// repeated: a value pasted into the kek_id slot would be echoed the same
			// way an *_env name used to be (Z19-1). The field names the position.
			return settings{}, fmt.Errorf(
				"%s.kek_id is the current key's id; a retired key must be a different key", field)
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

	// Downstream clients. [client] is the primary one and keeps the environment
	// overrides; it may be omitted only when [[clients]] entries take its place, so
	// a deployment that configures its clients as an array never also gets the
	// default `cli` registration it did not ask for.
	clientEnvID := strings.TrimSpace(os.Getenv("RE0AUTH_CLIENT_ID"))
	cfg.noPrimaryClient = len(f.Clients) > 0 && f.Client.isZero() && clientEnvID == ""
	if !cfg.noPrimaryClient {
		cfg.clientID = config.FirstNonEmpty(clientEnvID, f.Client.ID, "cli")
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
		// The one exemption from mandatory PKCE, off unless the file (or the env)
		// turns it on. It is resolved here so an invalid env value is a startup error
		// rather than a silently ignored typo.
		allowMissingPKCE, err := config.Bool("RE0AUTH_CLIENT_ALLOW_MISSING_PKCE", f.Client.AllowMissingPKCE)
		if err != nil {
			return settings{}, err
		}
		cfg.clientAllowMissingPKCE = allowMissingPKCE
	}

	// Additional downstream clients, in file order. Client ids must be unique
	// across [client] and [[clients]]: two sections describing one client would make
	// the drift refusal ambiguous, and the registry can only hold one row.
	seenClientIDs := map[string]string{}
	if !cfg.noPrimaryClient {
		seenClientIDs[cfg.clientID] = "the [client] section"
	}
	for i, entry := range f.Clients {
		spec, err := resolveClientSpec(i, entry)
		if err != nil {
			return settings{}, err
		}
		if source, duplicate := seenClientIDs[spec.ID]; duplicate {
			return settings{}, fmt.Errorf("clients[%d] (%s): this client_id is already configured by %s",
				i, spec.ID, source)
		}
		seenClientIDs[spec.ID] = fmt.Sprintf("clients[%d]", i)
		cfg.extraClients = append(cfg.extraClients, spec)
	}

	// Operator plane. Off unless a deployment names at least one account: an admin
	// API is not something to expose by accident, and an empty allowlist that
	// still mounted the routes would be a door with no lock. An explicitly empty
	// RE0AUTH_ADMIN_SUBJECTS clears the file's list and unmounts the plane
	// (config.List; Z12-4).
	for _, s := range config.List("RE0AUTH_ADMIN_SUBJECTS", f.Admin.Subjects) {
		if s = strings.TrimSpace(s); s != "" {
			cfg.adminSubjects = append(cfg.adminSubjects, s)
		}
	}

	// Operator step-up window. It only matters when the operator plane is
	// mounted, but it is resolved unconditionally so a typo is reported rather
	// than discovered at the first suspend.
	reauthRaw := strings.TrimSpace(f.Admin.ReauthWindow)
	if env := strings.TrimSpace(os.Getenv("RE0AUTH_ADMIN_REAUTH_WINDOW")); env != "" {
		reauthRaw = env
	}
	cfg.AdminReauthWindow = defaultAdminReauthWindow
	if reauthRaw != "" {
		d, err := time.ParseDuration(reauthRaw)
		if err != nil {
			return settings{}, fmt.Errorf("admin.reauth_window %q is not a duration (e.g. 15m)", reauthRaw)
		}
		if d < 0 {
			return settings{}, errors.New("admin.reauth_window cannot be negative (use 0 to disable)")
		}
		cfg.AdminReauthWindow = d
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
		// Record a non-https issuer so the startup path can warn about it. The
		// authorization redirect, discovery, JWKS fetch and the token exchange —
		// which carries the client secret and the authorization code — all run over
		// whatever scheme the issuer names, and there is no acknowledgement switch
		// for it (unlike expose_internal). It is a warning rather than a refusal
		// because a local/plaintext provider is a legitimate shape; the point is
		// that it is never silent (S08-9).
		if issuer := strings.TrimSpace(section.Issuer); issuer != "" && !strings.HasPrefix(issuer, "https://") {
			cfg.insecureIdPIssuers = append(cfg.insecureIdPIssuers, name)
		}
		credential := idp.Credentials{
			Provider:    provider,
			ClientID:    section.ClientID,
			AuthURL:     section.AuthURL,
			TokenURL:    section.TokenURL,
			UserInfoURL: section.UserInfoURL,
			JWKSURL:     section.JWKSURL,
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
	// validation is the source of truth rather than a duplicate here. It also
	// NORMALIZES (an empty token_class becomes revocable, an empty status active),
	// so cfg.sources is rebuilt from it: keeping the pre-validation copies would
	// leave the composition root holding the un-normalized values the registry
	// already fixed.
	reg, err := federation.NewRegistry(cfg.sources...)
	if err != nil {
		return fmt.Errorf("sources: %w", err)
	}
	cfg.sources = reg.AllSources()
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

// internalAddrIsLocal reports whether the operational listener would be confined
// to this host.
//
// It is deliberately conservative: anything it cannot prove is loopback counts as
// reachable, because the two mistakes do not cost the same. Refusing a private
// address costs one configuration line; accepting a public one publishes heap
// profiles and goroutine dumps to whoever can reach the port.
//
// A hostname other than "localhost" is therefore not local. Resolving it here
// would answer with DNS what the bind answers with the interface table, and the
// two are allowed to disagree — between the check and the listen, or between this
// process and the resolver.
func internalAddrIsLocal(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Not host:port. Keep whatever is there as the host, so a bare "127.0.0.1"
		// or a bare ":9090" is still classified rather than waved through.
		host = addr
	}
	if host == "localhost" {
		return true
	}
	// Covers the empty host (":9090", every interface, which is not local), the
	// unspecified addresses (0.0.0.0, ::) and any routable one: IsLoopback is true
	// only for 127.0.0.0/8 and ::1.
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.IsLoopback()
}

// hasUniversalPrefix reports whether the parsed list covers every address of an
// address family.
//
// A single /0 is the direct spelling, but it is not the only one: two /1 halves
// (0.0.0.0/1 + 128.0.0.0/1, or ::/1 + 8000::/1) cover the same space, and so does
// any set whose union merges into a /0. The guard exists to force the
// trusted_proxies_any acknowledgement, so it has to answer the question about
// COVERAGE rather than about the length of one entry — otherwise a generated list
// that split the halves skips the acknowledgement the single /0 is refused for
// (S08-5).
func hasUniversalPrefix(prefixes []netip.Prefix) bool {
	work := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		work = append(work, p.Masked())
	}
	// Merge sibling halves until nothing more merges: 0/2 + 64/2 -> 0/1, and then
	// 0/1 + 128/1 -> 0/0. These lists are a handful of entries, so the quadratic
	// scan is not worth avoiding.
	for {
		merged := false
	outer:
		for i := 0; i < len(work); i++ {
			for j := i + 1; j < len(work); j++ {
				parent, ok := mergeSiblingPrefixes(work[i], work[j])
				if !ok {
					continue
				}
				work = append(work[:j], work[j+1:]...)
				work = append(work[:i], work[i+1:]...)
				work = append(work, parent)
				merged = true
				break outer
			}
		}
		if !merged {
			break
		}
	}
	for _, p := range work {
		if p.Bits() == 0 {
			return true
		}
	}
	return false
}

// mergeSiblingPrefixes combines two distinct prefixes of the same length that are
// the two halves of one parent prefix (they differ only in the last network bit).
func mergeSiblingPrefixes(a, b netip.Prefix) (netip.Prefix, bool) {
	if a.Bits() != b.Bits() || a.Bits() == 0 || a == b {
		return netip.Prefix{}, false
	}
	parent := netip.PrefixFrom(a.Addr(), a.Bits()-1).Masked()
	if netip.PrefixFrom(b.Addr(), b.Bits()-1).Masked().Addr() != parent.Addr() {
		return netip.Prefix{}, false
	}
	return parent, true
}

// parseTrustedProxies parses CIDR prefixes, and bare addresses as single-host
// prefixes. A malformed entry is an error rather than a skipped one: a typo that
// quietly trusted nobody — or, if it were handled differently, everybody — is
// exactly the kind of setting that looks applied and is not.
func parseTrustedProxies(values []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for i, raw := range values {
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
			// The entry is free text from the file and is not repeated: a pasted
			// secret is echoed the same way an *_env name used to be (Z19-1). The
			// index is the position an operator needs to find it.
			return nil, fmt.Errorf("server.trusted_proxies entry %d is not an IP address or CIDR", i)
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
		n, err := poolSize("storage.max_conns", *section.MaxConns)
		if err != nil {
			return poolSettings{}, err
		}
		out.MaxConns = n
	}
	if section.MinConns != nil {
		n, err := poolSize("storage.min_conns", *section.MinConns)
		if err != nil {
			return poolSettings{}, err
		}
		out.MinConns = n
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

// poolSize converts a pool size read from the TOML file — the decoder stores it
// in an int — to the int32 the driver takes. The bounds check is what makes the
// conversion provably lossless (G115): a value outside int32 is refused by name
// instead of being silently truncated, which is the same "say what is wrong, do
// not start" rule resolvePool applies to every other setting.
//
// This is the validation Z12-9 asks for at the config boundary.
// (Z16-2, docs/issues/P2-medium.md)
func poolSize(what string, n int) (int32, error) {
	if n > math.MaxInt32 || n < math.MinInt32 {
		return 0, fmt.Errorf("%s %d is out of range (max %d)", what, n, math.MaxInt32)
	}
	return int32(n), nil
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
		// Distinguish "not a number" from "a number that does not fit": the old
		// message called 4294967297 "not an integer" — it IS one, it is just out of
		// int32 range — which sent the operator looking for a typo instead of at
		// the magnitude or the field's type (Z12V-3).
		if errors.Is(err, strconv.ErrRange) {
			return 0, fmt.Errorf("%s %q is out of range for a 32-bit pool size (max %d)",
				name, raw, math.MaxInt32)
		}
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
