// Package federation is Re0Auth's data plane: it maps a downstream request for
// a game resource onto a bound upstream source and returns that source's
// normalized payload.
//
// It is the counterpart of upstreamkit: the kit makes a backend a
// compliant source, this package consumes such sources. Sources are configured
// (for now) rather than discovered; see docs/upstream-protocol.md.
package federation

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
)

var (
	// ErrUnknownGame reports a game with no configured sources.
	ErrUnknownGame = errors.New("federation: unknown game")
	// ErrUnknownSource reports a source that is not configured.
	ErrUnknownSource = errors.New("federation: unknown source")
	// ErrUnknownResource reports a resource no source declares.
	ErrUnknownResource = errors.New("federation: unknown resource")
	// ErrNotBound reports that the user has not bound the chosen source.
	ErrNotBound = errors.New("federation: source is not bound")
	// ErrSourceRetired reports a source that has been taken out of service.
	ErrSourceRetired = errors.New("federation: source is retired")
	// ErrRawUnsupported reports a source without a raw API.
	ErrRawUnsupported = errors.New("federation: source has no raw API")
	// ErrRawPathEscapes reports a raw request whose path tries to climb out of
	// the source's base URL.
	ErrRawPathEscapes = errors.New("federation: raw path escapes the source base")
	// ErrResponseTooLarge reports an upstream body past the size this proxy will
	// pass through. It is an error rather than a truncated success: a short body
	// returned as a complete one is the response lying about itself.
	ErrResponseTooLarge = errors.New("federation: upstream response exceeds the size limit")
)

// SourceStatus is a source's lifecycle state (docs/upstream-protocol.md §10).
type SourceStatus string

const (
	// StatusActive is the normal, preferred state.
	StatusActive SourceStatus = "active"
	// StatusDegraded is usable but not preferred; it is only chosen when no
	// active source can serve the request.
	StatusDegraded SourceStatus = "degraded"
	// StatusRetired is out of service and never selected.
	StatusRetired SourceStatus = "retired"
)

func statusRank(s SourceStatus) int {
	switch s {
	case StatusActive, "":
		return 0
	case StatusDegraded:
		return 1
	default:
		return 2
	}
}

// Resource is one data collection a source provides.
type Resource struct {
	Name   string
	Schema string
	// Scope is the canonical scope that grants access to it.
	Scope string
}

// Source is a configured upstream data source.
type Source struct {
	Game        string
	Name        string
	DisplayName string
	// Issuer is the source base URL; resources live at {Issuer}/resources/{name}.
	Issuer     string
	TokenClass string
	Resources  []Resource
	// Status is the source's lifecycle state. Empty means active.
	Status SourceStatus
	// RawBase, when set, is the source's native API root; Re0Auth proxies it
	// verbatim under /v1/games/{game}/sources/{source}/raw/...
	RawBase string

	// ClientID / ClientSecret are Re0Auth's OAuth client registration with this
	// source, used by the binding flow.
	ClientID     string
	ClientSecret string
	// AuthorizationEndpoint / TokenEndpoint override the defaults derived from
	// Issuer (/oauth/authorize, /oauth/token).
	AuthorizationEndpoint string
	TokenEndpoint         string
	// RevocationEndpoint overrides the default {Issuer}/oauth/revoke. It is used
	// when a user unbinds, to tell the source to drop the token it issued.
	RevocationEndpoint string
	// CascadeRevocationEndpoint ends the subject's whole upstream session, not
	// merely the token Re0Auth holds. It overrides the default
	// {Issuer}/oauth/cascade_revocation.
	//
	// **Empty means the source cannot do it, and that is the default.** The
	// capability is opt-in because most sources cannot, and a default would make
	// Re0Auth offer a button that fails — the same lie as any other unbacked claim.
	// Like token_class, this is the operator's declaration: set it only if the
	// source's discovery document advertises cascade_revocation_endpoint.
	CascadeRevocationEndpoint string
}

// bindScopes are the scopes requested when binding: the account scope plus
// every resource scope, deduplicated.
func (s Source) bindScopes() []string {
	out := []string{"account.read"}
	seen := map[string]bool{"account.read": true}
	for _, r := range s.Resources {
		if r.Scope != "" && !seen[r.Scope] {
			seen[r.Scope] = true
			out = append(out, r.Scope)
		}
	}
	return out
}

// Resource returns the named resource.
func (s Source) Resource(name string) (Resource, bool) {
	for _, r := range s.Resources {
		if r.Name == name {
			return r, true
		}
	}
	return Resource{}, false
}

// Registry holds the configured sources.
type Registry struct {
	byGame map[string][]Source
	byKey  map[string]Source
	// sourcesCopied counts the Source values Sources has copied out. Like
	// MemoryBindingStore.rowsCopied it is diagnostic only: a probe reads it to show
	// that a caller walks the sources once instead of copying the whole game per
	// resource declaration (S05-4). Nothing in the read path depends on it.
	sourcesCopied atomic.Int64
}

// NewRegistry builds a registry, rejecting incomplete or duplicate sources.
func NewRegistry(sources ...Source) (*Registry, error) {
	r := &Registry{byGame: make(map[string][]Source), byKey: make(map[string]Source)}
	for _, s := range sources {
		if s.Game == "" || s.Name == "" || s.Issuer == "" {
			return nil, errors.New("federation: source requires game, name and issuer")
		}
		// The game and source names are operator input, but they end up in the
		// callback URL, the vault identity and the registry's own key, so they are
		// checked rather than trusted — the same rule, and the same reason, as
		// idp.validateProviderName (FO-04). See validateSourceName for why "." is
		// excluded alongside the URL metacharacters (G-18).
		if err := validateSourceName("game", s.Game); err != nil {
			return nil, fmt.Errorf("federation: source %s/%s: %w", s.Game, s.Name, err)
		}
		if err := validateSourceName("name", s.Name); err != nil {
			return nil, fmt.Errorf("federation: source %s/%s: %w", s.Game, s.Name, err)
		}
		// A resource's declared name is matched against the caller's path segment
		// and its scope is sent upstream verbatim; both are validated for the same
		// reason as the source name (FO-04).
		for _, res := range s.Resources {
			if res.Name != "" {
				if err := validateSourceName("resource name", res.Name); err != nil {
					return nil, fmt.Errorf("federation: source %s/%s: %w", s.Game, s.Name, err)
				}
			}
			if err := validateResourceScope(res.Name, res.Scope); err != nil {
				return nil, fmt.Errorf("federation: source %s/%s: %w", s.Game, s.Name, err)
			}
		}
		k := sourceKey(s.Game, s.Name)
		if _, dup := r.byKey[k]; dup {
			return nil, fmt.Errorf("federation: duplicate source %s", k)
		}
		// The issuer is the base of every URL this source's requests are built
		// from and of the browser redirect the bind flow sends, so it has to be an
		// absolute http(s) URL before anything joins to it (S05-6). A
		// scheme-relative "//evil.example" loads fine and makes /bind answer a 302
		// naming another host; a relative path fails far from the typo.
		if err := validateEndpointURL("issuer", s.Issuer); err != nil {
			return nil, fmt.Errorf("federation: source %s: %w", k, err)
		}
		issuer := strings.TrimRight(s.Issuer, "/")
		if s.AuthorizationEndpoint == "" {
			s.AuthorizationEndpoint = issuer + "/oauth/authorize"
		}
		if s.TokenEndpoint == "" {
			s.TokenEndpoint = issuer + "/oauth/token"
		}
		if s.RevocationEndpoint == "" {
			s.RevocationEndpoint = issuer + "/oauth/revoke"
		}
		s.Issuer = issuer
		// The overrides are used as whole request URLs (the token exchange, the
		// revocation POST, the cascade request) and as a browser redirect target,
		// so they carry the same requirement as the issuer, whether they were set
		// explicitly or derived from it above (S05-6).
		for _, ep := range []struct{ field, value string }{
			{"authorization_endpoint", s.AuthorizationEndpoint},
			{"token_endpoint", s.TokenEndpoint},
			{"revocation_endpoint", s.RevocationEndpoint},
			{"cascade_revocation_endpoint", s.CascadeRevocationEndpoint},
		} {
			if ep.value == "" {
				continue
			}
			if err := validateEndpointURL(ep.field, ep.value); err != nil {
				return nil, fmt.Errorf("federation: source %s: %w", k, err)
			}
		}
		// status shares token_class's shape and its failure mode: an unrecognised
		// spelling is an operator's attempt at "out of service" that the rest of
		// the package reads as "in service". Only the exact string "retired" is
		// excluded by candidates(), so a typo keeps the source selectable and
		// keeps it deciding another source's scope gate. Refuse it here, where
		// token_class is refused, so the composition root and the published
		// discovery document cannot disagree about the vocabulary.
		switch s.Status {
		case "":
			s.Status = StatusActive
		case StatusActive, StatusDegraded, StatusRetired:
		default:
			return nil, fmt.Errorf("federation: source %s: status %q must be %q, %q or %q",
				k, s.Status, StatusActive, StatusDegraded, StatusRetired)
		}
		// token_class is the operator's honest declaration of what the source can
		// do, and unbind.go reads it as "long_lived means cannot revoke per client,
		// everything else means it can". An empty value must therefore become the
		// safe default (revocable, the common case), and an unrecognised one must be
		// refused: a typo like "long_live" would otherwise be silently read as
		// revocable, and Re0Auth would report "revoked upstream" for a source that
		// never could. Validation lives here, at the registry, so the composition
		// root and the conformance suite cannot disagree about what is valid.
		switch s.TokenClass {
		case "":
			s.TokenClass = tokenClassRevocable
		case tokenClassRevocable, tokenClassLongLived:
		default:
			return nil, fmt.Errorf("federation: source %s: token_class %q must be %q or %q",
				k, s.TokenClass, tokenClassRevocable, tokenClassLongLived)
		}
		s.RawBase = strings.TrimRight(s.RawBase, "/")
		if s.RawBase != "" {
			if err := validateRawBase(s.RawBase); err != nil {
				return nil, fmt.Errorf("federation: source %s: %w", k, err)
			}
		}
		r.byKey[k] = s
		r.byGame[s.Game] = append(r.byGame[s.Game], s)
	}
	return r, nil
}

// validateEndpointURL checks an operator-supplied http(s) endpoint before any
// request URL or browser redirect is built from it.
//
// It is validateRawBase's rule for the values that are used whole rather than
// joined to a caller path: the issuer, the two OAuth endpoint overrides, and the
// two revocation overrides (S05-6). None has a legitimate relative form — the
// upstream protocol fixes them as absolute URLs — and a value that is not one
// either sends a request somewhere the operator did not write or hands the
// browser a Location it resolves against Re0Auth's own origin.
func validateEndpointURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s %q is not a URL: %w", field, raw, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%s %q must be an absolute http(s) URL", field, raw)
	}
	return nil
}

// validateRawBase checks a source's native API root before anything is ever joined
// to it.
//
// The join is `RawBase + "/" + path`, so a base that is not an absolute http(s)
// URL — or that carries its own query or fragment — silently changes what every
// raw request means. With `raw_base = "https://api.example/v1?x=1"` the caller's
// path and query are appended to the *query string*: the path guard is never
// consulted on the join it was written for, and the subject's upstream token is
// sent to whatever that string resolves to. With `//evil.example` the value loads
// fine and every call fails at request time, far from the typo.
//
// It is an operator's mistake rather than a remote attack, which is exactly why it
// has to be reported at startup: nothing downstream can tell "the operator meant
// this" from "the operator fat-fingered it".
func validateRawBase(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("raw_base %q is not a URL: %w", raw, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("raw_base %q must be an absolute http(s) URL", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf(
			"raw_base %q must not carry a query or fragment: the caller's path is appended to it", raw)
	}
	return nil
}

// maxSourceNameBytes bounds a game, source or resource name.
//
// The name is path-safe under validateSourceName's charset rule, but path-safe is
// not the same as bounded: the value is joined into the bind callback path, the
// vault provider identity and the registry's own key, echoed in the /v1/sources
// listing and stored per binding. Nothing legitimate approaches this length, and
// 128 bytes is the cap the rest of the tree already uses for operator- and
// caller-chosen identifiers — maxBoundHandleBytes (internal/auth) and
// maxRequestIDBytes (internal/httpapi) — so an over-long name is refused at
// startup rather than carried verbatim (22-2: a 4096-byte name was accepted).
const maxSourceNameBytes = 128

// validateSourceName checks a game or source name before it is joined into a URL
// path, a vault identity or the registry's key.
//
// Same rule, and the same reason, as idp.validateProviderName: these are operator
// values that end up in the bind callback URL
// ({base}/auth/upstream/{game}/{source}/callback) and in every stored identity, so
// they are checked rather than trusted (FO-04). A "/" or ".." changes the path the
// callback resolves to, "?"/"#" truncates it and appends the callback to nothing,
// a backslash is a separator to a Windows-hosted proxy, and whitespace or a
// control byte produces a URL neither the operator nor the source wrote.
//
// The "." exclusion is the second finding (G-18): BindingIdentity joins game and
// source with a bare "." to build the vault provider ("game.source"), and that
// separator cannot change — existing ciphertext is bound to it as AAD — so with a
// dot allowed in either half, ("a.b","c") and ("a","b.c") are two registry
// entries that share one credential row: binding one overwrites the other's token
// and unbinding either crypto-shreds the other. Refusing the separator inside the
// halves is what keeps the join injective. This is deliberately stricter than
// FO-04's suggested "[a-z0-9][a-z0-9._-]*": that charset would leave the collision
// open.
//
// The charset says what a name may contain; maxSourceNameBytes says how long it
// may be. Both are refused here, at startup, for the same reason.
func validateSourceName(field, value string) error {
	if len(value) > maxSourceNameBytes {
		return fmt.Errorf(
			"%s is %d bytes, over the %d-byte limit: the name is joined into a URL path, a vault identity and the registry key, so it is bounded rather than carried",
			field, len(value), maxSourceNameBytes)
	}
	for i, r := range value {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
		if i == 0 && (r == '-' || r == '_') {
			valid = false
		}
		if !valid {
			return fmt.Errorf(
				"%s %q must be lowercase letters, digits, '-' or '_' (no '.'), and start with a letter or digit",
				field, value)
		}
	}
	return nil
}

// validateResourceScope checks a declared resource scope before bindScopes hands
// it to oauth2 as one element of the scope list.
//
// golang.org/x/oauth2 joins that list with spaces, so whitespace INSIDE one
// declared scope becomes several scopes on the wire: with
// scope = "phigros.profile.read account.id" the source is asked for a scope the
// operator never declared and the consent screen never showed — the silent
// privilege expansion FO-04 is about. The bindScopes doc promises "the account
// scope plus every resource scope", and this is the only place that promise can
// be kept. An empty scope is allowed: it means "no scope for this resource" and
// bindScopes skips it.
func validateResourceScope(resource, scope string) error {
	for _, r := range scope {
		valid := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_'
		if !valid {
			return fmt.Errorf(
				"resource %s: scope %q must be letters, digits, '.', '-' or '_' only (whitespace would be sent as several scopes)",
				resource, scope)
		}
	}
	return nil
}

// AllSources returns every configured source, ordered by game then name.
//
// It exists so the account page can offer what could be connected. Without it, a
// page whose job is connecting sources could only show the ones already
// connected — a dead end for anyone who has none.
func (r *Registry) AllSources() []Source {
	games := make([]string, 0, len(r.byGame))
	for game := range r.byGame {
		games = append(games, game)
	}
	sort.Strings(games)

	out := make([]Source, 0, len(r.byKey))
	for _, game := range games {
		sources := append([]Source(nil), r.byGame[game]...)
		sort.Slice(sources, func(i, j int) bool { return sources[i].Name < sources[j].Name })
		out = append(out, sources...)
	}
	return out
}

// Get returns a source by game and name.
func (r *Registry) Get(game, name string) (Source, bool) {
	s, ok := r.byKey[sourceKey(game, name)]
	return s, ok
}

// Sources returns a game's sources, ordered by name.
func (r *Registry) Sources(game string) []Source {
	out := append([]Source(nil), r.byGame[game]...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	r.sourcesCopied.Add(int64(len(out)))
	return out
}

// Games returns the configured games, sorted.
func (r *Registry) Games() []string {
	out := make([]string, 0, len(r.byGame))
	for g := range r.byGame {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

func sourceKey(game, name string) string { return game + "/" + name }
