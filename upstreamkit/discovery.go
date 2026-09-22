// Package upstreamkit helps a game backend become a compliant Re0Auth data
// source with minimal effort.
//
// A compliant source is three things (see docs/upstream-protocol.md §3): an
// OAuth 2.0 authorization server, a normalized data API, and a self-describing
// discovery document. This package supplies the discovery/scope layer and a
// mountable HTTP server that wires an oauth.Service to the protocol's
// endpoints, leaving the game-specific parts to hooks.
package upstreamkit

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ProtocolVersion is the major version of the upstream protocol this kit
// implements.
const ProtocolVersion = 1

// AccountScope is the one scope every source must support: it yields the stable
// upstream account identifier used for binding.
const AccountScope = "account.read"

// TokenClass declares what kind of credential a source hands out, which is what
// lets Re0Auth describe a source honestly (docs/upstream-protocol.md §6).
type TokenClass string

const (
	// TokenRevocable: scoped, expiring, revocable. Re0Auth stores a refresh
	// token and can cascade revocation.
	TokenRevocable TokenClass = "revocable"
	// TokenLongLived: a master key that cannot be revoked per client. Re0Auth
	// stores it as a high-risk secret and says so.
	TokenLongLived TokenClass = "long_lived"
)

// Resource is one data collection a source declares.
type Resource struct {
	// Name is the resource identifier, e.g. "scores".
	Name string `json:"name"`
	// Schema is the canonical schema id, e.g. "re0auth.phigros.scores/1".
	Schema string `json:"schema"`
	// Scope is the canonical scope that grants access to it.
	Scope string `json:"scope"`
}

// RawSpec declares a source's native API, which Re0Auth may proxy verbatim to
// offer neutrality (docs/upstream-protocol.md §9).
type RawSpec struct {
	Base    string `json:"base"`
	OpenAPI string `json:"openapi,omitempty"`
}

// OAuthEndpoints are the source's OAuth 2.0 endpoints.
type OAuthEndpoints struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	// CascadeRevocationEndpoint ends the subject's whole upstream session, not
	// merely the token Re0Auth holds.
	//
	// It is a Re0Auth extension: RFC 7009 has no way to ask for this, and the
	// difference is the point. RFC 7009 forgets a token; this signs the person out
	// of the account that token came from — including the device in their hand.
	//
	// It is **omitted when the source cannot do it**, which is what lets Re0Auth
	// offer "sign out everywhere" only where it is real. Advertising it without
	// implementing it would be the same class of lie as advertising DPoP while
	// issuing plain bearer tokens.
	CascadeRevocationEndpoint string `json:"cascade_revocation_endpoint,omitempty"`
	JWKSURI                   string `json:"jwks_uri,omitempty"`
}

// Discovery is the /.well-known/re0auth-upstream document.
type Discovery struct {
	ProtocolVersion int            `json:"re0auth_upstream_version"`
	Game            string         `json:"game"`
	Source          string         `json:"source"`
	DisplayName     string         `json:"display_name"`
	OAuth           OAuthEndpoints `json:"oauth"`
	TokenClass      TokenClass     `json:"token_class"`
	ScopesSupported []string       `json:"scopes_supported"`
	Resources       []Resource     `json:"resources"`
	Raw             *RawSpec       `json:"raw,omitempty"`
	Contact         string         `json:"contact,omitempty"`
}

// Config describes a source. The kit fills in OAuth endpoints from Issuer.
type Config struct {
	Game        string
	Source      string
	DisplayName string
	// Issuer is the public base URL of the source, e.g.
	// "https://api.next-phi.example".
	Issuer     string
	TokenClass TokenClass
	Resources  []Resource
	Raw        *RawSpec
	Contact    string
}

// NewDiscovery validates cfg and builds the discovery document.
func NewDiscovery(cfg Config) (Discovery, error) {
	if strings.TrimSpace(cfg.Game) == "" {
		return Discovery{}, errors.New("upstreamkit: Game is required")
	}
	if strings.TrimSpace(cfg.Source) == "" {
		return Discovery{}, errors.New("upstreamkit: Source is required")
	}
	if strings.TrimSpace(cfg.DisplayName) == "" {
		return Discovery{}, errors.New("upstreamkit: DisplayName is required")
	}
	if cfg.TokenClass != TokenRevocable && cfg.TokenClass != TokenLongLived {
		return Discovery{}, fmt.Errorf("upstreamkit: invalid token_class %q", cfg.TokenClass)
	}
	issuer := strings.TrimRight(cfg.Issuer, "/")
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return Discovery{}, fmt.Errorf("upstreamkit: invalid Issuer %q", cfg.Issuer)
	}

	scopes := []string{AccountScope}
	seen := map[string]bool{AccountScope: true}
	for _, res := range cfg.Resources {
		switch {
		case strings.TrimSpace(res.Name) == "":
			return Discovery{}, errors.New("upstreamkit: resource name is required")
		case !strings.HasPrefix(res.Schema, "re0auth."):
			return Discovery{}, fmt.Errorf("upstreamkit: resource %s schema %q must start with \"re0auth.\"", res.Name, res.Schema)
		case !ValidCanonicalScope(res.Scope):
			return Discovery{}, fmt.Errorf("upstreamkit: resource %s has invalid canonical scope %q", res.Name, res.Scope)
		}
		if !seen[res.Scope] {
			seen[res.Scope] = true
			scopes = append(scopes, res.Scope)
		}
	}

	disc := Discovery{
		ProtocolVersion: ProtocolVersion,
		Game:            cfg.Game,
		Source:          cfg.Source,
		DisplayName:     cfg.DisplayName,
		TokenClass:      cfg.TokenClass,
		ScopesSupported: scopes,
		Resources:       append([]Resource(nil), cfg.Resources...),
		Raw:             cfg.Raw,
		Contact:         cfg.Contact,
		OAuth: OAuthEndpoints{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/oauth/authorize",
			TokenEndpoint:         issuer + "/oauth/token",
			RevocationEndpoint:    issuer + "/oauth/revoke",
		},
	}
	if err := disc.Validate(); err != nil {
		return Discovery{}, err
	}
	return disc, nil
}

// Validate checks a discovery document against the protocol.
func (d Discovery) Validate() error {
	if d.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("upstreamkit: unsupported protocol version %d", d.ProtocolVersion)
	}
	if d.Game == "" || d.Source == "" || d.DisplayName == "" {
		return errors.New("upstreamkit: game, source and display_name are required")
	}
	if d.TokenClass != TokenRevocable && d.TokenClass != TokenLongLived {
		return fmt.Errorf("upstreamkit: invalid token_class %q", d.TokenClass)
	}
	if d.OAuth.Issuer == "" || d.OAuth.AuthorizationEndpoint == "" || d.OAuth.TokenEndpoint == "" || d.OAuth.RevocationEndpoint == "" {
		return errors.New("upstreamkit: oauth endpoints are incomplete")
	}
	found := false
	for _, s := range d.ScopesSupported {
		if s == AccountScope {
			found = true
			break
		}
	}
	if !found {
		return errors.New("upstreamkit: scopes_supported must include " + AccountScope)
	}
	for _, res := range d.Resources {
		if res.Name == "" || !strings.HasPrefix(res.Schema, "re0auth.") {
			return fmt.Errorf("upstreamkit: invalid resource %+v", res)
		}
	}
	return nil
}

// ValidCanonicalScope reports whether s follows "<game>.<resource>.<action>"
// with action read/write, or is the account scope.
func ValidCanonicalScope(s string) bool {
	if s == AccountScope {
		return true
	}
	parts := strings.Split(s, ".")
	if len(parts) < 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if r != '_' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return false
			}
		}
	}
	action := parts[len(parts)-1]
	return action == "read" || action == "write"
}
