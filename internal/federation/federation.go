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
	"sort"
	"strings"
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
}

// NewRegistry builds a registry, rejecting incomplete or duplicate sources.
func NewRegistry(sources ...Source) (*Registry, error) {
	r := &Registry{byGame: make(map[string][]Source), byKey: make(map[string]Source)}
	for _, s := range sources {
		if s.Game == "" || s.Name == "" || s.Issuer == "" {
			return nil, errors.New("federation: source requires game, name and issuer")
		}
		k := sourceKey(s.Game, s.Name)
		if _, dup := r.byKey[k]; dup {
			return nil, fmt.Errorf("federation: duplicate source %s", k)
		}
		issuer := strings.TrimRight(s.Issuer, "/")
		if s.AuthorizationEndpoint == "" {
			s.AuthorizationEndpoint = issuer + "/oauth/authorize"
		}
		if s.TokenEndpoint == "" {
			s.TokenEndpoint = issuer + "/oauth/token"
		}
		s.Issuer = issuer
		if s.Status == "" {
			s.Status = StatusActive
		}
		s.RawBase = strings.TrimRight(s.RawBase, "/")
		r.byKey[k] = s
		r.byGame[s.Game] = append(r.byGame[s.Game], s)
	}
	return r, nil
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
