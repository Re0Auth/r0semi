// Package oauth implements the r0semi authorization server: the down-facing
// half of the broker. It issues scoped, short-lived access tokens to downstream
// clients so they never hold an upstream credential.
//
// Scope names are namespaced -- "<provider>.<resource>.<action>" -- and every
// scope carries a risk tier. A descriptor may additionally be ExplicitConsent,
// which forces the scope to be approved on its own (and optionally restricts it
// to an allowlist of clients).
//
// That mechanism is generic, and the built-in catalog currently marks nothing
// critical: **re0auth exports no upstream credential at all**, so there is no
// scope that could justify it. See docs/api-design.md §5.
package oauth

import (
	"fmt"
	"sort"
	"strings"
)

// Scope is a namespaced permission such as "phigros.score.read".
type Scope string

func (s Scope) String() string { return string(s) }

// Provider returns the first segment of the scope.
func (s Scope) Provider() string {
	if i := strings.IndexByte(string(s), '.'); i > 0 {
		return string(s)[:i]
	}
	return ""
}

func (s Scope) valid() bool {
	parts := strings.Split(string(s), ".")
	if len(parts) < 2 {
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
	return true
}

// MustScope panics on a malformed scope. It is for package-level constants.
func MustScope(s string) Scope {
	scope := Scope(s)
	if !scope.valid() {
		panic("oauth: malformed scope " + s)
	}
	return scope
}

// The MVP scope catalog. Provider packages will contribute their own
// descriptors as the catalog grows; see DefaultDescriptors.
var (
	ScopeAccountID      = MustScope("account.id")
	ScopeTapTapAccount  = MustScope("taptap.account.id")
	ScopePhigrosProfile = MustScope("phigros.profile.read")
	ScopePhigrosScore   = MustScope("phigros.score.read")
	ScopePhigrosB30     = MustScope("phigros.b30.read")
)

// Risk classifies the blast radius of granting a scope.
type Risk int

const (
	RiskLow Risk = iota
	RiskMedium
	RiskHigh
	RiskCritical
)

func (r Risk) String() string {
	switch r {
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	case RiskCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Descriptor describes one scope.
type Descriptor struct {
	Scope       Scope
	Title       string
	Description string
	Risk        Risk

	// ExplicitConsent requires the scope to be individually approved by the
	// user; it must never be bundled into a "select all".
	ExplicitConsent bool

	// AllowedClients, when non-empty, restricts the scope to those client ids
	// regardless of what a client was registered with.
	AllowedClients []string
}

func (d Descriptor) allowsClient(id string) bool {
	if len(d.AllowedClients) == 0 {
		return true
	}
	for _, c := range d.AllowedClients {
		if c == id {
			return true
		}
	}
	return false
}

// DefaultDescriptors returns the built-in MVP catalog.
//
// Nothing here is ExplicitConsent. The mechanism stays, because "the user
// approved this scope specifically" has to remain expressible and a source-side
// scope may need it later; the catalog simply has no such scope today. A
// previous version advertised `taptap.stoken.read` to export the raw TapTap
// session token; re0auth no longer holds that credential, so the scope was
// removed rather than left as an endpoint that could not be served.
func DefaultDescriptors() []Descriptor {
	return []Descriptor{
		{
			Scope: ScopeAccountID, Title: "账号 ID", Risk: RiskLow,
			Description: "读取你的 Re0Auth 账号标识（subject）。",
		},
		{
			Scope: ScopeTapTapAccount, Title: "TapTap 账号", Risk: RiskLow,
			Description: "读取你的 TapTap openid / unionid。",
		},
		{
			Scope: ScopePhigrosProfile, Title: "读取 Phigros 档案", Risk: RiskMedium,
			Description: "通过 Re0Auth 代理读取你的 Phigros 档案（rks 等）。",
		},
		{
			Scope: ScopePhigrosScore, Title: "读取 Phigros 成绩", Risk: RiskMedium,
			Description: "通过 Re0Auth 代理读取你的 Phigros 成绩。",
		},
		{
			Scope: ScopePhigrosB30, Title: "读取 Phigros B30", Risk: RiskMedium,
			Description: "通过 Re0Auth 代理读取你的 Phigros B30。",
		},
	}
}

// Registry resolves scopes to descriptors.
type Registry struct {
	byScope map[Scope]Descriptor
}

// NewRegistry builds a registry from descriptors, rejecting duplicates and
// malformed entries.
func NewRegistry(descriptors ...Descriptor) (*Registry, error) {
	r := &Registry{byScope: make(map[Scope]Descriptor, len(descriptors))}
	for _, d := range descriptors {
		if err := r.Register(d); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// DefaultRegistry is NewRegistry over DefaultDescriptors.
func DefaultRegistry() *Registry {
	r, err := NewRegistry(DefaultDescriptors()...)
	if err != nil {
		panic("oauth: default scope catalog: " + err.Error())
	}
	return r
}

// Register adds a descriptor. It is meant to be called by provider packages at
// composition time.
func (r *Registry) Register(d Descriptor) error {
	if !d.Scope.valid() {
		return fmt.Errorf("oauth: malformed scope %q", d.Scope)
	}
	if d.Title == "" {
		return fmt.Errorf("oauth: scope %s needs a title", d.Scope)
	}
	if _, exists := r.byScope[d.Scope]; exists {
		return fmt.Errorf("oauth: duplicate scope %s", d.Scope)
	}
	r.byScope[d.Scope] = d
	return nil
}

// Get returns the descriptor for a scope.
func (r *Registry) Get(s Scope) (Descriptor, bool) {
	d, ok := r.byScope[s]
	return d, ok
}

// Descriptors returns every descriptor, ordered by scope.
func (r *Registry) Descriptors() []Descriptor {
	out := make([]Descriptor, 0, len(r.byScope))
	for _, d := range r.byScope {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scope < out[j].Scope })
	return out
}

// Resolve validates a requested scope set: every scope must be known and, when
// the descriptor restricts clients, the requesting client must be allowed.
func (r *Registry) Resolve(scopes []Scope, clientID string) ([]Descriptor, error) {
	seen := make(map[Scope]struct{}, len(scopes))
	out := make([]Descriptor, 0, len(scopes))
	for _, s := range scopes {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}

		d, ok := r.byScope[s]
		if !ok {
			return nil, fmt.Errorf("oauth: unknown scope %q", s)
		}
		if !d.allowsClient(clientID) {
			return nil, fmt.Errorf("oauth: scope %s is not available to client %s", s, clientID)
		}
		out = append(out, d)
	}
	return out, nil
}
