package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// ClientType distinguishes clients that can keep a secret from those that
// cannot (desktop, CLI, mobile, SPA).
type ClientType string

const (
	ClientPublic       ClientType = "public"
	ClientConfidential ClientType = "confidential"
)

// ErrClientNotFound reports an unknown client id.
var ErrClientNotFound = errors.New("oauth: client not found")

// ErrNoSecretToRotate reports a rotation asked of a client that has no secret to
// rotate: a public client authenticates with PKCE, not a shared secret.
var ErrNoSecretToRotate = errors.New("oauth: client has no secret to rotate")

// ClientStatus is the administrative lifecycle of a registered client.
//
// A suspended client is not "denied": it is reported as unknown by every
// protocol entrance, because a ClientRegistry.Get returns ErrClientNotFound for
// it. An operator's decision should not be distinguishable from a client id that
// never existed.
type ClientStatus string

const (
	ClientActive    ClientStatus = "active"
	ClientSuspended ClientStatus = "suspended"
)

// A Client is a registered downstream application. The secret is stored only as
// a SHA-256 hash.
type Client struct {
	ID            string
	Name          string
	Type          ClientType
	Status        ClientStatus
	CreatedAt     time.Time
	RedirectURIs  []string
	AllowedScopes []Scope
	// AllowMissingPKCE opts this client out of the mandatory-PKCE rule the
	// protocol plane enforces on every authorization code request. It exists for
	// clients that cannot send a code_challenge (a certification suite, a legacy
	// RP) and is set only by an explicit `[client] allow_missing_pkce = true`.
	//
	// The zero value is false, so every client built by NewClient, restored from
	// storage, or created through the admin API still requires PKCE; the exemption
	// cannot be reached by accident, by a missing field, or by a request
	// parameter.
	AllowMissingPKCE bool

	secretHash []byte
}

// WithAllowMissingPKCE returns a copy of c with the exemption set. It is the only
// way to grant the exemption, so the call sites are greppable: registration of
// the configured first-party client, and the tests that pin this behaviour.
func (c Client) WithAllowMissingPKCE(allow bool) Client {
	c.AllowMissingPKCE = allow
	return c
}

// NewClient validates and constructs a client. A confidential client must have
// a secret; a public client must not.
func NewClient(id, name string, typ ClientType, secret string, redirects []string, allowed []Scope) (Client, error) {
	if id == "" {
		return Client{}, errors.New("oauth: client id is required")
	}
	if typ != ClientPublic && typ != ClientConfidential {
		return Client{}, fmt.Errorf("oauth: invalid client type %q", typ)
	}
	if typ == ClientConfidential && secret == "" {
		return Client{}, errors.New("oauth: confidential client requires a secret")
	}
	if typ == ClientPublic && secret != "" {
		return Client{}, errors.New("oauth: public client must not have a secret")
	}
	if len(redirects) == 0 {
		return Client{}, errors.New("oauth: at least one redirect URI is required")
	}
	for _, r := range redirects {
		if err := validRedirectURI(r); err != nil {
			return Client{}, fmt.Errorf("oauth: invalid redirect URI %q: %w", r, err)
		}
	}

	c := Client{
		ID:            id,
		Name:          name,
		Type:          typ,
		Status:        ClientActive,
		CreatedAt:     time.Now().UTC(),
		RedirectURIs:  append([]string(nil), redirects...),
		AllowedScopes: append([]Scope(nil), allowed...),
	}
	if secret != "" {
		c.secretHash = NewSecretHash(secret)
	}
	return c, nil
}

// NewSecretHash returns the stored digest of a client secret. Registration and
// rotation use it to turn a freshly generated secret into the form a registry
// persists; Authenticate is its counterpart.
func NewSecretHash(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// Authenticate checks a client secret in constant time.
func (c Client) Authenticate(secret string) bool {
	if len(c.secretHash) == 0 {
		return false
	}
	sum := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare(c.secretHash, sum[:]) == 1
}

// SecretHash returns the stored digest of the client secret, for persistence.
// It is empty for a public client. A registry persists this, never the
// plaintext secret.
func (c Client) SecretHash() []byte { return append([]byte(nil), c.secretHash...) }

// RestoreClient rebuilds a client from persisted fields. It is the inverse of
// NewClient plus SecretHash, and is what a persistent ClientRegistry uses;
// NewClient is for registration, where the plaintext secret is still known.
func RestoreClient(id, name string, typ ClientType, secretHash []byte, redirects []string, allowed []Scope, createdAt time.Time) (Client, error) {
	return RestoreClientWithStatus(id, name, typ, ClientActive, secretHash, redirects, allowed, createdAt)
}

// RestoreClientWithStatus is RestoreClient plus the persisted lifecycle status,
// for a registry that stores it.
//
// The PKCE exemption is deliberately NOT a parameter here: a store that persists
// it applies WithAllowMissingPKCE to the result after restoring, so a storage
// layer that never learned the field cannot silently grant the exemption.
func RestoreClientWithStatus(id, name string, typ ClientType, status ClientStatus, secretHash []byte, redirects []string, allowed []Scope, createdAt time.Time) (Client, error) {
	if status != ClientActive && status != ClientSuspended {
		return Client{}, fmt.Errorf("oauth: invalid client status %q", status)
	}
	switch {
	case id == "":
		return Client{}, errors.New("oauth: client id is required")
	case typ != ClientPublic && typ != ClientConfidential:
		return Client{}, fmt.Errorf("oauth: invalid client type %q", typ)
	case typ == ClientConfidential && len(secretHash) != sha256.Size:
		return Client{}, errors.New("oauth: confidential client requires a secret hash")
	case typ == ClientPublic && len(secretHash) != 0:
		return Client{}, errors.New("oauth: public client must not have a secret hash")
	case len(redirects) == 0:
		return Client{}, errors.New("oauth: at least one redirect URI is required")
	}
	return Client{
		ID:            id,
		Name:          name,
		Type:          typ,
		Status:        status,
		CreatedAt:     createdAt,
		RedirectURIs:  append([]string(nil), redirects...),
		AllowedScopes: append([]Scope(nil), allowed...),
		secretHash:    append([]byte(nil), secretHash...),
	}, nil
}

// AllowsRedirect reports whether uri is an exact registered redirect URI.
func (c Client) AllowsRedirect(uri string) bool {
	return c.RegisteredRedirect(uri) != ""
}

// RegisteredRedirect returns the registered redirect URI that equals uri, or ""
// when the client has none. It is AllowsRedirect plus the value, for the callers
// that then redirect: what a redirect target is built from must be the URI the
// client registered, not the string the request carried. The two are equal — that
// is what the check means — but only one of them is a value this server chose, and
// a reader (or a taint analyser, gosecurity:S5146) cannot tell an echoed request
// value from an attacker-chosen destination by looking at the variable alone.
func (c Client) RegisteredRedirect(uri string) string {
	for _, r := range c.RedirectURIs {
		if r == uri {
			return r
		}
	}
	return ""
}

// forbiddenRedirectSchemes are schemes a redirect must never target. Each one
// either carries a document a browser interprets (javascript:, data:, vbscript:)
// or addresses the local machine rather than a client (file:, blob:, about:).
var forbiddenRedirectSchemes = map[string]bool{
	"javascript": true,
	"data":       true,
	"vbscript":   true,
	"file":       true,
	"blob":       true,
	"about":      true,
}

// validRedirectURI validates a redirect URI at registration time.
//
// Registration is where this belongs, and it is deliberately *not* applied by
// RestoreClient: a URI already in the registry was accepted under whatever policy
// was in force when it was written, and refusing to load it would turn a
// tightened rule into a deployment that cannot start.
//
// The rules are RFC 6749 §3.1.2 (no fragment) plus RFC 8252: https anywhere, http
// only for a loopback host (§7.3 — a native client's local listener), and any
// reverse-DNS private-use scheme (§7.1 — com.example.app:/cb, how a desktop or
// mobile app receives a code). Everything else is refused. Without this the check
// was "does url.Parse find a scheme", which accepts http:// for a host nobody can
// protect and never rejects javascript:.
func validRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("it does not parse as a URL")
	}
	if u.Scheme == "" {
		return errors.New("it has no scheme")
	}
	if u.Fragment != "" {
		return errors.New("RFC 6749 §3.1.2 forbids a fragment")
	}
	if u.User != nil {
		return errors.New("it carries userinfo, which no client needs and a phisher does")
	}
	scheme := strings.ToLower(u.Scheme)
	if forbiddenRedirectSchemes[scheme] {
		return fmt.Errorf("the %s: scheme is never a redirect target", scheme)
	}
	switch scheme {
	case "https":
		if u.Host == "" {
			return errors.New("an https redirect URI needs a host")
		}
		return nil
	case "http":
		if !loopbackHost(strings.ToLower(u.Hostname())) {
			return errors.New("http is allowed only for a loopback host (RFC 8252 §7.3); use https")
		}
		return nil
	default:
		// A private-use URI scheme in reverse-DNS notation (RFC 8252 §7.1). The
		// dot is required: `app:` alone is what a device might already have
		// registered for something else.
		if !strings.Contains(scheme, ".") {
			return errors.New("a custom scheme must be in reverse-DNS notation (RFC 8252 §7.1), e.g. com.example.app")
		}
		if u.Opaque == "" && u.Path == "" && u.Host == "" {
			return errors.New("it names no target")
		}
		return nil
	}
}

// loopbackHost reports whether host is the local machine, the one place RFC 8252
// §7.3 allows a plain http redirect.
func loopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// AllowsScope reports whether the client was registered for the scope.
func (c Client) AllowsScope(s Scope) bool {
	for _, a := range c.AllowedScopes {
		if a == s {
			return true
		}
	}
	return false
}

// ClientRegistry stores registered clients.
type ClientRegistry interface {
	Create(ctx context.Context, c Client) error
	Get(ctx context.Context, id string) (Client, error)
}

// ClientNameLookup is implemented by a registry that can resolve many display
// names at once. It exists because the grants view asked for one client at a time
// from inside a loop over its rows: N round trips for a page whose whole content
// is N names.
//
// Callers type-assert rather than require it: a registry that does not implement
// it keeps working, one Get per id, which is what every caller did before.
type ClientNameLookup interface {
	ClientNames(ctx context.Context, ids []string) (map[string]string, error)
}

// LookupClientNames resolves display names for ids: in one call when the registry
// can, one id at a time when it cannot.
//
// Names are cosmetic, so nothing here is fatal. A bulk lookup that fails does not
// take the view down with it, and an id it did not answer is filled in
// individually — which is also the whole path for a registry without the bulk
// method. An id that resolves to nothing keeps an empty name, exactly as the
// per-id code left it.
func LookupClientNames(ctx context.Context, reg ClientRegistry, ids []string) map[string]string {
	out := make(map[string]string, len(ids))
	if reg == nil || len(ids) == 0 {
		return out
	}
	if bulk, ok := reg.(ClientNameLookup); ok {
		if names, err := bulk.ClientNames(ctx, ids); err == nil {
			for id, name := range names {
				out[id] = name
			}
		}
	}
	for _, id := range ids {
		if _, resolved := out[id]; resolved {
			continue
		}
		if c, err := reg.Get(ctx, id); err == nil {
			out[id] = c.Name
		}
	}
	return out
}

// ClientAdmin is the management side of a registry: the operations an operator
// uses to review and revoke clients. It is separate from ClientRegistry so the
// protocol plane depends only on what it needs to serve requests, and so a
// read-only or third-party registry remains a valid ClientRegistry.
type ClientAdmin interface {
	// List returns every client, suspended ones included, ordered by id.
	List(ctx context.Context) ([]Client, error)
	// SetStatus changes the lifecycle. An unknown id is ErrClientNotFound.
	SetStatus(ctx context.Context, id string, status ClientStatus) error
	// RotateSecret replaces a confidential client's secret digest. An unknown id
	// is ErrClientNotFound; a public client is ErrNoSecretToRotate, because it has
	// no secret and giving it one would break RestoreClient's validation.
	RotateSecret(ctx context.Context, id string, secretHash []byte) error
	// Delete removes the registration. Deleting an absent client is not an
	// error, which keeps an operator's retry idempotent.
	Delete(ctx context.Context, id string) error
}

// MemoryClientRegistry is a non-durable ClientRegistry for development and tests.
type MemoryClientRegistry struct {
	mu   sync.RWMutex
	byID map[string]Client
}

// NewMemoryClientRegistry returns an empty registry.
func NewMemoryClientRegistry() *MemoryClientRegistry {
	return &MemoryClientRegistry{byID: make(map[string]Client)}
}

// Create implements ClientRegistry.
func (r *MemoryClientRegistry) Create(_ context.Context, c Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byID[c.ID]; exists {
		return fmt.Errorf("oauth: client %s already exists", c.ID)
	}
	r.byID[c.ID] = c
	return nil
}

// Get implements ClientRegistry. A suspended client is reported as not found,
// so the protocol plane treats it exactly like an id that was never registered.
func (r *MemoryClientRegistry) Get(_ context.Context, id string) (Client, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.byID[id]
	if !ok || c.Status == ClientSuspended {
		return Client{}, ErrClientNotFound
	}
	return c, nil
}

// ClientNames implements ClientNameLookup: one read lock for the whole page.
//
// Unlike Get it does not hide a suspended client. What a name is asked for here
// is a view of tokens that were issued to somebody, and an operator suspending a
// client does not make the user's grant stop existing — the list would show an
// unnamed client for exactly the entry the user most needs to recognise and
// revoke.
func (r *MemoryClientRegistry) ClientNames(_ context.Context, ids []string) (map[string]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]string, len(ids))
	for _, id := range ids {
		if c, ok := r.byID[id]; ok {
			out[id] = c.Name
		}
	}
	return out, nil
}

// List implements ClientAdmin.
func (r *MemoryClientRegistry) List(_ context.Context) ([]Client, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Client, 0, len(r.byID))
	for _, c := range r.byID {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// SetStatus implements ClientAdmin.
func (r *MemoryClientRegistry) SetStatus(_ context.Context, id string, status ClientStatus) error {
	if status != ClientActive && status != ClientSuspended {
		return fmt.Errorf("oauth: invalid client status %q", status)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byID[id]
	if !ok {
		return ErrClientNotFound
	}
	c.Status = status
	r.byID[id] = c
	return nil
}

// RotateSecret implements ClientAdmin.
func (r *MemoryClientRegistry) RotateSecret(_ context.Context, id string, secretHash []byte) error {
	if len(secretHash) == 0 {
		return errors.New("oauth: a rotation needs a secret hash")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byID[id]
	if !ok {
		return ErrClientNotFound
	}
	if c.Type != ClientConfidential {
		return ErrNoSecretToRotate
	}
	c.secretHash = append([]byte(nil), secretHash...)
	r.byID[id] = c
	return nil
}

// Delete implements ClientAdmin.
func (r *MemoryClientRegistry) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byID, id)
	return nil
}
