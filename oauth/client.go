package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
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

// A Client is a registered downstream application. The secret is stored only as
// a SHA-256 hash.
type Client struct {
	ID            string
	Name          string
	Type          ClientType
	CreatedAt     time.Time
	RedirectURIs  []string
	AllowedScopes []Scope

	secretHash []byte
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
		u, err := url.Parse(r)
		if err != nil || u.Scheme == "" {
			return Client{}, fmt.Errorf("oauth: invalid redirect URI %q", r)
		}
	}

	c := Client{
		ID:            id,
		Name:          name,
		Type:          typ,
		CreatedAt:     time.Now().UTC(),
		RedirectURIs:  append([]string(nil), redirects...),
		AllowedScopes: append([]Scope(nil), allowed...),
	}
	if secret != "" {
		sum := sha256.Sum256([]byte(secret))
		c.secretHash = sum[:]
	}
	return c, nil
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
		CreatedAt:     createdAt,
		RedirectURIs:  append([]string(nil), redirects...),
		AllowedScopes: append([]Scope(nil), allowed...),
		secretHash:    append([]byte(nil), secretHash...),
	}, nil
}

// AllowsRedirect reports whether uri is an exact registered redirect URI.
func (c Client) AllowsRedirect(uri string) bool {
	for _, r := range c.RedirectURIs {
		if r == uri {
			return true
		}
	}
	return false
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

// Get implements ClientRegistry.
func (r *MemoryClientRegistry) Get(_ context.Context, id string) (Client, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.byID[id]
	if !ok {
		return Client{}, ErrClientNotFound
	}
	return c, nil
}
