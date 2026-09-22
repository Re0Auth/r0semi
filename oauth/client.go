package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"sort"
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
		Status:        ClientActive,
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
	return RestoreClientWithStatus(id, name, typ, ClientActive, secretHash, redirects, allowed, createdAt)
}

// RestoreClientWithStatus is RestoreClient plus the persisted lifecycle status,
// for a registry that stores it.
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

// ClientAdmin is the management side of a registry: the operations an operator
// uses to review and revoke clients. It is separate from ClientRegistry so the
// protocol plane depends only on what it needs to serve requests, and so a
// read-only or third-party registry remains a valid ClientRegistry.
type ClientAdmin interface {
	// List returns every client, suspended ones included, ordered by id.
	List(ctx context.Context) ([]Client, error)
	// SetStatus changes the lifecycle. An unknown id is ErrClientNotFound.
	SetStatus(ctx context.Context, id string, status ClientStatus) error
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

// Delete implements ClientAdmin.
func (r *MemoryClientRegistry) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byID, id)
	return nil
}
