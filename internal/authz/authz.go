// Package authz holds pending authorization requests: the server-side handle
// between /oauth/authorize and the consent screen.
//
// The handle is what keeps every security decision on the server. The client's
// request parameters (redirect_uri, PKCE challenge, scopes, state) are captured
// once, validated by the authorization server, and never trusted from the
// browser again. Approving a handle issues the code through oauth.Authorize, so
// explicit-consent and scope rules are enforced exactly once, in one place.
//
// Browser binding (which session owns a handle) is not this package's concern;
// the HTTP layer keeps it in the session. See docs/account-model.md §7.
package authz

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/Re0Auth/r0semi/oauth"
)

var (
	// ErrNotFound reports an unknown handle.
	ErrNotFound = errors.New("authz: authorization request not found")
	// ErrExpired reports a handle past its lifetime.
	ErrExpired = errors.New("authz: authorization request expired")
	// ErrScopeNotRequested reports an approval of a scope that was never asked
	// for; approval can only narrow, never widen.
	ErrScopeNotRequested = errors.New("authz: approved scope was not requested")
)

// Request is a pending authorization. It contains no secret.
type Request struct {
	ID                  string
	ClientID            string
	ClientName          string
	RedirectURI         string
	Scopes              []oauth.Scope
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

// BeginInput is the browser's authorization request.
type BeginInput struct {
	ClientID            string
	RedirectURI         string
	Scopes              []oauth.Scope
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// Store persists pending requests.
type Store interface {
	Put(ctx context.Context, r Request) error
	Get(ctx context.Context, id string) (Request, error)
	Delete(ctx context.Context, id string) error
}

// Service is the authorization-interaction capability.
type Service interface {
	// Begin validates the request and creates a pending handle.
	Begin(ctx context.Context, in BeginInput) (Request, error)
	// Get returns a live pending request.
	Get(ctx context.Context, id string) (Request, error)
	// Approve issues an authorization code for the authenticated subject.
	// approved may only narrow the requested scope set; explicit must list the
	// critical scopes the user individually ticked.
	Approve(ctx context.Context, id, subject string, approved, explicit []oauth.Scope) (oauth.AuthorizationResponse, error)
	// Deny discards a request and returns it so the caller can redirect the
	// browser back with an error.
	Deny(ctx context.Context, id string) (Request, error)
}

type service struct {
	oauth oauth.Service
	store Store
	ttl   time.Duration
	now   func() time.Time
}

// Config configures the service.
type Config struct {
	// TTL is how long a pending handle stays valid. Defaults to 10 minutes.
	TTL time.Duration
	// Now supplies the current time; tests inject a fake clock.
	Now func() time.Time
}

// NewService wires the authorization-interaction service.
func NewService(oauthSvc oauth.Service, store Store, cfg Config) (Service, error) {
	if oauthSvc == nil {
		return nil, errors.New("authz: oauth.Service is required")
	}
	if store == nil {
		return nil, errors.New("authz: Store is required")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &service{oauth: oauthSvc, store: store, ttl: cfg.TTL, now: cfg.Now}, nil
}

func (s *service) Begin(ctx context.Context, in BeginInput) (Request, error) {
	details, err := s.oauth.DescribeAuthorization(ctx, oauth.AuthorizationRequest{
		ClientID:            in.ClientID,
		RedirectURI:         in.RedirectURI,
		Scopes:              in.Scopes,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
	})
	if err != nil {
		return Request{}, err
	}

	id, err := newID()
	if err != nil {
		return Request{}, err
	}
	now := s.now()
	req := Request{
		ID:                  id,
		ClientID:            details.Client.ID,
		ClientName:          details.Client.Name,
		RedirectURI:         in.RedirectURI,
		Scopes:              append([]oauth.Scope(nil), in.Scopes...),
		State:               in.State,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		CreatedAt:           now,
		ExpiresAt:           now.Add(s.ttl),
	}
	if err := s.store.Put(ctx, req); err != nil {
		return Request{}, err
	}
	return req, nil
}

func (s *service) Get(ctx context.Context, id string) (Request, error) {
	req, err := s.store.Get(ctx, id)
	if err != nil {
		return Request{}, err
	}
	if !s.now().Before(req.ExpiresAt) {
		_ = s.store.Delete(ctx, id)
		return Request{}, ErrExpired
	}
	return req, nil
}

func (s *service) Approve(ctx context.Context, id, subject string, approved, explicit []oauth.Scope) (oauth.AuthorizationResponse, error) {
	req, err := s.Get(ctx, id)
	if err != nil {
		return oauth.AuthorizationResponse{}, err
	}
	if len(approved) == 0 {
		approved = req.Scopes
	}
	for _, sc := range approved {
		if !contains(req.Scopes, sc) {
			return oauth.AuthorizationResponse{}, ErrScopeNotRequested
		}
	}
	for _, sc := range explicit {
		if !contains(approved, sc) {
			return oauth.AuthorizationResponse{}, ErrScopeNotRequested
		}
	}

	resp, err := s.oauth.Authorize(ctx, oauth.AuthorizationRequest{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Subject:             subject,
		Scopes:              approved,
		Explicit:            explicit,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	})
	if err != nil {
		return oauth.AuthorizationResponse{}, err
	}
	// Single use: a decided handle can never be replayed.
	_ = s.store.Delete(ctx, id)
	return resp, nil
}

func (s *service) Deny(ctx context.Context, id string) (Request, error) {
	req, err := s.Get(ctx, id)
	if err != nil {
		return Request{}, err
	}
	_ = s.store.Delete(ctx, id)
	return req, nil
}

func contains(scopes []oauth.Scope, want oauth.Scope) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("authz: random source failed")
	}
	return "arq_" + hex.EncodeToString(b), nil
}

// MemoryStore is a non-durable Store for development and tests.
type MemoryStore struct {
	mu       sync.Mutex
	requests map[string]Request
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{requests: make(map[string]Request)}
}

// Put implements Store.
func (m *MemoryStore) Put(_ context.Context, r Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.Scopes = append([]oauth.Scope(nil), r.Scopes...)
	m.requests[r.ID] = r
	return nil
}

// Get implements Store.
func (m *MemoryStore) Get(_ context.Context, id string) (Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.requests[id]
	if !ok {
		return Request{}, ErrNotFound
	}
	return r, nil
}

// Delete implements Store.
func (m *MemoryStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.requests, id)
	return nil
}

// InvalidID reports whether a handle is structurally implausible, letting the
// HTTP layer reject garbage before a store lookup.
func InvalidID(id string) bool {
	return !strings.HasPrefix(id, "arq_") || len(id) != len("arq_")+32
}
