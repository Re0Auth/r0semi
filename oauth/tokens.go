package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// ErrTokenNotFound reports a missing (or already consumed) code or token.
var ErrTokenNotFound = errors.New("oauth: token not found")

// AccessToken is a short-lived bearer token's record. It deliberately does NOT
// carry the token value: the store keys records by TokenHash(value), so a dump
// of the store yields no usable token.
type AccessToken struct {
	ClientID  string
	Subject   string
	Scopes    []Scope
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// RefreshToken is a long-lived token used to obtain new access tokens. It is
// rotated on every use.
type RefreshToken struct {
	ClientID  string
	Subject   string
	Scopes    []Scope
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// AuthorizationCode is a one-time code bound to a client, redirect URI and PKCE
// challenge.
type AuthorizationCode struct {
	ClientID            string
	Subject             string
	Scopes              []Scope
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

// Store persists authorization codes and token records.
//
// The opaque value (code or token) is passed alongside the record. It is used
// only as a lookup key and is never persisted: an implementation MUST key on
// TokenHash(value) and MUST NOT store the value itself. That way a leaked store
// is not a leaked credential.
//
// Expiry is enforced by the service, not the store, so a store stays a dumb map.
//
// ConsumeCode and ConsumeRefresh must be atomic: a code is single-use and a
// refresh token is single-use because it rotates.
//
// ListBySubject and DeleteBySubjectClient exist for the grants view, and they are
// what make "the tokens are the grant" true rather than merely stated: revoking a
// client is deleting its rows, so a revoked grant cannot survive in a table that
// the next request does not consult.
type Store interface {
	SaveCode(ctx context.Context, value string, c AuthorizationCode) error
	ConsumeCode(ctx context.Context, value string) (AuthorizationCode, error)

	SaveAccess(ctx context.Context, value string, t AccessToken) error
	GetAccess(ctx context.Context, value string) (AccessToken, error)
	DeleteAccess(ctx context.Context, value string) error

	SaveRefresh(ctx context.Context, value string, t RefreshToken) error
	ConsumeRefresh(ctx context.Context, value string) (RefreshToken, error)
	DeleteRefresh(ctx context.Context, value string) error

	// ListBySubject returns every token record for a subject, expired ones
	// included: the store has no clock, so the service decides what is still live.
	ListBySubject(ctx context.Context, subject string) ([]GrantRecord, error)
	// DeleteBySubjectClient removes every token one client holds for one subject.
	DeleteBySubjectClient(ctx context.Context, subject, clientID string) error

	// TokenOwner returns the client a presented token value was issued to, or
	// ErrTokenNotFound. The value may name an access token or a refresh token.
	//
	// It is a READ, not a consume, and it exists because RFC 7009 §2.1 requires
	// revocation to check that the token belongs to the client asking: deleting by
	// value alone let any registered client revoke another's tokens — and with
	// them the refresh chain — if it ever came by the value.
	TokenOwner(ctx context.Context, value string) (string, error)
}

// TokenFilter selects tokens for bulk revocation. An empty filter matches every
// token; when both fields are set they combine with AND.
type TokenFilter struct {
	ClientID string
	Subject  string
}

// Matches reports whether a token's owner is selected by the filter.
func (f TokenFilter) Matches(clientID, subject string) bool {
	return (f.ClientID == "" || f.ClientID == clientID) &&
		(f.Subject == "" || f.Subject == subject)
}

// TokenAdmin is the management side of a token store: bulk revocation, for an
// operator disabling a client, containing a compromised account, or throwing the
// Kill Switch. It is separate from Store so the request path depends only on the
// operations it actually performs.
type TokenAdmin interface {
	// RevokeTokens deletes every matching token and reports how many rows went
	// away. Removing zero is success: revocation is idempotent.
	RevokeTokens(ctx context.Context, f TokenFilter) (int, error)
}

// MemoryStore is a non-durable Store for development and tests.
type MemoryStore struct {
	mu      sync.Mutex
	codes   map[string]AuthorizationCode
	access  map[string]AccessToken
	refresh map[string]RefreshToken
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		codes:   make(map[string]AuthorizationCode),
		access:  make(map[string]AccessToken),
		refresh: make(map[string]RefreshToken),
	}
}

// SaveCode implements Store.
func (s *MemoryStore) SaveCode(_ context.Context, value string, c AuthorizationCode) error {
	s.mu.Lock()
	s.codes[TokenHash(value)] = c
	s.mu.Unlock()
	return nil
}

// ConsumeCode implements Store.
func (s *MemoryStore) ConsumeCode(_ context.Context, value string) (AuthorizationCode, error) {
	key := TokenHash(value)

	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[key]
	if !ok {
		return AuthorizationCode{}, ErrTokenNotFound
	}
	delete(s.codes, key)
	return c, nil
}

// SaveAccess implements Store.
func (s *MemoryStore) SaveAccess(_ context.Context, value string, t AccessToken) error {
	s.mu.Lock()
	s.access[TokenHash(value)] = t
	s.mu.Unlock()
	return nil
}

// GetAccess implements Store.
func (s *MemoryStore) GetAccess(_ context.Context, value string) (AccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.access[TokenHash(value)]
	if !ok {
		return AccessToken{}, ErrTokenNotFound
	}
	return t, nil
}

// DeleteAccess implements Store. Deleting an absent token is not an error, so
// revocation stays idempotent.
func (s *MemoryStore) DeleteAccess(_ context.Context, value string) error {
	s.mu.Lock()
	delete(s.access, TokenHash(value))
	s.mu.Unlock()
	return nil
}

// TokenOwner implements Store.
func (s *MemoryStore) TokenOwner(_ context.Context, value string) (string, error) {
	key := TokenHash(value)
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.access[key]; ok {
		return t.ClientID, nil
	}
	if t, ok := s.refresh[key]; ok {
		return t.ClientID, nil
	}
	return "", ErrTokenNotFound
}

// SaveRefresh implements Store.
func (s *MemoryStore) SaveRefresh(_ context.Context, value string, t RefreshToken) error {
	s.mu.Lock()
	s.refresh[TokenHash(value)] = t
	s.mu.Unlock()
	return nil
}

// ConsumeRefresh implements Store.
func (s *MemoryStore) ConsumeRefresh(_ context.Context, value string) (RefreshToken, error) {
	key := TokenHash(value)

	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refresh[key]
	if !ok {
		return RefreshToken{}, ErrTokenNotFound
	}
	delete(s.refresh, key)
	return t, nil
}

// DeleteRefresh implements Store.
func (s *MemoryStore) DeleteRefresh(_ context.Context, value string) error {
	s.mu.Lock()
	delete(s.refresh, TokenHash(value))
	s.mu.Unlock()
	return nil
}

// TokenHash is the at-rest form of an opaque token. Store implementations MUST
// key on it and MUST NOT persist the token itself.
//
// A plain SHA-256 is the right tool here, unlike for passwords: these tokens are
// 32 bytes from crypto/rand, so there is nothing to brute force and no need for
// a slow KDF. The store is a lookup table, not a verifier.
func TokenHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
