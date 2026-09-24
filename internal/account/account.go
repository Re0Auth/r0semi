// Package account stores r0semi accounts and their linked external identities.
//
// It is the only place that assigns a usr_ id, and it enforces the three
// identity invariants from docs/account-model.md §2:
//
//	I-1 equality   -- all linked identities are login-equivalent; primary is a
//	                  display-only pointer and grants nothing;
//	I-2 last identity -- a user always keeps at least one identity;
//	I-3 isolation  -- an identity already owned by another user is never linked.
//
// Credentials are not stored here; they live in the vault, keyed by (usr_,
// credential_source).
package account

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Re0Auth/r0semi/idp"
)

// UserID is a r0semi account identifier, e.g. "usr_1a2b...".
type UserID string

// IdentityID identifies one linked identity, e.g. "idn_1a2b...".
type IdentityID string

var (
	// ErrNotFound reports an unknown user or identity.
	ErrNotFound = errors.New("account: not found")
	// ErrIdentityTaken reports an identity already linked to another user (I-3).
	ErrIdentityTaken = errors.New("account: identity is already linked to another account")
	// ErrLastIdentity reports an attempt to unlink the last identity (I-2).
	ErrLastIdentity = errors.New("account: cannot unlink the last identity")
)

// User is a r0semi account.
type User struct {
	ID UserID
	// PrimaryIdentity is display-only: it nominates which identity to show as
	// the account's origin. It grants no privilege (I-1).
	PrimaryIdentity IdentityID
	CreatedAt       time.Time
}

// Identity is one external IdP identity linked to a user.
type Identity struct {
	ID          IdentityID
	User        UserID
	Provider    idp.Provider
	Subject     string
	DisplayName string
	Email       string
	AvatarURL   string
	LinkedAt    time.Time
	LastLoginAt time.Time
}

// Store persists users and identities.
type Store interface {
	// FindByIdentity returns the user owning (provider, subject), or ErrNotFound.
	FindByIdentity(ctx context.Context, provider idp.Provider, subject string) (UserID, error)

	// CreateWithIdentity creates a new user whose first identity is in. It fails
	// with ErrIdentityTaken if the identity already exists.
	CreateWithIdentity(ctx context.Context, in idp.Identity) (User, Identity, error)

	// LinkIdentity links an identity to an existing user. Re-linking an
	// identity already owned by the same user is idempotent; an identity owned
	// by another user fails with ErrIdentityTaken (I-3).
	LinkIdentity(ctx context.Context, user UserID, in idp.Identity) (Identity, error)

	// UnlinkIdentity removes an identity, failing with ErrLastIdentity when it
	// is the user's last one (I-2). If it was the primary, the primary is
	// reassigned to the earliest remaining identity.
	UnlinkIdentity(ctx context.Context, user UserID, identity IdentityID) error

	// Identities returns a user's identities, oldest first.
	Identities(ctx context.Context, user UserID) ([]Identity, error)

	// GetUser returns a user.
	GetUser(ctx context.Context, user UserID) (User, error)

	// DeleteUser removes a user and every identity it holds.
	//
	// It is the account row's own deletion and nothing more: the tokens, sessions,
	// bindings and credentials that hang off the account live in tables this store
	// does not own, and deleting the user here does not cascade to them. Callers
	// must clear those first; internal/lifecycle does exactly that. Deleting an
	// absent user is not an error, so a retried erasure stays idempotent.
	DeleteUser(ctx context.Context, user UserID) error

	// TouchLogin records that an identity has just authenticated.
	TouchLogin(ctx context.Context, provider idp.Provider, subject string) error
}

type identityKey struct {
	provider idp.Provider
	subject  string
}

// MemoryStore is a non-durable Store for development and tests. It is safe for
// concurrent use.
type MemoryStore struct {
	mu         sync.RWMutex
	users      map[UserID]User
	identities map[IdentityID]Identity
	byKey      map[identityKey]IdentityID
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users:      make(map[UserID]User),
		identities: make(map[IdentityID]Identity),
		byKey:      make(map[identityKey]IdentityID),
	}
}

// FindByIdentity implements Store.
func (s *MemoryStore) FindByIdentity(_ context.Context, provider idp.Provider, subject string) (UserID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byKey[identityKey{provider, subject}]
	if !ok {
		return "", ErrNotFound
	}
	return s.identities[id].User, nil
}

// CreateWithIdentity implements Store.
func (s *MemoryStore) CreateWithIdentity(_ context.Context, in idp.Identity) (User, Identity, error) {
	if err := in.Validate(); err != nil {
		return User{}, Identity{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := identityKey{in.Provider, in.Subject}
	if _, exists := s.byKey[key]; exists {
		return User{}, Identity{}, ErrIdentityTaken
	}

	now := time.Now().UTC()
	user := User{ID: NewUserID(), CreatedAt: now}
	ident := Identity{
		ID: NewIdentityID(), User: user.ID,
		Provider: in.Provider, Subject: in.Subject,
		DisplayName: in.DisplayName, Email: in.Email, AvatarURL: in.AvatarURL,
		LinkedAt: now, LastLoginAt: now,
	}
	user.PrimaryIdentity = ident.ID

	s.users[user.ID] = user
	s.identities[ident.ID] = ident
	s.byKey[key] = ident.ID
	return user, ident, nil
}

// LinkIdentity implements Store.
func (s *MemoryStore) LinkIdentity(_ context.Context, user UserID, in idp.Identity) (Identity, error) {
	if err := in.Validate(); err != nil {
		return Identity{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[user]; !ok {
		return Identity{}, ErrNotFound
	}

	key := identityKey{in.Provider, in.Subject}
	if existingID, exists := s.byKey[key]; exists {
		existing := s.identities[existingID]
		if existing.User == user {
			return existing, nil // idempotent
		}
		return Identity{}, ErrIdentityTaken // I-3
	}

	ident := Identity{
		ID: NewIdentityID(), User: user,
		Provider: in.Provider, Subject: in.Subject,
		DisplayName: in.DisplayName, Email: in.Email, AvatarURL: in.AvatarURL,
		LinkedAt: time.Now().UTC(),
	}
	s.identities[ident.ID] = ident
	s.byKey[key] = ident.ID
	return ident, nil
}

// UnlinkIdentity implements Store.
func (s *MemoryStore) UnlinkIdentity(_ context.Context, user UserID, identity IdentityID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ident, ok := s.identities[identity]
	if !ok || ident.User != user {
		return ErrNotFound
	}

	remaining := s.identitiesOfLocked(user)
	if len(remaining) <= 1 {
		return ErrLastIdentity // I-2
	}

	delete(s.identities, identity)
	delete(s.byKey, identityKey{ident.Provider, ident.Subject})

	if u := s.users[user]; u.PrimaryIdentity == identity {
		// Reassign to the earliest remaining identity. Any surviving identity
		// is equally valid for login (I-1), so this is purely cosmetic.
		for _, r := range remaining {
			if r.ID != identity {
				u.PrimaryIdentity = r.ID
				break
			}
		}
		s.users[user] = u
	}
	return nil
}

// Identities implements Store.
func (s *MemoryStore) Identities(_ context.Context, user UserID) ([]Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.users[user]; !ok {
		return nil, ErrNotFound
	}
	return s.identitiesOfLocked(user), nil
}

// GetUser implements Store.
func (s *MemoryStore) GetUser(_ context.Context, user UserID) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[user]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

// TouchLogin implements Store.
func (s *MemoryStore) TouchLogin(_ context.Context, provider idp.Provider, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byKey[identityKey{provider, subject}]
	if !ok {
		return ErrNotFound
	}
	ident := s.identities[id]
	ident.LastLoginAt = time.Now().UTC()
	s.identities[id] = ident
	return nil
}

// DeleteUser implements Store. Both the identities and their (provider, subject)
// lookup keys go, so a later sign-in with the same external identity creates a
// fresh account rather than resurrecting the deleted one.
func (s *MemoryStore) DeleteUser(_ context.Context, user UserID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, user)
	for id, ident := range s.identities {
		if ident.User == user {
			delete(s.identities, id)
			delete(s.byKey, identityKey{ident.Provider, ident.Subject})
		}
	}
	return nil
}

func (s *MemoryStore) identitiesOfLocked(user UserID) []Identity {
	out := make([]Identity, 0, 4)
	for _, ident := range s.identities {
		if ident.User == user {
			out = append(out, ident)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LinkedAt.Equal(out[j].LinkedAt) {
			return out[i].LinkedAt.Before(out[j].LinkedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// NewUserID mints a fresh account identifier.
func NewUserID() UserID { return UserID("usr_" + randomHex(16)) }

// NewIdentityID mints a fresh identity identifier.
func NewIdentityID() IdentityID { return IdentityID("idn_" + randomHex(16)) }

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is unrecoverable for id generation.
		panic(fmt.Sprintf("account: random: %v", err))
	}
	return hex.EncodeToString(b)
}
