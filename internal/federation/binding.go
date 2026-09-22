package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/vault"
)

// Binding is a user's authorization for one source.
//
// It carries only metadata. The upstream token lives in the vault, encrypted,
// under Identity{Subject: usr_, Provider: "<game>.<source>"} -- so a dump of the
// binding store leaks no credential.
type Binding struct {
	User      account.UserID
	Game      string
	Source    string
	TokenType string
	Expiry    time.Time
	// HasRefresh records whether a refresh token exists, so refresh decisions
	// can be made without opening the vault.
	HasRefresh bool
	// Version increments on every refresh. It is how a second, concurrent
	// request notices that the token was already rotated.
	Version uint64
}

// bindingSecret is what the vault protects. It never reaches the binding store.
type bindingSecret struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// BindingIdentity is the vault key for a binding's upstream token.
func BindingIdentity(b Binding) vault.Identity {
	return vault.Identity{Subject: string(b.User), Provider: b.Game + "." + b.Source}
}

// storeBindingSecret encrypts and stores the upstream token pair.
func (s *service) storeBindingSecret(ctx context.Context, b Binding, secret bindingSecret) error {
	encoded, err := json.Marshal(secret)
	if err != nil {
		return fmt.Errorf("federation: encode binding secret: %w", err)
	}
	defer vault.Scrub(encoded)
	return s.vault.Enroll(ctx, BindingIdentity(b), encoded, map[string]string{
		"game": b.Game, "source": b.Source,
	})
}

// useBindingSecret opens the vault's plaintext window. The secret is valid only
// inside fn.
func (s *service) useBindingSecret(ctx context.Context, b Binding, fn func(*bindingSecret) error) error {
	return s.vault.Use(ctx, BindingIdentity(b), func(plaintext []byte) error {
		var secret bindingSecret
		if err := json.Unmarshal(plaintext, &secret); err != nil {
			return fmt.Errorf("federation: decode binding secret: %w", err)
		}
		return fn(&secret)
	})
}

// withAccessToken runs fn with the binding's upstream access token.
func (s *service) withAccessToken(ctx context.Context, b Binding, fn func(token string) error) error {
	return s.useBindingSecret(ctx, b, func(secret *bindingSecret) error {
		return fn(secret.AccessToken)
	})
}

// BindingStore persists binding metadata. It must never hold a credential: the
// token lives in the vault under BindingIdentity.
type BindingStore interface {
	Get(ctx context.Context, user account.UserID, game, source string) (Binding, error)
	Put(ctx context.Context, b Binding) error
	Delete(ctx context.Context, user account.UserID, game, source string) error
	// List returns every binding a user holds, so the account page can show what
	// is connected and offer to disconnect it.
	List(ctx context.Context, user account.UserID) ([]Binding, error)
}

// MemoryBindingStore is a non-durable BindingStore for development and tests.
type MemoryBindingStore struct {
	mu sync.RWMutex
	m  map[string]Binding
}

// NewMemoryBindingStore returns an empty store.
func NewMemoryBindingStore() *MemoryBindingStore {
	return &MemoryBindingStore{m: make(map[string]Binding)}
}

// Get implements BindingStore.
func (s *MemoryBindingStore) Get(_ context.Context, user account.UserID, game, source string) (Binding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.m[bindingKey(user, game, source)]
	if !ok {
		return Binding{}, ErrNotBound
	}
	return b, nil
}

// Put implements BindingStore.
func (s *MemoryBindingStore) Put(_ context.Context, b Binding) error {
	s.mu.Lock()
	s.m[bindingKey(b.User, b.Game, b.Source)] = b
	s.mu.Unlock()
	return nil
}

// Delete implements BindingStore. Deleting an absent binding is not an error.
// Delete implements BindingStore. Deleting an absent binding is not an error,
// which keeps unbinding idempotent.
func (s *MemoryBindingStore) Delete(_ context.Context, user account.UserID, game, source string) error {
	s.mu.Lock()
	delete(s.m, bindingKey(user, game, source))
	s.mu.Unlock()
	return nil
}

// List implements BindingStore.
func (s *MemoryBindingStore) List(_ context.Context, user account.UserID) ([]Binding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Binding, 0, len(s.m))
	for _, b := range s.m {
		if b.User == user {
			out = append(out, b)
		}
	}
	// Sorted, so the account page does not reorder itself between two loads.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Game != out[j].Game {
			return out[i].Game < out[j].Game
		}
		return out[i].Source < out[j].Source
	})
	return out, nil
}

func bindingKey(user account.UserID, game, source string) string {
	return string(user) + "|" + game + "|" + source
}
