package federation

import (
	"context"
	"crypto/rand"
	"encoding/binary"
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
	// Version is an opaque generation, not a counter: it changes whenever this
	// binding is written, and its only job is to let a writer notice that the row
	// moved under it. A refresh compares it (compare-and-swap) and a rejected
	// refresh reads a moved version as "somebody else rotated this", which is what
	// separates a spent one-time token from a dead grant.
	//
	// It is therefore NOT 1 on every bind — see newBindingGeneration for what
	// restarting at 1 broke.
	Version uint64
}

// newBindingGeneration returns the version a freshly bound binding starts at.
//
// Random rather than always 1 because of what the version is FOR. `refreshRejected`
// treats "the stored version moved" as the only evidence that another writer
// rotated this binding — the signal that separates a spent one-time refresh token
// from a genuinely dead grant. Re-binding the same (user, game, source) used to
// restart the count at 1, so a stale refresh still holding 1 would see "still 1",
// conclude the credential was dead, and delete the binding the user had just
// reconnected, shredding its secret without telling the source.
//
// A fresh random generation makes a re-bind look to that check exactly like a
// rotation, which is the truthful answer: either way, the credential the stale
// caller holds is not the current one.
func newBindingGeneration() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("federation: generate binding version: %w", err)
	}
	if v := binary.BigEndian.Uint64(b[:]); v != 0 {
		return v, nil
	}
	return 1, nil
}

// bindingSecret is what the vault protects. It never reaches the binding store.
//
// The fields are strings, so a decoded copy cannot be zeroized — Go strings are
// immutable. See useBindingSecret for what that means for the vault's window.
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

// useBindingSecret opens the vault's plaintext window and decodes the pair.
//
// What the window actually guarantees, stated precisely because the old comment
// here was wrong: the BYTE BUFFER the vault decrypted into is zeroed when Use
// returns, but `secret` is a pair of Go strings, and strings are immutable and
// cannot be wiped. Those copies live until the garbage collector reclaims them —
// they do not vanish with the window.
//
// So a caller must treat anything it lifts into its own variables as living as long
// as it holds it. That is fine for this package's use (the token is on its way to
// the source over TLS, in the same call), and it is not fine to stash it anywhere
// durable.
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
	// PutIfVersion stores b only if the persisted binding is still at
	// expectedVersion, and reports whether it did. It is the compare-and-swap
	// that makes two refreshes of the same binding safe when they run in
	// different processes: both may read version N, but only one may write N+1.
	// The loser must re-read and use the winner's token rather than overwrite it.
	PutIfVersion(ctx context.Context, b Binding, expectedVersion uint64) (bool, error)
	Delete(ctx context.Context, user account.UserID, game, source string) error
	// List returns every binding a user holds, so the account page can show what
	// is connected and offer to disconnect it.
	List(ctx context.Context, user account.UserID) ([]Binding, error)
	// ListAll returns every binding in the deployment, for the Kill Switch.
	ListAll(ctx context.Context) ([]Binding, error)
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

// PutIfVersion implements BindingStore. The version check and the write happen
// under one lock, which is what makes it a compare-and-swap rather than a read
// followed by a write.
func (s *MemoryBindingStore) PutIfVersion(_ context.Context, b Binding, expectedVersion uint64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := bindingKey(b.User, b.Game, b.Source)
	existing, ok := s.m[key]
	if !ok || existing.Version != expectedVersion {
		return false, nil
	}
	s.m[key] = b
	return true, nil
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

// ListAll implements BindingStore. It exists for the Kill Switch, which has to
// reach a binding it was never told about; the account page never needs it.
func (s *MemoryBindingStore) ListAll(_ context.Context) ([]Binding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Binding, 0, len(s.m))
	for _, b := range s.m {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		switch {
		case out[i].User != out[j].User:
			return out[i].User < out[j].User
		case out[i].Game != out[j].Game:
			return out[i].Game < out[j].Game
		default:
			return out[i].Source < out[j].Source
		}
	})
	return out, nil
}
