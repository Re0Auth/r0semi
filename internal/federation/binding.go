package federation

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
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
	// encoded is the vault's plaintext payload: Enroll encrypts it before it
	// reaches the store and it is scrubbed on the way out (defer below), which
	// is the protection G117 is looking for at a marshal boundary. The JSON
	// field names are the persisted format, not a wire leak.
	encoded, err := json.Marshal(secret) //nolint:gosec // G117: the marshaled token pair is the vault-encrypted payload
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
	// Create stores b only if no binding exists for (user, game, source), and
	// reports whether it did. It is the compare-and-swap a FIRST bind needs:
	// there is no version to expect, so "still absent" is the precondition. One
	// insert-if-absent statement, so a bind that lost its flow to a removal in
	// another process cannot recreate the row.
	Create(ctx context.Context, b Binding) (bool, error)
	Delete(ctx context.Context, user account.UserID, game, source string) error
	// List returns every binding a user holds, so the account page can show what
	// is connected and offer to disconnect it.
	List(ctx context.Context, user account.UserID) ([]Binding, error)
	// ListAll returns every binding in the deployment, for the Kill Switch.
	ListAll(ctx context.Context) ([]Binding, error)
}

// BindingPager is implemented by a store that can enumerate the deployment's
// bindings a page at a time, in (user, game, source) order.
//
// The Kill Switch sweeps every binding in the deployment, and loading all of them
// into memory to do it does not scale with the number of accounts — worse, each
// one it holds is a row it is about to make an upstream call about. A store that
// can page is asked for pages instead; one that cannot keeps using ListAll, which
// is why this is a separate interface rather than a seventh method on
// BindingStore.
//
// An empty cursor is the start of the list.
type BindingPager interface {
	ListAllPage(ctx context.Context, afterUser, afterGame, afterSource string, limit int) ([]Binding, error)
}

// MemoryBindingStore is a non-durable BindingStore for development and tests.
type MemoryBindingStore struct {
	mu sync.RWMutex
	m  map[string]Binding
	// index lists the map's keys in (user, game, source) order -- the order
	// sortBindings used to impose. A listing or a page walks it instead of
	// materialising and re-sorting the whole map, and every mutation keeps it in
	// sync: Put/Create insert the key with a binary search, Delete removes it, and
	// PutIfVersion rewrites only the payload (the key does not move).
	index []bindingIndexKey
	// rowsCopied counts the rows ListAll and ListAllPage have copied out. It exists
	// so a probe can show that paging copies each row once rather than materialising
	// the whole table per page; nothing in the read path depends on it.
	rowsCopied atomic.Int64
}

// bindingIndexKey is the ordered part of a binding: exactly the fields the index,
// the listing order and the page cursor compare. The payload lives only in the map,
// so a version bump does not make the index stale.
type bindingIndexKey struct {
	user   account.UserID
	game   string
	source string
}

// NewMemoryBindingStore returns an empty store.
func NewMemoryBindingStore() *MemoryBindingStore {
	return &MemoryBindingStore{m: make(map[string]Binding)}
}

// indexOf returns the position of key in the ordered index and whether it is
// present. When absent, the position is where it must be inserted.
func (s *MemoryBindingStore) indexOf(key bindingIndexKey) (int, bool) {
	i := sort.Search(len(s.index), func(i int) bool { return !bindingIndexLess(s.index[i], key) })
	if i < len(s.index) && s.index[i] == key {
		return i, true
	}
	return i, false
}

// insertIndex records key in the ordered index. The caller must have already
// established that key is absent.
func (s *MemoryBindingStore) insertIndex(key bindingIndexKey) {
	i, _ := s.indexOf(key)
	s.index = append(s.index, bindingIndexKey{})
	copy(s.index[i+1:], s.index[i:])
	s.index[i] = key
}

// removeIndex drops key from the ordered index if it is there.
func (s *MemoryBindingStore) removeIndex(key bindingIndexKey) {
	if i, ok := s.indexOf(key); ok {
		s.index = append(s.index[:i], s.index[i+1:]...)
	}
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
	defer s.mu.Unlock()
	key := bindingKey(b.User, b.Game, b.Source)
	if _, ok := s.m[key]; !ok {
		s.insertIndex(bindingIndexKey{user: b.User, game: b.Game, source: b.Source})
	}
	s.m[key] = b
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

// Create implements BindingStore: insert only if the key is absent, under one
// lock so the check and the write cannot be separated.
func (s *MemoryBindingStore) Create(_ context.Context, b Binding) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := bindingKey(b.User, b.Game, b.Source)
	if _, ok := s.m[key]; ok {
		return false, nil
	}
	s.insertIndex(bindingIndexKey{user: b.User, game: b.Game, source: b.Source})
	s.m[key] = b
	return true, nil
}

// Delete implements BindingStore. Deleting an absent binding is not an error,
// which keeps unbinding idempotent.
func (s *MemoryBindingStore) Delete(_ context.Context, user account.UserID, game, source string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := bindingKey(user, game, source)
	if _, ok := s.m[key]; ok {
		delete(s.m, key)
		s.removeIndex(bindingIndexKey{user: user, game: game, source: source})
	}
	return nil
}

// List implements BindingStore.
func (s *MemoryBindingStore) List(_ context.Context, user account.UserID) ([]Binding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Binding, 0, len(s.m))
	// The index is globally (user, game, source) ordered, so restricting it to one
	// user yields (game, source) order -- the sorted order the account page wants.
	for _, k := range s.index {
		if k.user == user {
			out = append(out, s.m[bindingKey(k.user, k.game, k.source)])
		}
	}
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

	out := make([]Binding, 0, len(s.index))
	for _, k := range s.index {
		out = append(out, s.m[bindingKey(k.user, k.game, k.source)])
	}
	s.rowsCopied.Add(int64(len(out)))
	return out, nil
}

// ListAllPage implements BindingPager: the bindings after the cursor, in the same
// order ListAll returns them.
//
// The ordered index makes this a bounded read rather than a full scan: the cursor
// is located by binary search, so a page copies only its own rows and never sorts
// the table.
func (s *MemoryBindingStore) ListAllPage(_ context.Context, afterUser, afterGame, afterSource string, limit int) ([]Binding, error) {
	if limit <= 0 {
		limit = 1
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	// bindingIndexAfter is monotone over the sorted index (a contiguous run of
	// trues), so its first true position is exactly the cursor's successor.
	pos := sort.Search(len(s.index), func(i int) bool {
		return bindingIndexAfter(s.index[i], afterUser, afterGame, afterSource)
	})
	end := pos + limit
	if end > len(s.index) {
		end = len(s.index)
	}

	out := make([]Binding, 0, end-pos)
	for _, k := range s.index[pos:end] {
		out = append(out, s.m[bindingKey(k.user, k.game, k.source)])
	}
	s.rowsCopied.Add(int64(len(out)))
	return out, nil
}

// bindingIndexAfter is the cursor test: whether the key sorts after
// (user, game, source). An empty cursor is the start of the list, which is safe
// because a real account id is never empty.
func bindingIndexAfter(k bindingIndexKey, user, game, source string) bool {
	if user == "" && game == "" && source == "" {
		return true
	}
	switch {
	case k.user != account.UserID(user):
		return k.user > account.UserID(user)
	case k.game != game:
		return k.game > game
	default:
		return k.source > source
	}
}

// bindingIndexLess orders bindings the one way every listing does, so a page
// boundary means the same thing to the store and to its caller.
func bindingIndexLess(a, b bindingIndexKey) bool {
	switch {
	case a.user != b.user:
		return a.user < b.user
	case a.game != b.game:
		return a.game < b.game
	default:
		return a.source < b.source
	}
}
