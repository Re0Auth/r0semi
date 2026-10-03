package auth

import (
	"sync"
	"time"

	"github.com/alexedwards/scs/v2"
)

// tombstoningStore makes invalidation authoritative for an in-process scs store.
//
// scs commits a loaded session after the handler returns (its LoadAndSave commits
// on return when the handler wrote nothing). A request that loaded a session
// before another request deleted it therefore writes its stale copy back, and
// scs's memstore Commit is an unconditional map write — the delete is undone.
// This wrapper remembers the tokens it was asked to delete and drops any later
// commit or load for them, which is the in-process half of R10-96. The durable
// store gets the same guarantee from a `invalidated_at` column instead
// (internal/store/postgres/sessions.go) because the Kill Switch reaches it
// directly, not through scs.
//
// It implements only scs.Store on purpose: scs's memstore implements only Store,
// and scs's LoadAndSave prefers CtxStore only when the store provides it.
type tombstoningStore struct {
	inner scs.Store
	ttl   time.Duration

	mu   sync.Mutex
	dead map[string]time.Time
}

func newTombstoningStore(inner scs.Store, ttl time.Duration) *tombstoningStore {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &tombstoningStore{inner: inner, ttl: ttl, dead: make(map[string]time.Time)}
}

// isDead reports whether token was invalidated and its marker has not lapsed. The
// marker is pruned on the way past, so the map holds one entry per invalidation
// for at most the session lifetime rather than forever.
func (t *tombstoningStore) isDead(token string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	until, ok := t.dead[token]
	if !ok {
		return false
	}
	if time.Now().Before(until) {
		return true
	}
	delete(t.dead, token)
	return false
}

// Find reports a tombstoned token as not found, so a replayed cookie cannot load
// a session even if the wrapped store still holds the row.
func (t *tombstoningStore) Find(token string) ([]byte, bool, error) {
	if t.isDead(token) {
		return nil, false, nil
	}
	return t.inner.Find(token)
}

// Commit drops the write for a tombstoned token. scs treats a returned error as a
// 500, and the session is already gone, so a silent no-op is the correct answer.
func (t *tombstoningStore) Commit(token string, b []byte, expiry time.Time) error {
	if t.isDead(token) {
		return nil
	}
	return t.inner.Commit(token, b, expiry)
}

// Delete records the tombstone before forwarding the delete, so a commit that
// reaches the store after this call cannot re-create the session.
func (t *tombstoningStore) Delete(token string) error {
	t.mu.Lock()
	t.dead[token] = time.Now().Add(t.ttl)
	t.mu.Unlock()
	return t.inner.Delete(token)
}
