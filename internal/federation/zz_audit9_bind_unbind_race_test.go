package federation

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

// audit9BlockingPutStore wraps MemoryBindingStore and blocks one Put on demand,
// giving the test a deterministic window inside CompleteBind's row write.
type audit9BlockingPutStore struct {
	*MemoryBindingStore
	mu      sync.Mutex
	armed   bool
	inPut   chan struct{}
	release chan struct{}
}

func (s *audit9BlockingPutStore) arm() {
	s.mu.Lock()
	s.armed = true
	s.mu.Unlock()
}

// block parks the next row write. CompleteBind claims the row with
// PutIfVersion when the flow began against a live binding, so every write
// primitive has to be parked or the test's window never opens.
func (s *audit9BlockingPutStore) block() {
	s.mu.Lock()
	block := s.armed
	s.armed = false
	s.mu.Unlock()
	if block {
		close(s.inPut)
		<-s.release
	}
}

func (s *audit9BlockingPutStore) Put(ctx context.Context, b Binding) error {
	s.block()
	return s.MemoryBindingStore.Put(ctx, b)
}

func (s *audit9BlockingPutStore) PutIfVersion(ctx context.Context, b Binding, expectedVersion uint64) (bool, error) {
	s.block()
	return s.MemoryBindingStore.PutIfVersion(ctx, b, expectedVersion)
}

func (s *audit9BlockingPutStore) Create(ctx context.Context, b Binding) (bool, error) {
	s.block()
	return s.MemoryBindingStore.Create(ctx, b)
}

// AUDIT9 / S14-2 (fixed) — CompleteBind holds the per-binding keyed lock, so a
// concurrent Unbind is ordered against it instead of interleaving.
//
// Before the fix CompleteBind was the one binding writer that took no lock: it
// stored the vault secret and Put() the row with nothing opposing an Unbind, a
// Kill Switch shred or an account erasure, so an in-flight bind could resurrect a
// binding that had already been reported disconnected. The lock is now held for
// the whole exchange-and-store sequence.
//
// The blocking store parks the bind inside bindings.Put, which is where the
// missing lock used to leave the window open. Unbind must then not complete until
// the bind does.
func TestAudit9UnbindWaitsForAnInFlightBind(t *testing.T) {
	up, challenge := fakeTokenServer(t, "up-token")
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: up.URL,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &audit9BlockingPutStore{
		MemoryBindingStore: NewMemoryBindingStore(),
		inPut:              make(chan struct{}),
		release:            make(chan struct{}),
	}
	svc, err := NewService(Config{
		Registry: reg, Bindings: store, Vault: newVault(t),
		Doer: http.DefaultClient, HTTPClient: http.DefaultClient,
		BaseURL: "https://re0auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// The source is already connected, as it is before a user disconnects it.
	first, err := svc.BeginBind(ctx, "usr_1", game, sourceName, "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	if u, perr := url.Parse(first.AuthorizeURL); perr != nil {
		t.Fatal(perr)
	} else {
		*challenge = u.Query().Get("code_challenge")
	}
	if _, _, err := svc.CompleteBind(ctx, "usr_1", first.ID, "code-1"); err != nil {
		t.Fatal(err)
	}

	// A second bind blocks inside bindings.Put, holding the per-binding lock.
	store.arm()
	second, err := svc.BeginBind(ctx, "usr_1", game, sourceName, "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	if u, perr := url.Parse(second.AuthorizeURL); perr != nil {
		t.Fatal(perr)
	} else {
		*challenge = u.Query().Get("code_challenge")
	}
	bindDone := make(chan error, 1)
	go func() {
		_, _, err := svc.CompleteBind(ctx, "usr_1", second.ID, "code-2")
		bindDone <- err
	}()
	select {
	case <-store.inPut:
	case <-time.After(3 * time.Second):
		t.Fatal("the second bind never reached bindings.Put")
	}

	// Unbind must wait: the bind holds the binding's lock.
	unbindDone := make(chan error, 1)
	go func() {
		_, err := svc.Unbind(ctx, "usr_1", game, sourceName)
		unbindDone <- err
	}()
	select {
	case err := <-unbindDone:
		close(store.release)
		<-bindDone
		t.Fatalf("Unbind completed (%v) while a bind held the per-binding lock: S14-2 regressed", err)
	case <-time.After(250 * time.Millisecond):
		// Expected: ordered behind the bind.
	}

	// Let the bind finish; Unbind then runs and removes what it wrote.
	close(store.release)
	if err := <-bindDone; err != nil {
		t.Fatalf("the in-flight bind: %v", err)
	}
	if err := <-unbindDone; err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if _, err := store.Get(ctx, "usr_1", game, sourceName); !errors.Is(err, ErrNotBound) {
		t.Fatalf("after the ordered Unbind the row is present: %v", err)
	}
}
