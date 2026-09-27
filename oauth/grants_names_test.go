package oauth

// The grants view is N clients' worth of names. It used to resolve them one Get at
// a time from inside its row loop — N round trips for a page whose whole content
// is N names. These tests pin that the bulk path is taken when a registry offers
// it, and that a registry which does not still works.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
)

// countingRegistry records how names were resolved. It implements the bulk seam
// (delegating to the wrapped registry's own implementation, so its own fallback
// does not show up in the count) and counts per-id Gets.
type countingRegistry struct {
	ClientRegistry
	mu    sync.Mutex
	gets  int
	names int
}

func (c *countingRegistry) Get(ctx context.Context, id string) (Client, error) {
	c.mu.Lock()
	c.gets++
	c.mu.Unlock()
	return c.ClientRegistry.Get(ctx, id)
}

func (c *countingRegistry) ClientNames(ctx context.Context, ids []string) (map[string]string, error) {
	c.mu.Lock()
	c.names++
	c.mu.Unlock()
	if bulk, ok := c.ClientRegistry.(ClientNameLookup); ok {
		return bulk.ClientNames(ctx, ids)
	}
	return nil, nil
}

func (c *countingRegistry) counts() (gets, names int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gets, c.names
}

// plainRegistry exposes only oauth.ClientRegistry, so the bulk path is not
// available to a caller that type-asserts for it.
type plainRegistry struct{ ClientRegistry }

func grantsService(t *testing.T, clients ClientRegistry, store Store) Service {
	t.Helper()
	svc, err := NewService(clients, store, audit.NewMemoryLogger(), Config{
		Issuer: "https://auth.test",
		Scopes: DefaultRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func registerClients(t *testing.T, reg ClientRegistry, ids ...string) {
	t.Helper()
	for _, id := range ids {
		c, err := NewClient(id, "App "+id, ClientPublic, "", []string{"https://app.example/cb"}, []Scope{ScopeAccountID})
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Create(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
}

func saveSubjectTokens(t *testing.T, store Store, ids ...string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	for _, id := range ids {
		if err := store.SaveAccess(ctx, "at-"+id, AccessToken{
			ClientID: id, Subject: "usr_1", Scopes: []Scope{ScopeAccountID},
			IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGrantsResolvesEveryClientNameInOneLookup(t *testing.T) {
	base := NewMemoryClientRegistry()
	registerClients(t, base, "a", "b", "c")
	reg := &countingRegistry{ClientRegistry: base}

	store := NewMemoryStore()
	saveSubjectTokens(t, store, "a", "b", "c")
	svc := grantsService(t, reg, store)

	grants, err := svc.Grants(context.Background(), "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 3 {
		t.Fatalf("grants = %d, want 3", len(grants))
	}
	for _, g := range grants {
		if want := "App " + g.ClientID; g.ClientName != want {
			t.Errorf("client %s name = %q, want %q", g.ClientID, g.ClientName, want)
		}
	}
	gets, names := reg.counts()
	if names != 1 {
		t.Errorf("bulk lookups = %d, want 1", names)
	}
	if gets != 0 {
		t.Errorf("per-client lookups = %d, want none", gets)
	}
}

// A registry that does not implement the bulk seam keeps working: names are
// resolved one id at a time, which is what the view did before.
func TestGrantsFallsBackToPerClientLookup(t *testing.T) {
	base := NewMemoryClientRegistry()
	registerClients(t, base, "a", "b")

	store := NewMemoryStore()
	saveSubjectTokens(t, store, "a", "b")
	svc := grantsService(t, plainRegistry{ClientRegistry: base}, store)

	grants, err := svc.Grants(context.Background(), "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 2 {
		t.Fatalf("grants = %d, want 2", len(grants))
	}
	for _, g := range grants {
		if want := "App " + g.ClientID; g.ClientName != want {
			t.Errorf("client %s name = %q, want %q", g.ClientID, g.ClientName, want)
		}
	}
}

// An id nobody registered keeps an empty name rather than failing the view.
func TestGrantsLeavesAnUnknownClientUnnamed(t *testing.T) {
	store := NewMemoryStore()
	saveSubjectTokens(t, store, "ghost")
	svc := grantsService(t, NewMemoryClientRegistry(), store)

	grants, err := svc.Grants(context.Background(), "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].ClientName != "" {
		t.Fatalf("grants = %+v, want one unnamed entry", grants)
	}
}
