package federation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// The compare-and-swap is what lets two processes refresh one binding safely:
// only the writer that still sees the version it read may advance it.
func TestMemoryBindingPutIfVersionIsCompareAndSwap(t *testing.T) {
	store := NewMemoryBindingStore()
	ctx := context.Background()
	if err := store.Put(ctx, Binding{User: "usr_1", Game: game, Source: sourceName, Version: 1}); err != nil {
		t.Fatal(err)
	}

	next := Binding{User: "usr_1", Game: game, Source: sourceName, Version: 2, TokenType: "Bearer"}

	// A stale expectation loses and must not overwrite.
	won, err := store.PutIfVersion(ctx, next, 0)
	if err != nil {
		t.Fatal(err)
	}
	if won {
		t.Fatal("a stale expectation won the compare-and-swap")
	}
	if got, _ := store.Get(ctx, "usr_1", game, sourceName); got.Version != 1 {
		t.Fatalf("version = %d after a losing write, want 1", got.Version)
	}

	// The matching expectation wins.
	won, err = store.PutIfVersion(ctx, next, 1)
	if err != nil || !won {
		t.Fatalf("matching expectation: won=%v err=%v", won, err)
	}
	if got, _ := store.Get(ctx, "usr_1", game, sourceName); got.Version != 2 || got.TokenType != "Bearer" {
		t.Fatalf("binding = %+v, want the written row", got)
	}

	// An absent binding is not created: the caller is refreshing one that exists,
	// so "not there" is a lost race, not an insert.
	won, err = store.PutIfVersion(ctx, Binding{User: "usr_2", Game: game, Source: sourceName, Version: 1}, 0)
	if err != nil || won {
		t.Fatalf("absent binding: won=%v err=%v, want false", won, err)
	}
}

// If another process rotated the binding while we were calling the source, the
// invalid_grant we got is for a token that was spent, not a dead one. The
// binding must survive, and the caller must get the winner's binding.
func TestRefreshRejectedKeepsBindingWhenAnotherInstanceRotated(t *testing.T) {
	svc, b := refreshService(t, "https://unused.example")
	ctx := context.Background()
	b.bind(t, "usr_1", sourceName, "stale", "rt-1", time.Now().Add(-time.Hour))

	spent := Binding{User: "usr_1", Game: game, Source: sourceName, Version: 1}
	// Another process won the race and advanced the version.
	winner := spent
	winner.Version = 2
	winner.HasRefresh = true
	if err := b.store.Put(ctx, winner); err != nil {
		t.Fatal(err)
	}

	got, err := svc.(*service).refreshRejected(ctx, spent)
	if err != nil {
		t.Fatalf("refreshRejected = %v, want the winner's binding", err)
	}
	if got.Version != 2 {
		t.Fatalf("version = %d, want the winner's 2", got.Version)
	}
	if _, gerr := b.store.Get(ctx, "usr_1", game, sourceName); gerr != nil {
		t.Fatalf("the binding was removed despite another instance renewing it: %v", gerr)
	}
}

// With the version unmoved, the grant really is gone: drop both the metadata and
// the encrypted secret, and tell the caller to bind again.
func TestRefreshRejectedDeletesWhenTheGrantIsDead(t *testing.T) {
	svc, b := refreshService(t, "https://unused.example")
	ctx := context.Background()
	b.bind(t, "usr_1", sourceName, "stale", "rt-1", time.Now().Add(-time.Hour))

	spent := Binding{User: "usr_1", Game: game, Source: sourceName, Version: 1}
	if _, err := svc.(*service).refreshRejected(ctx, spent); !errors.Is(err, ErrNotBound) {
		t.Fatalf("err = %v, want ErrNotBound", err)
	}
	if _, gerr := b.store.Get(ctx, "usr_1", game, sourceName); !errors.Is(gerr, ErrNotBound) {
		t.Fatalf("a dead binding was not deleted: %v", gerr)
	}
	if exists, _ := b.vault.Exists(ctx, BindingIdentity(spent)); exists {
		t.Fatal("the encrypted secret outlived the binding")
	}
}

// twoInstances builds two services over one store and vault, standing in for two
// processes sharing one database. Their per-process refresh locks do not see each
// other, so only the version compare-and-swap and the re-read keep them from
// destroying the binding.
func twoInstances(t *testing.T, issuer string, b backend) (Service, Service) {
	t.Helper()
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: issuer,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mk := func() Service {
		svc, err := NewService(Config{
			Registry: reg, Bindings: b.store, Vault: b.vault,
			Doer: http.DefaultClient, HTTPClient: http.DefaultClient,
			BaseURL: "https://re0auth.test",
		})
		if err != nil {
			t.Fatal(err)
		}
		return svc
	}
	return mk(), mk()
}

// The end-to-end version of the race: two instances refresh the same expired
// binding at once against a source that rotates the refresh token, so exactly one
// upstream refresh can succeed. Both fetches must still succeed and the binding
// must survive — before the re-read, the loser deleted a binding the winner had
// just renewed.
//
// The source decides success by the refresh token, not by counting requests: the
// oauth2 client probes the token endpoint's auth style, so one logical refresh
// may arrive as two requests, and counting those would measure the wrong thing.
func TestConcurrentRefreshAcrossInstancesKeepsTheBinding(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryBindingStore()
	v := newVault(t)

	var mu sync.Mutex
	spent := map[string]bool{}
	successes := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = r.ParseForm()
			rt := r.PostForm.Get("refresh_token")

			mu.Lock()
			won := rt != "" && !spent[rt]
			if won {
				spent[rt] = true
				successes++
			}
			mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			if won {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": "fresh", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "rt-2",
				})
				return
			}
			// The token rotates, so a caller whose refresh token is already spent
			// has lost the race. Wait until the winner has committed its version,
			// so the loser's re-read sees it — the interleaving this fix exists
			// for, made deterministic.
			for i := 0; i < 2000; i++ {
				if got, _ := store.Get(ctx, "usr_1", game, sourceName); got.Version > 1 {
					break
				}
				time.Sleep(time.Millisecond)
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		case "/resources/profile":
			if r.Header.Get("Authorization") != "Bearer fresh" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer up.Close()

	b := backend{store: store, vault: v}
	b.bind(t, "usr_1", sourceName, "stale", "rt-1", time.Now().Add(-time.Hour))
	a, c := twoInstances(t, up.URL, b)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, svc := range []Service{a, c} {
		wg.Add(1)
		go func(i int, svc Service) {
			defer wg.Done()
			_, errs[i] = svc.Fetch(ctx, FetchRequest{User: "usr_1", Game: game, Resource: "profile"})
		}(i, svc)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("instance %d fetch: %v", i, err)
		}
	}

	got, gerr := store.Get(ctx, "usr_1", game, sourceName)
	if gerr != nil {
		t.Fatalf("the binding did not survive a concurrent refresh: %v", gerr)
	}
	if got.Version != 2 {
		t.Fatalf("version = %d, want 2 (exactly one rotation)", got.Version)
	}
	mu.Lock()
	n := successes
	mu.Unlock()
	if n != 1 {
		t.Fatalf("successful refreshes = %d, want exactly 1", n)
	}
}
