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

// refreshUpstream serves a resource that only accepts validToken, and a token
// endpoint that rotates to it (or rejects the grant).
func refreshUpstream(t *testing.T, validToken string, tokenStatus int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = r.ParseForm()
			if r.PostForm.Get("grant_type") != "refresh_token" {
				t.Errorf("grant_type = %q, want refresh_token", r.PostForm.Get("grant_type"))
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(tokenStatus)
			if tokenStatus == http.StatusOK {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": validToken, "token_type": "Bearer", "expires_in": 3600, "refresh_token": "rt-2",
				})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			}
		case "/resources/profile":
			if r.Header.Get("Authorization") != "Bearer "+validToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func refreshService(t *testing.T, issuer string) (Service, backend) {
	t.Helper()
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: issuer,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	b := backend{store: NewMemoryBindingStore(), vault: newVault(t)}
	return mustService(t, Config{
		Registry: reg,
		Doer:     http.DefaultClient, HTTPClient: http.DefaultClient,
		BaseURL: "https://re0auth.test",
	}, b), b
}

func TestFetchRefreshesExpiredBinding(t *testing.T) {
	up := refreshUpstream(t, "fresh-token", http.StatusOK)
	svc, b := refreshService(t, up.URL)
	ctx := context.Background()
	b.bind(t, "usr_1", sourceName, "stale-token", "rt-1", time.Now().Add(-time.Hour))

	res, err := svc.Fetch(ctx, FetchRequest{User: "usr_1", Game: game, Resource: "profile"})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Data) != `{"ok":true}` {
		t.Fatalf("data = %s", res.Data)
	}

	stored, err := b.store.Get(ctx, "usr_1", game, sourceName)
	if err != nil {
		t.Fatal(err)
	}
	if secret := b.secret(t, "usr_1", sourceName); secret.AccessToken != "fresh-token" || secret.RefreshToken != "rt-2" {
		t.Fatalf("secret = %+v", secret)
	}
	if stored.Expiry.IsZero() {
		t.Fatal("expiry was not updated")
	}
}

// A rejected token with no expiry hint is caught reactively on the 401.
func TestFetchRefreshesOnUnauthorized(t *testing.T) {
	up := refreshUpstream(t, "fresh-token", http.StatusOK)
	svc, b := refreshService(t, up.URL)
	ctx := context.Background()
	b.bind(t, "usr_1", sourceName, "stale-token", "rt-1", time.Time{})

	res, err := svc.Fetch(ctx, FetchRequest{User: "usr_1", Game: game, Resource: "profile"})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Data) != `{"ok":true}` {
		t.Fatalf("data = %s", res.Data)
	}
	if got := b.secret(t, "usr_1", sourceName); got.AccessToken != "fresh-token" {
		t.Fatalf("secret = %+v", got)
	}
}

// A dead refresh grant means the user must bind again, not a transient error.
func TestFetchRebindsWhenRefreshRejected(t *testing.T) {
	up := refreshUpstream(t, "fresh-token", http.StatusBadRequest)
	svc, b := refreshService(t, up.URL)
	ctx := context.Background()
	b.bind(t, "usr_1", sourceName, "stale", "rt-1", time.Now().Add(-time.Hour))

	_, err := svc.Fetch(ctx, FetchRequest{User: "usr_1", Game: game, Resource: "profile"})
	if !errors.Is(err, ErrNotBound) {
		t.Fatalf("err = %v, want ErrNotBound", err)
	}
	if _, gerr := b.store.Get(ctx, "usr_1", game, sourceName); !errors.Is(gerr, ErrNotBound) {
		t.Fatalf("a dead binding was not deleted: %v", gerr)
	}
	// The encrypted secret must not outlive the binding.
	identity := BindingIdentity(Binding{User: "usr_1", Game: game, Source: sourceName})
	if exists, _ := b.vault.Exists(ctx, identity); exists {
		t.Fatal("the encrypted secret outlived the binding")
	}
}

// Without a refresh token a 401 is surfaced as-is.
func TestFetchWithoutRefreshTokenFails(t *testing.T) {
	up := refreshUpstream(t, "fresh-token", http.StatusOK)
	svc, b := refreshService(t, up.URL)
	ctx := context.Background()
	b.bind(t, "usr_1", sourceName, "stale", "", time.Time{})

	_, err := svc.Fetch(ctx, FetchRequest{User: "usr_1", Game: game, Resource: "profile"})
	var se *SourceError
	if !errors.As(err, &se) || se.Status != http.StatusUnauthorized {
		t.Fatalf("err = %v, want SourceError 401", err)
	}
}

// Concurrent fetches of the same expired binding must refresh exactly once,
// because the upstream may rotate the refresh token.
func TestConcurrentRefreshHappensOnce(t *testing.T) {
	var mu sync.Mutex
	refreshes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			mu.Lock()
			refreshes++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "fresh", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "rt-2",
			})
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
	defer srv.Close()

	svc, b := refreshService(t, srv.URL)
	ctx := context.Background()
	b.bind(t, "usr_1", sourceName, "stale", "rt-1", time.Now().Add(-time.Hour))

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.Fetch(ctx, FetchRequest{User: "usr_1", Game: game, Resource: "profile"}); err != nil {
				t.Errorf("fetch: %v", err)
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	n := refreshes
	mu.Unlock()
	if n != 1 {
		t.Fatalf("refreshes = %d, want exactly 1", n)
	}
}
