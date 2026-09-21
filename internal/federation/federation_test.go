package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/vault"
)

const (
	game         = "phigros"
	sourceName   = "fake"
	profileScope = "phigros.profile.read"
)

func fakeSource(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/resources/profile" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer upstream-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// backend is a test fixture that mirrors the real split: binding metadata in
// the store, the upstream token in the vault.
type backend struct {
	store BindingStore
	vault vault.Service
}

func newVault(t *testing.T) vault.Service {
	t.Helper()
	wrapper, err := vault.NewLocalKeyWrapper("test", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := vault.NewService(vault.NewMemoryRepo(), wrapper, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// bindAll creates metadata in the store and the token in the vault for every
// named source.
func bindAll(t *testing.T, token string, names ...string) backend {
	t.Helper()
	v := newVault(t)
	store := NewMemoryBindingStore()
	ctx := context.Background()
	for _, name := range names {
		b := Binding{User: "usr_1", Game: game, Source: name, Version: 1}
		if err := store.Put(ctx, b); err != nil {
			t.Fatal(err)
		}
		if err := v.Enroll(ctx, BindingIdentity(b), mustSecret(t, token), nil); err != nil {
			t.Fatal(err)
		}
	}
	return backend{store: store, vault: v}
}

func testService(t *testing.T, upstream *httptest.Server, b backend) Service {
	t.Helper()
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: upstream.URL, TokenClass: "revocable",
		Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(Config{Registry: reg, Bindings: b.store, Vault: b.vault, Doer: upstream.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// bound binds the default source for user, with token in the vault.
func bound(t *testing.T, user account.UserID, token string) backend {
	t.Helper()
	v := newVault(t)
	store := NewMemoryBindingStore()
	b := Binding{User: user, Game: game, Source: sourceName, Version: 1}
	if err := store.Put(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if err := v.Enroll(context.Background(), BindingIdentity(b), mustSecret(t, token), nil); err != nil {
		t.Fatal(err)
	}
	return backend{store: store, vault: v}
}

func mustSecret(t *testing.T, token string) []byte {
	t.Helper()
	return mustSecretPair(t, token, "")
}

func mustSecretPair(t *testing.T, access, refresh string) []byte {
	t.Helper()
	payload, err := json.Marshal(bindingSecret{AccessToken: access, RefreshToken: refresh})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// mustService wires a service using the fixture's store and vault.
func mustService(t *testing.T, cfg Config, b backend) Service {
	t.Helper()
	cfg.Bindings, cfg.Vault = b.store, b.vault
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// bind records binding metadata and enrolls the token pair, mirroring what
// CompleteBind does in production.
func (b backend) bind(t *testing.T, user account.UserID, name, access, refresh string, expiry time.Time) {
	t.Helper()
	binding := Binding{
		User: user, Game: game, Source: name,
		HasRefresh: refresh != "", Expiry: expiry, Version: 1,
	}
	if err := b.store.Put(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	if err := b.vault.Enroll(context.Background(), BindingIdentity(binding), mustSecretPair(t, access, refresh), nil); err != nil {
		t.Fatal(err)
	}
}

// secret reads back a binding's token pair from the vault.
func (b backend) secret(t *testing.T, user account.UserID, name string) bindingSecret {
	t.Helper()
	binding, err := b.store.Get(context.Background(), user, game, name)
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	var out bindingSecret
	if err := b.vault.Use(context.Background(), BindingIdentity(binding), func(plain []byte) error {
		return json.Unmarshal(plain, &out)
	}); err != nil {
		t.Fatalf("secret: %v", err)
	}
	return out
}

func TestFetchReturnsSourcePayload(t *testing.T) {
	up := fakeSource(t, http.StatusOK, `{"game":"phigros","user_id":"usr_1","rks":12.34}`)
	svc := testService(t, up, bound(t, "usr_1", "upstream-token"))

	res, err := svc.Fetch(context.Background(), FetchRequest{User: "usr_1", Game: game, Resource: "profile"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != sourceName || res.Degraded {
		t.Fatalf("result = %+v", res)
	}
	if string(res.Data) != `{"game":"phigros","user_id":"usr_1","rks":12.34}` {
		t.Fatalf("data = %s", res.Data)
	}
}

func TestFetchWithoutBindingReportsNotBound(t *testing.T) {
	up := fakeSource(t, http.StatusOK, `{}`)
	svc := testService(t, up, backend{store: NewMemoryBindingStore(), vault: newVault(t)})

	_, err := svc.Fetch(context.Background(), FetchRequest{User: "usr_1", Game: game, Resource: "profile"})
	if !errors.Is(err, ErrNotBound) {
		t.Fatalf("err = %v, want ErrNotBound", err)
	}
	var nb *NotBoundError
	if !errors.As(err, &nb) || nb.Game != game || nb.Source != sourceName {
		t.Fatalf("not-bound error = %#v", err)
	}
}

func TestFetchUnknownThings(t *testing.T) {
	up := fakeSource(t, http.StatusOK, `{}`)
	svc := testService(t, up, bound(t, "usr_1", "upstream-token"))
	ctx := context.Background()

	if _, err := svc.Fetch(ctx, FetchRequest{User: "usr_1", Game: "arcaea", Resource: "profile"}); !errors.Is(err, ErrUnknownGame) {
		t.Fatalf("unknown game: %v", err)
	}
	if _, err := svc.Fetch(ctx, FetchRequest{User: "usr_1", Game: game, Resource: "nope"}); !errors.Is(err, ErrUnknownResource) {
		t.Fatalf("unknown resource: %v", err)
	}
	if _, err := svc.Fetch(ctx, FetchRequest{User: "usr_1", Game: game, Resource: "profile", Source: "nope"}); !errors.Is(err, ErrUnknownSource) {
		t.Fatalf("unknown source: %v", err)
	}
}

func TestFetchSurfacesSourceError(t *testing.T) {
	up := fakeSource(t, http.StatusInternalServerError, `{}`)
	svc := testService(t, up, bound(t, "usr_1", "upstream-token"))

	_, err := svc.Fetch(context.Background(), FetchRequest{User: "usr_1", Game: game, Resource: "profile"})
	var se *SourceError
	if !errors.As(err, &se) || se.Status != http.StatusInternalServerError {
		t.Fatalf("err = %v, want SourceError 500", err)
	}
}

func TestResourceScope(t *testing.T) {
	up := fakeSource(t, http.StatusOK, `{}`)
	svc := testService(t, up, backend{store: NewMemoryBindingStore(), vault: newVault(t)})

	if scope, ok := svc.ResourceScope(game, "profile"); !ok || scope != profileScope {
		t.Fatalf("scope = %q, %v", scope, ok)
	}
	if _, ok := svc.ResourceScope(game, "nope"); ok {
		t.Fatal("unknown resource reported a scope")
	}
}

func TestRegistryRejectsBadSources(t *testing.T) {
	if _, err := NewRegistry(Source{Game: game, Name: ""}); err == nil {
		t.Fatal("accepted a source without a name")
	}
	dup := Source{Game: game, Name: sourceName, Issuer: "https://x"}
	if _, err := NewRegistry(dup, dup); err == nil {
		t.Fatal("accepted a duplicate source")
	}
	reg, err := NewRegistry(dup)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Get(game, sourceName); !ok {
		t.Fatal("source not found")
	}
	if len(reg.Sources("arcaea")) != 0 {
		t.Fatal("unexpected sources for an unknown game")
	}
}
