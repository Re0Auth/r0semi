package federation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/vault"
)

func fakeTokenServer(t *testing.T, accessToken string) (*httptest.Server, *string) {
	t.Helper()
	challenge := new(string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %q", r.PostForm.Get("grant_type"))
		}
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != *challenge {
			t.Errorf("PKCE mismatch: verifier hashed to %s, expected %s", got, *challenge)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": accessToken, "token_type": "Bearer", "expires_in": 3600, "refresh_token": "rt-1",
		})
	}))
	t.Cleanup(srv.Close)
	return srv, challenge
}

func bindService(t *testing.T, issuer string) (Service, *MemoryBindingStore, vault.Service) {
	t.Helper()
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: issuer,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings := NewMemoryBindingStore()
	v := newVault(t)
	svc, err := NewService(Config{
		Registry: reg, Bindings: bindings, Vault: v,
		Doer: http.DefaultClient, HTTPClient: http.DefaultClient,
		BaseURL: "https://re0auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, bindings, v
}

// putFailsStore is the row write failing while the vault is fine: the case the
// bind path rolls back.
type putFailsStore struct {
	BindingStore
	err error
}

func (p putFailsStore) Put(context.Context, Binding) error { return p.err }

// A bind writes the upstream token to the vault BEFORE it records the binding row,
// so a failing row write is rolled back. When the rollback fails too, the residue is
// a decryptable upstream token with no row pointing at it: no endpoint can reach it
// and only an account erasure clears it. That failure used to be dropped with `_ =`,
// which made the residue invisible to the caller and to the operator. Both learn
// about it now — the error is joined, and the log says what is stranded.
func TestCompleteBindReportsARollbackThatFailed(t *testing.T) {
	up, challenge := fakeTokenServer(t, "up-token")
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: up.URL,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	putErr := errors.New("binding store is down")
	revokeErr := errors.New("vault is sealed")
	svc, err := NewService(Config{
		Registry: reg,
		Bindings: putFailsStore{err: putErr},
		Vault:    revokeBrokenVault{Service: newVault(t), err: revokeErr},
		Doer:     http.DefaultClient, HTTPClient: http.DefaultClient,
		BaseURL: "https://re0auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Capture the log, so "an operator can see it" is a fact rather than a claim.
	var logged bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ctx := context.Background()
	ch, err := svc.BeginBind(ctx, "usr_1", game, sourceName, "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(ch.AuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	*challenge = u.Query().Get("code_challenge")

	_, _, err = svc.CompleteBind(ctx, "usr_1", ch.ID, "code-1")

	switch {
	case err == nil:
		t.Fatal("a bind that could not be recorded was reported as a success")
	case !errors.Is(err, putErr):
		t.Fatalf("err = %v, want the store failure", err)
	case !errors.Is(err, revokeErr):
		t.Fatalf("err = %v, want the rollback failure joined in", err)
	case !strings.Contains(err.Error(), "no binding"):
		t.Fatalf("err = %v, want it to name the residue", err)
	}
	if !strings.Contains(logged.String(), "no binding") {
		t.Fatalf("the stranded secret was not logged: %q", logged.String())
	}
}

func TestBindFlow(t *testing.T) {
	up, challenge := fakeTokenServer(t, "up-token")
	svc, bindings, v := bindService(t, up.URL)
	ctx := context.Background()

	ch, err := svc.BeginBind(ctx, "usr_1", game, sourceName, "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(ch.AuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("state") != ch.ID || q.Get("client_id") != "cid" {
		t.Fatalf("authorize query = %v", q)
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("missing PKCE: %v", q)
	}
	if q.Get("redirect_uri") != "https://re0auth.test/auth/upstream/phigros/fake/callback" {
		t.Fatalf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	*challenge = q.Get("code_challenge")

	binding, flow, err := svc.CompleteBind(ctx, "usr_1", ch.ID, "code-1")
	if err != nil {
		t.Fatal(err)
	}
	if binding.TokenType != "Bearer" || !binding.HasRefresh || binding.Version == 0 {
		t.Fatalf("binding = %+v", binding)
	}
	if flow.ReturnTo != "/dashboard" || flow.Game != game || flow.Source != sourceName {
		t.Fatalf("flow = %+v", flow)
	}

	stored, err := bindings.Get(ctx, "usr_1", game, sourceName)
	if err != nil || !stored.HasRefresh {
		t.Fatalf("stored = %+v, %v", stored, err)
	}
	// The upstream token must live in the vault, not in the binding store.
	if err := v.Use(ctx, BindingIdentity(stored), func(secret []byte) error {
		var got bindingSecret
		if err := json.Unmarshal(secret, &got); err != nil {
			return err
		}
		if got.AccessToken != "up-token" || got.RefreshToken != "rt-1" {
			t.Errorf("vault secret = %+v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A bind flow is single-use.
	if _, _, err := svc.CompleteBind(ctx, "usr_1", ch.ID, "code-1"); !errors.Is(err, ErrUnknownBind) {
		t.Fatalf("replay err = %v, want ErrUnknownBind", err)
	}
}

func TestBeginBindRejectsUnknownSource(t *testing.T) {
	up, _ := fakeTokenServer(t, "x")
	svc, _, _ := bindService(t, up.URL)
	if _, err := svc.BeginBind(context.Background(), "usr_1", game, "nope", "/"); !errors.Is(err, ErrUnknownSource) {
		t.Fatalf("err = %v, want ErrUnknownSource", err)
	}
}

func TestBeginBindUnavailableWithoutClient(t *testing.T) {
	reg, err := NewRegistry(Source{Game: game, Name: sourceName, Issuer: "https://up.example"})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(Config{Registry: reg, Bindings: NewMemoryBindingStore(), Vault: newVault(t), Doer: http.DefaultClient, BaseURL: "https://re0auth.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.BeginBind(context.Background(), "usr_1", game, sourceName, "/"); !errors.Is(err, ErrBindUnavailable) {
		t.Fatalf("err = %v, want ErrBindUnavailable", err)
	}
}

func TestCompleteBindRejectsWrongUser(t *testing.T) {
	up, _ := fakeTokenServer(t, "x")
	svc, _, _ := bindService(t, up.URL)
	ctx := context.Background()

	ch, err := svc.BeginBind(ctx, "usr_1", game, sourceName, "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	_, flow, err := svc.CompleteBind(ctx, "usr_2", ch.ID, "code-1")
	if !errors.Is(err, ErrBindUser) {
		t.Fatalf("err = %v, want ErrBindUser", err)
	}
	if flow.ReturnTo != "/dashboard" {
		t.Fatalf("flow not returned for redirect: %+v", flow)
	}
}

func TestCompleteBindDenied(t *testing.T) {
	up, _ := fakeTokenServer(t, "x")
	svc, _, _ := bindService(t, up.URL)
	ctx := context.Background()

	ch, err := svc.BeginBind(ctx, "usr_1", game, sourceName, "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	_, flow, err := svc.CompleteBind(ctx, "usr_1", ch.ID, "")
	if err == nil || errors.Is(err, ErrUnknownBind) {
		t.Fatalf("err = %v, want a refusal", err)
	}
	if flow.ReturnTo != "/dashboard" {
		t.Fatalf("flow = %+v", flow)
	}
}
