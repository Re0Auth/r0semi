package federation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

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

// claimFailsStore fails the row claim while the vault is fine. With the claim
// ordered before the vault write, a failed claim must leave no secret behind.
type claimFailsStore struct {
	BindingStore
	err error
}

func (p claimFailsStore) Create(context.Context, Binding) (bool, error) {
	return false, p.err
}

func (p claimFailsStore) PutIfVersion(context.Context, Binding, uint64) (bool, error) {
	return false, p.err
}

// enrollFailsVault fails the vault write while leaving reads working.
type enrollFailsVault struct {
	vault.Service
	err error
}

func (v enrollFailsVault) Enroll(context.Context, vault.Identity, []byte, map[string]string) error {
	return v.err
}

// A bind claims the binding row BEFORE it writes the upstream token to the vault,
// so a failed claim leaves no residue: no decryptable credential with no row
// pointing at it. The old order (secret first, roll back on a failed row write)
// could strand one when the rollback also failed; claiming first removes the
// window instead of reporting it.
func TestCompleteBindClaimsTheRowBeforeItWritesTheSecret(t *testing.T) {
	up, challenge := fakeTokenServer(t, "up-token")
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: up.URL,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	claimErr := errors.New("binding store is down")
	v := newVault(t)
	svc, err := NewService(Config{
		Registry: reg,
		Bindings: claimFailsStore{BindingStore: NewMemoryBindingStore(), err: claimErr},
		Vault:    v,
		Doer:     http.DefaultClient, HTTPClient: http.DefaultClient,
		BaseURL: "https://re0auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}

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
	if !errors.Is(err, claimErr) {
		t.Fatalf("err = %v, want the store failure", err)
	}
	// The claim came first, so no secret was written and there is nothing stranded.
	ok, xerr := v.Exists(ctx, BindingIdentity(Binding{User: "usr_1", Game: game, Source: sourceName}))
	if xerr != nil || ok {
		t.Fatalf("a failed row claim left a vault secret: exists=%v err=%v", ok, xerr)
	}
}

// The other half of the ordering: when the claim wins and the vault write then
// fails, the error is reported and the claimed row is left for the next call or
// an Unbind. There is no secret, so the failure cannot advertise a usable binding.
func TestCompleteBindReportsASecretWriteFailureAfterTheClaim(t *testing.T) {
	up, challenge := fakeTokenServer(t, "up-token")
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: up.URL,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollErr := errors.New("vault is sealed")
	store := NewMemoryBindingStore()
	svc, err := NewService(Config{
		Registry: reg,
		Bindings: store,
		Vault:    enrollFailsVault{Service: newVault(t), err: enrollErr},
		Doer:     http.DefaultClient, HTTPClient: http.DefaultClient,
		BaseURL: "https://re0auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}

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
	if !errors.Is(err, enrollErr) {
		t.Fatalf("err = %v, want the vault failure", err)
	}
	if _, gerr := store.Get(ctx, "usr_1", game, sourceName); gerr != nil {
		t.Fatalf("the claimed row is gone after a vault failure: %v", gerr)
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

// A bind flow is written by BeginBind and read only if the browser comes back, so
// an abandoned one — a closed tab, a scan the user never finished — has to be
// removable. Consume already refuses an expired flow; without a sweep the entry
// itself stayed in the map, which in memory mode is the only bound that exists.
func TestMemoryBindFlowStoreSweepsExpiredFlows(t *testing.T) {
	store := NewMemoryBindFlowStore()
	ctx := context.Background()
	now := time.Now()

	expired := BindFlow{
		ID: "bnd_expired", State: "bnd_expired", User: "usr_1", Game: game, Source: sourceName,
		Verifier: "verifier", ReturnTo: "/dashboard", ExpiresAt: now.Add(-time.Minute),
	}
	live := BindFlow{
		ID: "bnd_live", State: "bnd_live", User: "usr_1", Game: game, Source: sourceName,
		Verifier: "verifier", ReturnTo: "/dashboard", ExpiresAt: now.Add(time.Minute),
	}
	for _, f := range []BindFlow{expired, live} {
		if err := store.Put(ctx, f); err != nil {
			t.Fatal(err)
		}
	}

	if removed := store.SweepExpired(); removed != 1 {
		t.Fatalf("SweepExpired removed %d, want only the expired flow", removed)
	}
	if _, err := store.Consume(ctx, expired.State); !errors.Is(err, ErrUnknownBind) {
		t.Fatalf("the expired flow survived the sweep: %v", err)
	}
	// The live one is untouched: a sweep is not allowed to break a flow in flight.
	if _, err := store.Consume(ctx, live.State); err != nil {
		t.Fatalf("the sweep removed a live flow: %v", err)
	}
	if removed := store.SweepExpired(); removed != 0 {
		t.Fatalf("a second sweep removed %d, want 0", removed)
	}
}
