package federation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/vault"
)

// releasingSource is a fake data source that exchanges a code for a token and
// records every revocation it is asked to perform.
type releasingSource struct {
	mu       sync.Mutex
	released []string
	hints    []string
	// cascaded records the tokens cascade revocation was asked about.
	cascaded []string
	// revokeStatus, when set, makes the revocation endpoint refuse.
	revokeStatus int
	// cascadeStatus, when set, makes the cascade endpoint refuse.
	cascadeStatus int
}

func (r *releasingSource) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.released...)
}

func (r *releasingSource) cascadeCalls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.cascaded...)
}

func newReleasingSource(t *testing.T, r *releasingSource) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "up-at", "token_type": "Bearer",
				"expires_in": 3600, "refresh_token": "up-rt",
			})
		case "/oauth/revoke":
			_ = req.ParseForm()
			if r.revokeStatus != 0 {
				w.WriteHeader(r.revokeStatus)
				return
			}
			// RFC 6749 §2.3.1: what arrives in the Basic header was urlencoded by
			// the sender, so undo that before comparing.
			id, secret, _ := req.BasicAuth()
			gotID, _ := url.QueryUnescape(id)
			gotSecret, _ := url.QueryUnescape(secret)
			r.mu.Lock()
			r.released = append(r.released, req.PostForm.Get("token"))
			r.hints = append(r.hints, req.PostForm.Get("token_type_hint"))
			r.mu.Unlock()
			if gotID != "cid" || gotSecret != "s+cr/et" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)

		case "/oauth/cascade_revocation":
			_ = req.ParseForm()
			if r.cascadeStatus != 0 {
				w.WriteHeader(r.cascadeStatus)
				return
			}
			id, secret, _ := req.BasicAuth()
			gotID, _ := url.QueryUnescape(id)
			gotSecret, _ := url.QueryUnescape(secret)
			r.mu.Lock()
			r.cascaded = append(r.cascaded, req.PostForm.Get("token"))
			r.mu.Unlock()
			if gotID != "cid" || gotSecret != "s+cr/et" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func unbindSource(issuer, tokenClass string) Source {
	return Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: issuer,
		// A secret with characters that must survive the Basic-header encoding.
		ClientID: "cid", ClientSecret: "s+cr/et", TokenClass: tokenClass,
		Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	}
}

func unbindService(t *testing.T, src Source) (Service, *MemoryBindingStore, vault.Service) {
	t.Helper()
	reg, err := NewRegistry(src)
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

// connect drives the real binding flow, so a binding under test came from the
// code that produces bindings.
func connect(t *testing.T, svc Service, user account.UserID) Binding {
	t.Helper()
	ctx := context.Background()
	ch, err := svc.BeginBind(ctx, user, game, sourceName, "/app/sources")
	if err != nil {
		t.Fatal(err)
	}
	binding, _, err := svc.CompleteBind(ctx, user, ch.ID, "upstream-code")
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestBindingsListsWhatIsConnected(t *testing.T) {
	rec := &releasingSource{}
	up := newReleasingSource(t, rec)
	svc, _, _ := unbindService(t, unbindSource(up.URL, "revocable"))

	if got, err := svc.Bindings(context.Background(), "usr_1"); err != nil || len(got) != 0 {
		t.Fatalf("before binding: %v, %v", got, err)
	}

	binding := connect(t, svc, "usr_1")
	got, err := svc.Bindings(context.Background(), "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Game != binding.Game || got[0].Source != binding.Source {
		t.Fatalf("bindings = %+v", got)
	}
	// Another account sees nothing.
	if other, err := svc.Bindings(context.Background(), "usr_2"); err != nil || len(other) != 0 {
		t.Fatalf("another user sees %+v, %v", other, err)
	}
	if _, err := svc.Bindings(context.Background(), ""); err == nil {
		t.Error("Bindings accepted an empty user")
	}
}

func TestUnbindReleasesUpstreamAndRemovesLocally(t *testing.T) {
	rec := &releasingSource{}
	up := newReleasingSource(t, rec)
	svc, bindings, v := unbindService(t, unbindSource(up.URL, "revocable"))
	ctx := context.Background()

	binding := connect(t, svc, "usr_1")
	if exists, _ := v.Exists(ctx, BindingIdentity(binding)); !exists {
		t.Fatal("the binding secret was not stored")
	}

	result, err := svc.Unbind(ctx, "usr_1", game, sourceName)
	if err != nil {
		t.Fatal(err)
	}
	if result.Upstream != RevocationDone {
		t.Fatalf("upstream = %q (%s), want done", result.Upstream, result.UpstreamError)
	}
	// The source was told, and told about the refresh token: that is the one whose
	// revocation ends the client's ability to keep coming back.
	if calls := rec.calls(); len(calls) != 1 || calls[0] != "up-rt" {
		t.Fatalf("upstream revocations = %v, want the refresh token once", calls)
	}

	// Both halves are gone locally: the row and the secret.
	if _, err := bindings.Get(ctx, "usr_1", game, sourceName); err == nil {
		t.Error("the binding row survived")
	}
	if exists, _ := v.Exists(ctx, BindingIdentity(binding)); exists {
		t.Error("the binding secret survived")
	}
}

// A source that declared it cannot revoke per client must be reported as such.
// Quietly claiming success would defeat the entire point of token_class.
func TestUnbindReportsLongLivedAsUnsupported(t *testing.T) {
	rec := &releasingSource{}
	up := newReleasingSource(t, rec)
	svc, bindings, _ := unbindService(t, unbindSource(up.URL, "long_lived"))
	ctx := context.Background()
	connect(t, svc, "usr_1")

	result, err := svc.Unbind(ctx, "usr_1", game, sourceName)
	if err != nil {
		t.Fatal(err)
	}
	if result.Upstream != RevocationUnsupported {
		t.Fatalf("upstream = %q, want unsupported", result.Upstream)
	}
	if calls := rec.calls(); len(calls) != 0 {
		t.Fatalf("a long-lived source was asked to revoke anyway: %v", calls)
	}
	// The local half still happened: the user asked to disconnect and is.
	if _, err := bindings.Get(ctx, "usr_1", game, sourceName); err == nil {
		t.Error("the binding row survived")
	}
}

// A source that is down must not be able to stop someone cutting it off from
// their own account.
func TestUnbindRemovesLocallyWhenTheSourceRefuses(t *testing.T) {
	rec := &releasingSource{revokeStatus: http.StatusInternalServerError}
	up := newReleasingSource(t, rec)
	svc, bindings, v := unbindService(t, unbindSource(up.URL, "revocable"))
	ctx := context.Background()

	binding := connect(t, svc, "usr_1")
	result, err := svc.Unbind(ctx, "usr_1", game, sourceName)
	if err != nil {
		t.Fatalf("a refusing source failed the unbind: %v", err)
	}
	if result.Upstream != RevocationUnavailable {
		t.Fatalf("upstream = %q, want unavailable", result.Upstream)
	}
	if result.UpstreamError == "" {
		t.Error("no reason given for a failed upstream revocation")
	}
	if _, err := bindings.Get(ctx, "usr_1", game, sourceName); err == nil {
		t.Error("the binding row survived a refused upstream revocation")
	}
	if exists, _ := v.Exists(ctx, BindingIdentity(binding)); exists {
		t.Error("the binding secret survived a refused upstream revocation")
	}
}

func TestUnbindIsIdempotent(t *testing.T) {
	rec := &releasingSource{}
	up := newReleasingSource(t, rec)
	svc, _, _ := unbindService(t, unbindSource(up.URL, "revocable"))
	ctx := context.Background()

	// Nothing bound at all: the desired state already holds.
	result, err := svc.Unbind(ctx, "usr_1", game, sourceName)
	if err != nil {
		t.Fatal(err)
	}
	if result.Upstream != RevocationNothingToDo {
		t.Fatalf("upstream = %q, want nothing", result.Upstream)
	}
	if calls := rec.calls(); len(calls) != 0 {
		t.Fatalf("revoked something that was never bound: %v", calls)
	}

	connect(t, svc, "usr_1")
	for i := 0; i < 2; i++ {
		if _, err := svc.Unbind(ctx, "usr_1", game, sourceName); err != nil {
			t.Fatalf("unbind %d: %v", i+1, err)
		}
	}
	// The second call had nothing to do, so the source was asked exactly once.
	if calls := rec.calls(); len(calls) != 1 {
		t.Fatalf("upstream revocations = %v, want one", calls)
	}
}

func TestUnbindRejectsBadInput(t *testing.T) {
	rec := &releasingSource{}
	up := newReleasingSource(t, rec)
	svc, _, _ := unbindService(t, unbindSource(up.URL, "revocable"))
	ctx := context.Background()

	if _, err := svc.Unbind(ctx, "usr_1", game, "nope"); err == nil {
		t.Error("Unbind accepted an unknown source")
	}
	for _, tc := range []struct{ user, game, source string }{
		{"", game, sourceName},
		{"usr_1", "", sourceName},
		{"usr_1", game, ""},
	} {
		if _, err := svc.Unbind(ctx, account.UserID(tc.user), tc.game, tc.source); err == nil {
			t.Errorf("Unbind accepted %+v", tc)
		}
	}
}

// The revocation endpoint is derived from the issuer like the other two, so a
// deployment that runs a source under a different layout can still point at it.
func TestRevocationEndpointDefaultsAndOverrides(t *testing.T) {
	reg, err := NewRegistry(Source{Game: "g", Name: "s", Issuer: "https://src.example/"})
	if err != nil {
		t.Fatal(err)
	}
	src, _ := reg.Get("g", "s")
	if src.RevocationEndpoint != "https://src.example/oauth/revoke" {
		t.Fatalf("revocation endpoint = %q", src.RevocationEndpoint)
	}

	reg, err = NewRegistry(Source{
		Game: "g", Name: "s", Issuer: "https://src.example",
		RevocationEndpoint: "https://src.example/api/1/revoke",
	})
	if err != nil {
		t.Fatal(err)
	}
	if src, _ := reg.Get("g", "s"); src.RevocationEndpoint != "https://src.example/api/1/revoke" {
		t.Fatalf("override ignored: %q", src.RevocationEndpoint)
	}
}
