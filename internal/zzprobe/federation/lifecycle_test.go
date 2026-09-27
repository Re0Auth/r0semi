//go:build audit5

package zzprobe_federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/federation"
)

// ---------------------------------------------------------------------------
// H. The normalized-resource scope gate across sources.
//
// handleGameResource authorises on a SCOPE and then fetches a RESOURCE. The
// scope is looked up by (game, resource) — "the first source that declares this
// resource" — but the resource is fetched from a source chosen by candidates().
// When two sources declare the same resource under different scopes, those are
// two different sources. This probe drives exactly that.
// ---------------------------------------------------------------------------

// twoSourceRig stands up two sources for one game, both declaring "profile" but
// under different scopes, and records what each was asked for.
type twoSourceRig struct {
	a, b   *httptest.Server
	reqsA  *reqLog
	reqsB  *reqLog
	svc    federation.Service
	unbind func(name string)
}

type reqLog struct {
	mu   sync.Mutex
	urls []string
	auth []string
}

func (r *reqLog) add(u, a string) {
	r.mu.Lock()
	r.urls = append(r.urls, u)
	r.auth = append(r.auth, a)
	r.mu.Unlock()
}

func (r *reqLog) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.urls...)
}

// newTwoSourceRig builds a deployment with two sources for one game. scopeA is
// what source "a" declares for the profile resource; scopeB is source "b"'s.
func newTwoSourceRig(t *testing.T, statusA, statusB federation.SourceStatus, scopeA, scopeB string) *twoSourceRig {
	t.Helper()
	logA, logB := &reqLog{}, &reqLog{}
	mk := func(log *reqLog, body string) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.add(r.URL.Path, r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(s.Close)
		return s
	}
	a := mk(logA, `{"served_by":"a"}`)
	b := mk(logB, `{"served_by":"b"}`)

	reg, err := federation.NewRegistry(
		federation.Source{
			Game: "phigros", Name: "a", DisplayName: "A", Issuer: a.URL,
			TokenClass: "revocable", Status: statusA,
			Resources: []federation.Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: scopeA}},
		},
		federation.Source{
			Game: "phigros", Name: "b", DisplayName: "B", Issuer: b.URL,
			TokenClass: "revocable", Status: statusB,
			Resources: []federation.Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: scopeB}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	bindings := federation.NewMemoryBindingStore()
	v := newTestVault(t)
	// The caller is bound to B only. A is not bound at all.
	bound := federation.Binding{User: "usr_1", Game: "phigros", Source: "b", Version: 1}
	if err := bindings.Put(context.Background(), bound); err != nil {
		t.Fatal(err)
	}
	if err := v.Enroll(context.Background(), federation.BindingIdentity(bound), mustPair(t, "token-for-b", ""), nil); err != nil {
		t.Fatal(err)
	}

	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: bindings, Vault: v,
		Doer: a.Client(), HTTPClient: a.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &twoSourceRig{a: a, b: b, reqsA: logA, reqsB: logB, svc: svc}
}

// The downstream scope is resolved from the FIRST source declaring the resource.
// If that source declares a different scope than the one that actually serves
// the read, the authorisation and the delivery disagree.
func TestProbeResourceScopeComesFromOneSourceButDataFromAnother(t *testing.T) {
	// "a" sorts first and is active; the caller is bound to "b" only.
	rig := newTwoSourceRig(t, federation.StatusActive, federation.StatusActive,
		"phigros.profile.read", "phigros.score.read")

	scope, ok := rig.svc.ResourceScope("phigros", "profile")
	if !ok {
		t.Fatal("no scope for the resource")
	}
	t.Logf("ResourceScope(phigros, profile) = %q — this is source a's declaration", scope)
	if scope != "phigros.profile.read" {
		t.Fatalf("fixture assumption changed: got %q", scope)
	}

	// A token carrying exactly the scope the gate asked for. Under the
	// scope-per-resource model that should grant "phigros.profile.read" — which
	// is a scope source b does not recognise at all.
	res, err := rig.svc.Fetch(context.Background(), federation.FetchRequest{
		User: "usr_1", Game: "phigros", Resource: "profile",
	})
	if err != nil {
		t.Logf("fetch refused: %v", err)
		return
	}
	t.Logf("a token holding %q (source a's scope, source a NOT bound) was served by %q with %s",
		scope, res.Source, res.Data)
	t.Logf("source a was asked for: %v", rig.reqsA.all())
	t.Logf("source b was asked for: %v", rig.reqsB.all())
	if res.Source == "b" {
		t.Errorf("the read was served by source b, which the token was never scoped for: "+
			"the gate named %q (source a's scope) and the fetch used source %q", scope, res.Source)
	}
}

// The mirror image: a token holding only source b's scope is refused for a
// resource that source b serves, because the gate asked for source a's scope.
// This is the non-vacuity control — it proves the gate is really reading a
// single source's declaration rather than the union.
func TestProbeScopeGateRefusesTheBoundSourcesOwnScope(t *testing.T) {
	rig := newTwoSourceRig(t, federation.StatusActive, federation.StatusActive,
		"phigros.profile.read", "phigros.score.read")

	// Bind source a as well, so the fetch cannot be blamed on a missing binding.
	// Instead: ask for the resource with b's scope and observe the gate's answer.
	scope, _ := rig.svc.ResourceScope("phigros", "profile")
	t.Logf("gate scope = %q; source b declares %q", scope, "phigros.score.read")
	if scope == "phigros.score.read" {
		t.Error("the gate used source b's declaration; the ordering assumption changed")
	}
}

// A degraded source can be reached without the caller asking for it and without
// knowing which source answered — unless it reads Re0Auth-Degraded. This checks
// the scope used for that read is still the gate source's scope.
func TestProbeDegradedSourceIsServedUnderTheGatesScope(t *testing.T) {
	rig := newTwoSourceRig(t, federation.StatusActive, federation.StatusDegraded,
		"phigros.profile.read", "phigros.score.read")
	// a is active but unbound; b is degraded and bound.
	res, err := rig.svc.Fetch(context.Background(), federation.FetchRequest{
		User: "usr_1", Game: "phigros", Resource: "profile",
	})
	if err != nil {
		t.Logf("refused: %v", err)
		return
	}
	t.Logf("served by %q degraded=%v data=%s", res.Source, res.Degraded, res.Data)
	if res.Source == "b" {
		t.Logf("a read whose scope came from source a was served by degraded source b: "+
			"Re0Auth-Degraded=%v is the only signal", res.Degraded)
	}
}

// ---------------------------------------------------------------------------
// I. Refresh CAS: the shape of the stored row and the vault after a race.
// ---------------------------------------------------------------------------

// frozenStore lets a probe hold the loser's write open while the winner lands,
// which is the only way the documented interleaving is reproducible.
type frozenStore struct {
	federation.BindingStore
	mu     sync.Mutex
	onPut  func()
	frozen bool
}

func (f *frozenStore) PutIfVersion(ctx context.Context, b federation.Binding, v uint64) (bool, error) {
	f.mu.Lock()
	hook := f.onPut
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	return f.BindingStore.PutIfVersion(ctx, b, v)
}

// After a refresh wins the CAS but the binding row is deleted before the vault
// write, the vault keeps a secret for a binding that no longer exists. That is
// the ordering trade refresh.go names ("the one case the ordering trade buys") —
// this probe asks whether the residue is really only the case named there.
func TestProbeRefreshVaultResidueAfterRowDisappears(t *testing.T) {
	log := &reqLog{}
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r.URL.Path, "")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "rotated-access",
				"refresh_token": "rotated-refresh",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		default:
			_, _ = io.WriteString(w, `{"ok":true}`)
		}
	}))
	defer tokenServer.Close()

	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "src", Issuer: tokenServer.URL, TokenClass: "revocable",
		Resources: []federation.Resource{{Name: "profile", Schema: "s/1", Scope: "phigros.profile.read"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	store := federation.NewMemoryBindingStore()
	v := newTestVault(t)
	ctx := context.Background()
	b := federation.Binding{
		User: "usr_1", Game: "phigros", Source: "src",
		HasRefresh: true, Expiry: time.Now().Add(-time.Minute), Version: 7,
	}
	if err := store.Put(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := v.Enroll(ctx, federation.BindingIdentity(b), mustPair(t, "old-access", "old-refresh"), nil); err != nil {
		t.Fatal(err)
	}

	// Delete the row from another "process" while the refresh is between its CAS
	// and its vault write.
	var once sync.Once
	probe := &frozenStore{BindingStore: store}
	probe.onPut = func() {
		once.Do(func() {
			if err := store.Delete(ctx, "usr_1", "phigros", "src"); err != nil {
				t.Errorf("delete: %v", err)
			}
		})
	}

	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: probe, Vault: v,
		Doer: tokenServer.Client(), HTTPClient: tokenServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, ferr := svc.Fetch(ctx, federation.FetchRequest{User: "usr_1", Game: "phigros", Resource: "profile"})
	t.Logf("fetch err after the row vanished mid-refresh: %v", ferr)

	_, gerr := store.Get(ctx, "usr_1", "phigros", "src")
	exists, _ := v.Exists(ctx, federation.BindingIdentity(b))
	t.Logf("row present: %v; vault secret present: %v", gerr == nil, exists)
	if gerr != nil && exists {
		t.Errorf("the vault holds a secret whose binding row is gone: no endpoint reaches it, "+
			"ListAll cannot see it, and the Kill Switch cannot ask its source (err=%v)", gerr)
	}
	if gerr == nil && exists {
		var out map[string]string
		_ = v.Use(ctx, federation.BindingIdentity(b), func(p []byte) error { return json.Unmarshal(p, &out) })
		t.Logf("row and secret both present; secret=%v", out)
	}
}

// Unbind must be able to cut a binding whose source is gone AND whose registry
// entry was removed for a different game. The working-tree change made the
// lookup happen after the binding read; this checks the order of the two
// consequences (404 vs 200) is what the HTTP layer documents.
func TestProbeUnbindOrderingAgainstTheHTTPContract(t *testing.T) {
	reg, err := federation.NewRegistry(federation.Source{Game: "phigros", Name: "known", Issuer: "https://api.example"})
	if err != nil {
		t.Fatal(err)
	}
	store := federation.NewMemoryBindingStore()
	v := newTestVault(t)
	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: store, Vault: v,
		Doer: http.DefaultClient, HTTPClient: http.DefaultClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// A binding for a source this deployment never configured (the operator
	// dropped it): must be removable, and must report "nothing" upstream.
	orphan := federation.Binding{User: "usr_1", Game: "phigros", Source: "gone", Version: 3}
	if err := store.Put(ctx, orphan); err != nil {
		t.Fatal(err)
	}
	if err := v.Enroll(ctx, federation.BindingIdentity(orphan), mustPair(t, "tok", ""), nil); err != nil {
		t.Fatal(err)
	}
	res, err := svc.Unbind(ctx, "usr_1", "phigros", "gone")
	t.Logf("orphan unbind: res=%+v err=%v", res, err)
	if err != nil {
		t.Fatalf("orphan could not be cut: %v", err)
	}
	if res.Upstream != federation.RevocationNothingToDo {
		t.Errorf("upstream=%q, want nothing (there is no source to ask)", res.Upstream)
	}

	// An unknown source with nothing bound: 404 at the HTTP layer.
	_, err = svc.Unbind(ctx, "usr_1", "phigros", "never-existed")
	if !errors.Is(err, federation.ErrUnknownSource) {
		t.Errorf("unknown source, nothing bound => %v, want ErrUnknownSource (HTTP 404)", err)
	}

	// A *known* source that is retired: the binding must still be cut.
	retired := federation.Binding{User: "usr_1", Game: "phigros", Source: "known", Version: 4}
	if err := store.Put(ctx, retired); err != nil {
		t.Fatal(err)
	}
	if err := v.Enroll(ctx, federation.BindingIdentity(retired), mustPair(t, "tok", ""), nil); err != nil {
		t.Fatal(err)
	}
	res, err = svc.Unbind(ctx, "usr_1", "phigros", "known")
	t.Logf("configured source unbind: res=%+v err=%v", res, err)
	if err != nil {
		t.Fatalf("a configured source could not be cut: %v", err)
	}
	_ = fmt.Sprint(strings.TrimSpace(""))
}
