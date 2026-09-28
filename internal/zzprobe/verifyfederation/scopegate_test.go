//go:build audit5

package zzprobe_verifyfederation

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/federation"
)

// twoSourceRig is a deployment with two sources for one game, each declaring the
// same resource name. The caller is bound to the SECOND one only.
type twoSourceRig struct {
	svc      federation.Service
	logA     *[]string
	logB     *[]string
	scopeA   string
	scopeB   string
	statusA  federation.SourceStatus
	statusB  federation.SourceStatus
	boundTo  string
	requests func() (a, b []string)
}

func newTwoSourceRig(t *testing.T, statusA, statusB federation.SourceStatus, scopeA, scopeB, boundTo string) *twoSourceRig {
	t.Helper()
	logA, logB := &[]string{}, &[]string{}
	a := recordingServer(t, logA, `{"served_by":"a"}`)
	b := recordingServer(t, logB, `{"served_by":"b"}`)

	reg, err := federation.NewRegistry(
		federation.Source{
			Game: "phigros", Name: "a", DisplayName: "A", Issuer: a.URL,
			TokenClass: "revocable", Status: statusA, ClientID: "cli",
			Resources: []federation.Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: scopeA}},
		},
		federation.Source{
			Game: "phigros", Name: "b", DisplayName: "B", Issuer: b.URL,
			TokenClass: "revocable", Status: statusB, ClientID: "cli",
			Resources: []federation.Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: scopeB}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	store := federation.NewMemoryBindingStore()
	v := newTestVault(t)
	bound := federation.Binding{User: "usr_1", Game: "phigros", Source: boundTo, Version: 1}
	if err := store.Put(context.Background(), bound); err != nil {
		t.Fatal(err)
	}
	if err := v.Enroll(context.Background(), federation.BindingIdentity(bound), mustPair(t, "token-b", ""), nil); err != nil {
		t.Fatal(err)
	}
	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: store, Vault: v,
		Doer: a.Client(), HTTPClient: a.Client(), BaseURL: "https://re0auth.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &twoSourceRig{
		svc: svc, logA: logA, logB: logB,
		scopeA: scopeA, scopeB: scopeB, statusA: statusA, statusB: statusB, boundTo: boundTo,
		requests: func() ([]string, []string) { return *logA, *logB },
	}
}

// TestVerifyGateAndServingSourceAreIndependent re-derives FO-01 from the service
// layer, asserted as the property the fix provides: the requirements name EVERY
// source that could serve the read, so whichever one answers, its scope was
// required. The old accessor named source a's scope while source b served, and
// there was nothing in its signature that could have said otherwise.
func TestVerifyGateAndServingSourceAreIndependent(t *testing.T) {
	rig := newTwoSourceRig(t, federation.StatusActive, federation.StatusActive,
		"phigros.profile.read", "phigros.community.read", "b")

	reqs, err := rig.svc.ResourceRequirements("phigros", "profile", "")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]string{}
	for _, r := range reqs {
		byName[r.Source] = r.Scope
	}
	res, err := rig.svc.Fetch(context.Background(), federation.FetchRequest{
		User: "usr_1", Game: "phigros", Resource: "profile",
	})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	a, b := rig.requests()
	t.Logf("the gate requires %+v; the read came from %q with %s", reqs, res.Source, res.Data)
	t.Logf("source a was asked for %v; source b was asked for %v", a, b)

	if res.Source != "b" {
		t.Fatalf("fixture: expected source b to serve, got %q", res.Source)
	}
	// The property: the serving source is one the gate named. Source b's own scope
	// is required now, which is the direction that used to be refused.
	if byName["b"] != rig.scopeB {
		t.Errorf("the serving source %q is not among the gate's requirements: %+v", res.Source, reqs)
	}
	if byName["a"] != rig.scopeA {
		t.Errorf("the gate dropped source a's requirement: %+v", reqs)
	}
	if rig.scopeA == rig.scopeB {
		t.Error("fixture: the two sources must declare different scopes for this test to mean anything")
	}
}

// TestVerifyConsentPlaneAndDataPlaneAgree (FIXED) is the crux the audit never
// checked: what the consent screen tells the user, versus what the data plane
// will actually do.
//
// Was: the consent plane keyed "satisfied" on the SCOPE ("a source declaring
// phigros.profile.read is connected") while the data plane keys servability on
// the RESOURCE NAME ("any connected source declaring resource `profile`"). With
// two sources declaring `profile` under different scopes, the consent screen
// prompted for a binding the read did not need, and stayed silent for the scope
// the read would actually use.
//
// MissingBindings now uses candidates()' criterion, so the two agree: the read is
// already servable through the connected source and the prompt reports nothing
// missing.
func TestVerifyConsentPlaneAndDataPlaneAgree(t *testing.T) {
	rig := newTwoSourceRig(t, federation.StatusActive, federation.StatusActive,
		"phigros.profile.read", "phigros.community.read", "b")
	ctx := context.Background()

	// What the read does, with source a NOT bound: served by b.
	res, err := rig.svc.Fetch(ctx, federation.FetchRequest{User: "usr_1", Game: "phigros", Resource: "profile"})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if res.Source != "b" {
		t.Fatalf("fixture: expected source b to serve, got %q", res.Source)
	}
	t.Logf("the read is served by %q", res.Source)

	// Neither scope prompts: the resource the read needs is already servable via
	// the connected source, so no binding is missing.
	for _, scope := range []string{rig.scopeA, rig.scopeB} {
		reqs, err := rig.svc.MissingBindings(ctx, "usr_1", []string{scope})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("MissingBindings(for %q) = %+v", scope, reqs)
		if len(reqs) != 0 {
			t.Errorf("the consent plane prompts for a binding the read does not need (scope %q): %+v", scope, reqs)
		}
	}

	// Anti-vacuity: a user with no bindings must still be prompted — the resource
	// is not servable, so the agreement above is not "MissingBindings always
	// returns nothing".
	if reqs, err := rig.svc.MissingBindings(ctx, "usr_unbound", []string{rig.scopeA}); err != nil {
		t.Fatal(err)
	} else if len(reqs) == 0 {
		t.Errorf("with no binding at all, the resource is unservable but the consent plane reports nothing missing")
	}
}

// TestVerifyRetiredSourceCannotSetTheGate is the case the verifier found and the
// audit did not report: a RETIRED source used to set the gate's requirement, and
// retired sources are never selectable — so retiring one source silently changed
// the authorization criterion for another, and could turn a live token into a 403.
//
// The requirements come from candidates() now, which excludes retired sources, so
// the retired declaration is not among them.
func TestVerifyRetiredSourceCannotSetTheGate(t *testing.T) {
	rig := newTwoSourceRig(t, federation.StatusRetired, federation.StatusActive,
		"phigros.profile.read", "phigros.community.read", "b")

	reqs, err := rig.svc.ResourceRequirements("phigros", "profile", "")
	if err != nil {
		t.Fatal(err)
	}
	res, err := rig.svc.Fetch(context.Background(), federation.FetchRequest{
		User: "usr_1", Game: "phigros", Resource: "profile",
	})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	t.Logf("source a is RETIRED and declares %q; the requirements are %+v; the read is served by %q",
		rig.scopeA, reqs, res.Source)

	if res.Source != "b" {
		t.Fatalf("fixture: expected source b to serve, got %q", res.Source)
	}
	for _, r := range reqs {
		if r.Source == "a" {
			t.Errorf("a retired source set the gate's requirement: %+v", reqs)
		}
	}
	if len(reqs) != 1 || reqs[0].Scope != rig.scopeB {
		t.Errorf("requirements = %+v, want only the active source's %q", reqs, rig.scopeB)
	}
}

// TestVerifyConsistentScopesCollapseTheDivergence states the condition the finding
// rested on, now as the property that makes the fix cheap where it should be: when
// the operator declares the SAME scope for the same resource name on both sources,
// the two requirements collapse into one, and a client that already holds that
// scope needs nothing new.
func TestVerifyConsistentScopesCollapseTheDivergence(t *testing.T) {
	rig := newTwoSourceRig(t, federation.StatusActive, federation.StatusActive,
		"phigros.profile.read", "phigros.profile.read", "b")
	reqs, err := rig.svc.ResourceRequirements("phigros", "profile", "")
	if err != nil {
		t.Fatal(err)
	}
	res, err := rig.svc.Fetch(context.Background(), federation.FetchRequest{
		User: "usr_1", Game: "phigros", Resource: "profile",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("both sources declare %q; requirements=%+v served-by=%q", rig.scopeB, reqs, res.Source)
	if len(reqs) != 1 || reqs[0].Scope != rig.scopeB {
		t.Errorf("requirements = %+v, want one entry for %q: identical declarations must not "+
			"make a client hold the same scope twice", reqs, rig.scopeB)
	}
}

// TestVerifyCollidingSourceKeyHasNoRequestPath executes the aliasing FO-04 raises
// as a "键空间可碰撞" hole. The key is collidable, but the game lookup happens
// first, so a request that would alias cannot reach the aliased source.
func TestVerifyCollidingSourceKeyHasNoRequestPath(t *testing.T) {
	log := &[]string{}
	srv := recordingServer(t, log, `{"served_by":"aliased"}`)
	reg, err := federation.NewRegistry(federation.Source{
		Game: "../..", Name: "src", Issuer: srv.URL, TokenClass: "revocable",
		Resources: []federation.Resource{{Name: "profile", Scope: "x.y.read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The pair the audit says aliases to the same key.
	aliased, ok := reg.Get("..", "../src")
	t.Logf(`registry.Get("..", "../src") -> ok=%v name=%q game=%q (sourceKey %q)`,
		ok, aliased.Name, aliased.Game, aliased.Game+"/"+aliased.Name)

	store := federation.NewMemoryBindingStore()
	v := newTestVault(t)
	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: store, Vault: v, Doer: srv.Client(), HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, ferr := svc.Fetch(context.Background(), federation.FetchRequest{
		User: "usr_1", Game: "..", Resource: "profile", Source: "../src",
	})
	t.Logf(`Fetch(game="..", source="../src") -> %v`, ferr)
	if ferr == nil {
		t.Errorf("the aliased pair reached a source: %v", ferr)
	}

	// Two entries that collide are rejected at startup rather than silently
	// sharing a key.
	_, err = federation.NewRegistry(
		federation.Source{Game: "../..", Name: "src", Issuer: "https://a.example"},
		federation.Source{Game: "..", Name: "../src", Issuer: "https://b.example"},
	)
	t.Logf("registering both colliding pairs -> %v", err)
	if err == nil {
		t.Errorf("a key collision was accepted")
	}
}

// TestVerifyDeclaredScopeReachesTheWireWithInjectedSpaces executes FO-04's scope
// claim through production code (BeginBind -> oauthConfig -> AuthCodeURL) rather
// than re-reading the fixture, which is all the reported probe does.
func TestVerifyDeclaredScopeReachesTheWireWithInjectedSpaces(t *testing.T) {
	srv := recordingServer(t, nil, `{}`)
	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "src", Issuer: srv.URL, TokenClass: "revocable", ClientID: "cli",
		Resources: []federation.Resource{
			{Name: "profile", Scope: "phigros.profile.read account.id"},
			{Name: "scores", Scope: "phigros.score.read"},
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	store := federation.NewMemoryBindingStore()
	v := newTestVault(t)
	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: store, Vault: v, Doer: srv.Client(), HTTPClient: srv.Client(),
		BaseURL: "https://re0auth.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	ch, err := svc.BeginBind(context.Background(), "usr_1", "phigros", "src", "/app")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(ch.AuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	raw := u.Query().Get("scope")
	t.Logf("authorize URL scope parameter = %q", raw)
	t.Logf("the source is asked for %d scope(s): %v", len(strings.Fields(raw)), strings.Fields(raw))
	if len(strings.Fields(raw)) != 4 {
		t.Errorf("expected the injected space to add one scope on the wire (4 total), got %v", strings.Fields(raw))
	}
	if !strings.Contains(raw, "account.id") {
		t.Errorf("the injected scope did not reach the wire: %q", raw)
	}
}

// TestVerifySourceNameShapesReachTheRedirectURI executes FO-04's redirect claim
// the same way.
func TestVerifySourceNameShapesReachTheRedirectURI(t *testing.T) {
	srv := recordingServer(t, nil, `{}`)
	for _, name := range []string{"src", "../evil", "src?x=1", "src#f", "src/../other"} {
		reg, err := federation.NewRegistry(federation.Source{
			Game: "phigros", Name: name, Issuer: srv.URL, TokenClass: "revocable", ClientID: "cli",
			Resources: []federation.Resource{{Name: "profile", Scope: "phigros.profile.read"}},
		})
		if err != nil {
			t.Logf("name=%q -> registry refused: %v", name, err)
			continue
		}
		store := federation.NewMemoryBindingStore()
		v := newTestVault(t)
		svc, err := federation.NewService(federation.Config{
			Registry: reg, Bindings: store, Vault: v, Doer: srv.Client(), HTTPClient: srv.Client(),
			BaseURL: "https://re0auth.example",
		})
		if err != nil {
			t.Fatal(err)
		}
		ch, err := svc.BeginBind(context.Background(), "usr_1", "phigros", name, "/app")
		if err != nil {
			t.Logf("name=%q -> BeginBind refused: %v", name, err)
			continue
		}
		u, _ := url.Parse(ch.AuthorizeURL)
		ru := u.Query().Get("redirect_uri")
		parsed, perr := url.Parse(ru)
		effective := ru
		if perr == nil {
			effective = parsed.Scheme + "://" + parsed.Host + parsed.Path
		}
		t.Logf("name=%-14q -> redirect_uri param=%q ; what a URL parser makes of it: %q", name, ru, effective)
	}
}
