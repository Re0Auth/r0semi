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
// layer: the scope the gate names and the source that answers come from two
// different lookups.
func TestVerifyGateAndServingSourceAreIndependent(t *testing.T) {
	rig := newTwoSourceRig(t, federation.StatusActive, federation.StatusActive,
		"phigros.profile.read", "phigros.community.read", "b")

	gateScope, ok := rig.svc.ResourceScope("phigros", "profile")
	if !ok {
		t.Fatal("no scope for the resource")
	}
	res, err := rig.svc.Fetch(context.Background(), federation.FetchRequest{
		User: "usr_1", Game: "phigros", Resource: "profile",
	})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	a, b := rig.requests()
	t.Logf("gate names %q (source a's declaration); the read came from %q with %s", gateScope, res.Source, res.Data)
	t.Logf("source a was asked for %v; source b was asked for %v", a, b)

	if gateScope != rig.scopeA {
		t.Fatalf("fixture: the gate did not resolve from source a (%q)", gateScope)
	}
	if res.Source != "b" {
		t.Fatalf("fixture: expected source b to serve, got %q", res.Source)
	}
	// The gate is a signature fact: ResourceScope cannot be source-aware because
	// it takes no source.
	var sig func(string, string) (string, bool) = rig.svc.ResourceScope
	_ = sig
	t.Logf("Service.ResourceScope(game, resource) has no source parameter, so the gate cannot name the source it is gating")

	// The mirror image: source b's own declared scope does NOT admit the read.
	if gateScope == rig.scopeB {
		t.Error("fixture: the two sources must declare different scopes for this test to mean anything")
	}
}

// TestVerifyConsentPlaneNamesASourceTheReadDoesNotNeed is the crux the audit
// never checked: what the consent screen tells the user, versus what the data
// plane will actually do.
func TestVerifyConsentPlaneNamesASourceTheReadDoesNotNeed(t *testing.T) {
	rig := newTwoSourceRig(t, federation.StatusActive, federation.StatusActive,
		"phigros.profile.read", "phigros.community.read", "b")
	ctx := context.Background()

	// What the consent screen asks for when the downstream requests source a's scope.
	reqs, err := rig.svc.MissingBindings(ctx, "usr_1", []string{rig.scopeA})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("MissingBindings(for %q) = %+v", rig.scopeA, reqs)
	for _, r := range reqs {
		t.Logf("  consent screen says: connect %q (%s) to serve %v", r.Source, r.DisplayName, r.Scopes)
	}
	if len(reqs) == 0 || reqs[0].Source != "a" {
		t.Fatalf("fixture: expected a binding prompt for source a, got %+v", reqs)
	}

	// What the read actually does, with source a NOT bound.
	res, err := rig.svc.Fetch(ctx, federation.FetchRequest{User: "usr_1", Game: "phigros", Resource: "profile"})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	t.Logf("the same read, with source a unbound, is served by %q: %s", res.Source, res.Data)

	// And for the community scope the data plane will actually use, the consent
	// screen reports nothing missing at all.
	reqs2, err := rig.svc.MissingBindings(ctx, "usr_1", []string{rig.scopeB})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("MissingBindings(for %q) = %+v (the source that will serve it is already bound)", rig.scopeB, reqs2)
	if len(reqs2) != 0 {
		t.Errorf("fixture: %q should already be servable through the connected source", rig.scopeB)
	}

	// The two planes therefore disagree: the advisory plane's model is
	// "a scope is servable when a source declaring THAT SCOPE is connected", the
	// enforcement plane's model is "a resource is servable when any source
	// declaring THAT RESOURCE NAME is connected".
	if len(reqs) > 0 && len(reqs2) == 0 {
		t.Logf("consent plane and data plane disagree: one prompts for a source the read does not need, " +
			"the other serves from a source the prompt never names")
	}
}

// TestVerifyRetiredSourceCanSetTheGate is a case the audit did not report: the
// gate's requirement can be resolved from a source that is retired, and retired
// sources are never selectable.
func TestVerifyRetiredSourceCanSetTheGate(t *testing.T) {
	rig := newTwoSourceRig(t, federation.StatusRetired, federation.StatusActive,
		"phigros.profile.read", "phigros.community.read", "b")

	gateScope, ok := rig.svc.ResourceScope("phigros", "profile")
	if !ok {
		t.Fatal("no scope for the resource")
	}
	res, err := rig.svc.Fetch(context.Background(), federation.FetchRequest{
		User: "usr_1", Game: "phigros", Resource: "profile",
	})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	t.Logf("source a is RETIRED and declares %q; the gate still requires it, and the read is served by %q",
		gateScope, res.Source)
	if gateScope != rig.scopeA || res.Source != "b" {
		t.Fatalf("fixture: got gate=%q served=%q", gateScope, res.Source)
	}
}

// TestVerifyConsistentScopesCollapseTheDivergence states the condition the whole
// finding rests on, so the severity claim is auditable: when the operator declares
// the SAME scope for the same resource name on both sources, the gate's answer is
// the serving source's answer.
func TestVerifyConsistentScopesCollapseTheDivergence(t *testing.T) {
	rig := newTwoSourceRig(t, federation.StatusActive, federation.StatusActive,
		"phigros.profile.read", "phigros.profile.read", "b")
	gateScope, _ := rig.svc.ResourceScope("phigros", "profile")
	res, err := rig.svc.Fetch(context.Background(), federation.FetchRequest{
		User: "usr_1", Game: "phigros", Resource: "profile",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("both sources declare %q; gate=%q served-by=%q", rig.scopeB, gateScope, res.Source)
	if gateScope != rig.scopeB {
		t.Errorf("fixture: with identical declarations the gate and the source must agree, got %q", gateScope)
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
