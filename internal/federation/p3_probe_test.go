package federation

// P3 probes for S05-3, S05-4, S05-5, S05-6, S05-7, S05-8, S06-9 and S14-4.
//
// Each probe was written to be RED against the code before its fix and GREEN
// after, and none of them may be satisfied by asserting something that is true
// for an unrelated reason: every probe carries an anti-vacuity check (the
// control path, the logged line, the surviving diagnostic) next to the property
// it pins.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/httpclient"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/vault"
)

// ---------------------------------------------------------------------------
// S05-3 / S14-4: the memory binding store's per-account listing
// ---------------------------------------------------------------------------

// p3StoreWithOtherAccounts fills a store with rows the probe does not read, then
// returns the store and the number of rows it holds in total.
func p3StoreWithOtherAccounts(t *testing.T, others int) (*MemoryBindingStore, int) {
	t.Helper()
	store := NewMemoryBindingStore()
	ctx := context.Background()
	for i := 0; i < others; i++ {
		b := Binding{
			User:   account.UserID(fmt.Sprintf("usr_other_%04d", i)),
			Game:   fmt.Sprintf("game_%d", i%3),
			Source: fmt.Sprintf("src_%d", i%7),
		}
		if err := store.Put(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	// The account under test holds three bindings, declared out of order so the
	// probe also pins that List returns them in (game, source) order.
	for _, b := range []Binding{
		{User: "usr_me", Game: "b", Source: "s"},
		{User: "usr_me", Game: "a", Source: "z"},
		{User: "usr_me", Game: "a", Source: "m"},
	} {
		if err := store.Put(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	all, err := store.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return store, len(all)
}

// TestP3S05_3ListAllocatesForOneAccountNotTheDeployment: List used to size its
// result with the WHOLE deployment (make(..., len(s.m))), so one account page
// allocated a slice for every binding in the system. The result's capacity is the
// observable: it must follow the account, not the table.
func TestP3S05_3ListAllocatesForOneAccountNotTheDeployment(t *testing.T) {
	store, total := p3StoreWithOtherAccounts(t, 500)
	if total <= 500 {
		t.Fatalf("fixture holds %d rows, want more than the 500 other-account rows: the probe is not discriminating", total)
	}

	got, err := store.List(context.Background(), "usr_me")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("List returned %d bindings, want 3", len(got))
	}
	if cap(got) != 3 {
		t.Errorf("List allocated capacity %d for a 3-binding account in a %d-binding deployment: "+
			"the result is sized for the whole table", cap(got), total)
	}
	// Order is part of the contract; keep it pinned while the index changes.
	if got[0].Game != "a" || got[0].Source != "m" || got[1].Source != "z" || got[2].Game != "b" {
		t.Errorf("List order = %v, want (a,m), (a,z), (b,s)", []string{
			got[0].Game + "/" + got[0].Source, got[1].Game + "/" + got[1].Source, got[2].Game + "/" + got[2].Source,
		})
	}
}

// TestP3S14_4ListWalksOnlyTheAccountsIndex: List used to filter the deployment's
// whole ordered index under the read lock, so an account page paid for every other
// account. listScanned counts the index entries List walks; an account page must
// walk its own and nothing else.
func TestP3S14_4ListWalksOnlyTheAccountsIndex(t *testing.T) {
	store, total := p3StoreWithOtherAccounts(t, 2000)
	if total <= 2000 {
		t.Fatalf("fixture holds %d rows, want more than the 2000 other-account rows", total)
	}

	store.listScanned.Store(0)
	got, err := store.List(context.Background(), "usr_me")
	if err != nil {
		t.Fatal(err)
	}
	scanned := store.listScanned.Load()
	if scanned != int64(len(got)) {
		t.Errorf("List walked %d index entries for an account holding %d bindings in a %d-binding "+
			"deployment: the account page is scanning the whole table", scanned, len(got), total)
	}
}

// Deleting a binding must take it out of the per-account index too, or the index
// would hand List a key with no row. The invariant List relies on -- every index
// key names a live row -- is checked here, and the two probes above would pass a
// store that leaked keys.
func TestP3S14_4DeleteKeepsThePerAccountIndexConsistent(t *testing.T) {
	store := NewMemoryBindingStore()
	ctx := context.Background()
	for _, b := range []Binding{
		{User: "usr_me", Game: "a", Source: "one"},
		{User: "usr_me", Game: "a", Source: "two"},
		{User: "usr_other", Game: "a", Source: "one"},
	} {
		if err := store.Put(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Delete(ctx, "usr_me", "a", "one"); err != nil {
		t.Fatal(err)
	}
	got, err := store.List(ctx, "usr_me")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Source != "two" {
		t.Fatalf("after Delete, List = %+v, want only (a,two)", got)
	}
	// Re-inserting the deleted key must land in order and be visible again.
	if err := store.Put(ctx, Binding{User: "usr_me", Game: "a", Source: "one"}); err != nil {
		t.Fatal(err)
	}
	got, err = store.List(ctx, "usr_me")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Source != "one" || got[1].Source != "two" {
		t.Fatalf("after re-Put, List = %+v, want (a,one), (a,two)", got)
	}
	if all, err := store.ListAll(ctx); err != nil || len(all) != 3 {
		t.Fatalf("ListAll = %d rows (err %v), want 3: the indexes disagree", len(all), err)
	}
}

// ---------------------------------------------------------------------------
// S05-4: MissingBindings' candidate lookup
// ---------------------------------------------------------------------------

// TestP3S05_4MissingBindingsDoesNotRebuildTheGamePerResource: the old inner
// lookup called registry.Sources(src.Game) for every (source, resource) pair,
// copying and sorting a whole game each time -- O((sources x resources)^2).
// sourcesCopied counts the Source values copied out, so one walk of the game is
// allowed and one copy per pair (n*m*n values) is not.
func TestP3S05_4MissingBindingsDoesNotRebuildTheGamePerResource(t *testing.T) {
	const (
		numSources   = 40
		numResources = 10
	)
	sources := make([]Source, 0, numSources)
	for i := 0; i < numSources; i++ {
		resources := make([]Resource, 0, numResources)
		for j := 0; j < numResources; j++ {
			resources = append(resources, Resource{
				Name: fmt.Sprintf("r%02d", j), Schema: "re0auth.probe/1", Scope: profileScope,
			})
		}
		sources = append(sources, Source{
			Game: game, Name: fmt.Sprintf("s%02d", i), DisplayName: fmt.Sprintf("s%02d", i),
			Issuer: fmt.Sprintf("https://s%02d.example", i), Resources: resources,
		})
	}
	reg, err := NewRegistry(sources...)
	if err != nil {
		t.Fatal(err)
	}
	b := backend{store: NewMemoryBindingStore(), vault: newVault(t)}
	svc := mustService(t, Config{Registry: reg, Doer: nopDoer{}}, b)

	reg.sourcesCopied.Store(0)
	reqs, err := svc.MissingBindings(context.Background(), "usr_1", []string{profileScope})
	if err != nil {
		t.Fatal(err)
	}
	// Anti-vacuity: the candidates really were enumerated and one requirement
	// came out, so a MissingBindings that returned early would not pass.
	if len(reqs) != 1 || reqs[0].Source != "s00" {
		t.Fatalf("requirements = %+v, want one requirement naming s00", reqs)
	}

	copied := reg.sourcesCopied.Load()
	if copied > int64(numSources) {
		t.Errorf("MissingBindings copied %d Source values for %d sources x %d resources; one walk of the "+
			"game is %d. The candidate lookup is rebuilding (and re-sorting) the game per resource declaration",
			copied, numSources, numResources, numSources)
	}
}

// ---------------------------------------------------------------------------
// S05-5: the lifecycle vocabulary is a gate, not a suggestion
// ---------------------------------------------------------------------------

// TestP3S05_5StatusOutsideTheVocabularyIsRefused: statusRank's default branch
// reads an unknown status as selectable, so a typo like "retierd" keeps a source
// in service and keeps it deciding another source's scope gate. The vocabulary is
// active|degraded|retired; anything else must fail at NewRegistry.
func TestP3S05_5StatusOutsideTheVocabularyIsRefused(t *testing.T) {
	for _, status := range []SourceStatus{"retierd", "Retired", "RETIRED", "disabled", "off", "active "} {
		_, err := NewRegistry(Source{Game: game, Name: "src", Issuer: "https://src.example", Status: status})
		if err == nil {
			t.Errorf("NewRegistry accepted status %q; the package would keep answering reads from it", status)
			continue
		}
		if !strings.Contains(err.Error(), "status") {
			t.Errorf("status %q was refused without naming the field: %v", status, err)
		}
	}
	// Anti-vacuity: the legal values are still accepted, and empty is still active.
	for in, want := range map[SourceStatus]SourceStatus{
		"": StatusActive, StatusActive: StatusActive, StatusDegraded: StatusDegraded, StatusRetired: StatusRetired,
	} {
		reg, err := NewRegistry(Source{Game: game, Name: "src", Issuer: "https://src.example", Status: in})
		if err != nil {
			t.Fatalf("NewRegistry refused the in-vocabulary status %q: %v", in, err)
		}
		if got, _ := reg.Get(game, "src"); got.Status != want {
			t.Errorf("status %q resolved to %q, want %q", in, got.Status, want)
		}
	}
}

// ---------------------------------------------------------------------------
// S05-6: the issuer and endpoint overrides are absolute http(s) URLs
// ---------------------------------------------------------------------------

// TestP3S05_6NonAbsoluteEndpointURLsAreRefused: Issuer is the base of every
// request URL and of the authorize redirect; the overrides are used whole. A
// scheme-relative "//evil.example" loads fine and makes the browser redirect name
// another host, and a relative path fails far from the typo.
func TestP3S05_6NonAbsoluteEndpointURLsAreRefused(t *testing.T) {
	cases := []struct {
		name  string
		src   Source
		field string
	}{
		{"scheme-relative issuer", Source{Issuer: "//evil.example"}, "issuer"},
		{"relative issuer", Source{Issuer: "/oauth"}, "issuer"},
		{"host-less issuer", Source{Issuer: "https://"}, "issuer"},
		{"relative token endpoint", Source{Issuer: "https://ok.example", TokenEndpoint: "oauth/token"}, "token_endpoint"},
		{"scheme-relative authorization endpoint",
			Source{Issuer: "https://ok.example", AuthorizationEndpoint: "//evil.example/oauth"}, "authorization_endpoint"},
		{"relative revocation endpoint",
			Source{Issuer: "https://ok.example", RevocationEndpoint: "/revoke"}, "revocation_endpoint"},
		{"relative cascade endpoint",
			Source{Issuer: "https://ok.example", CascadeRevocationEndpoint: "cascade"}, "cascade_revocation_endpoint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.src
			src.Game, src.Name, src.DisplayName = game, "src", "Src"
			_, err := NewRegistry(src)
			if err == nil {
				t.Fatalf("NewRegistry accepted %s %q", tc.field, tc.src)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("the refusal does not name %s, so it is not fixable at startup: %v", tc.field, err)
			}
		})
	}

	// Anti-vacuity: a fully absolute source is still accepted, and the overrides
	// are still used as written.
	reg, err := NewRegistry(Source{
		Game: game, Name: "src", DisplayName: "Src", Issuer: "https://ok.example",
		AuthorizationEndpoint: "https://auth.other.example/authorize",
		TokenEndpoint:         "https://auth.other.example/token",
		RevocationEndpoint:    "https://auth.other.example/revoke",
	})
	if err != nil {
		t.Fatalf("NewRegistry refused a fully absolute source: %v", err)
	}
	src, ok := reg.Get(game, "src")
	if !ok || src.Issuer != "https://ok.example" || src.TokenEndpoint != "https://auth.other.example/token" {
		t.Fatalf("registry rewrote the absolute values: %+v", src)
	}
}

// ---------------------------------------------------------------------------
// S05-7: a retired source cannot be bound
// ---------------------------------------------------------------------------

// TestP3S05_7RetiredSourceCannotBeBound: candidates() and Raw() refuse a retired
// source, but BeginBind and CompleteBind did not, so a new credential could be
// created for a source the operator had taken out of service. Both steps are
// checked, and CompleteBind is checked WITHOUT a live flow: the flow store is
// handed a pending flow directly, which is the only way to model "began while the
// source was live, completed after it was retired".
func TestP3S05_7RetiredSourceCannotBeBound(t *testing.T) {
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Retired", Issuer: "https://retired.example",
		Status: StatusRetired, ClientID: "cid", ClientSecret: "sec",
	})
	if err != nil {
		t.Fatal(err)
	}
	flows := NewMemoryBindFlowStore()
	b := backend{store: NewMemoryBindingStore(), vault: newVault(t)}
	svc := mustService(t, Config{
		Registry: reg, Flows: flows, Doer: nopDoer{}, BaseURL: "https://re0auth.test",
	}, b)

	ctx := context.Background()
	if _, err := svc.BeginBind(ctx, "usr_1", game, sourceName, "/app/sources"); !errors.Is(err, ErrSourceRetired) {
		t.Errorf("BeginBind against a retired source = %v, want ErrSourceRetired", err)
	}

	flow := BindFlow{
		ID: "bnd_probe", User: "usr_1", Game: game, Source: sourceName,
		Verifier: "v", State: "bnd_probe", ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := flows.Put(ctx, flow); err != nil {
		t.Fatal(err)
	}
	before := lenMustList(t, b.store)
	binding, gotFlow, err := svc.CompleteBind(ctx, "usr_1", "bnd_probe", "upstream-code")
	if !errors.Is(err, ErrSourceRetired) {
		t.Errorf("CompleteBind against a retired source = %v, want ErrSourceRetired", err)
	}
	if binding.User != "" {
		t.Errorf("CompleteBind returned binding %+v for a retired source", binding)
	}
	if gotFlow.ID != "bnd_probe" {
		t.Errorf("CompleteBind did not return the consumed flow: %+v", gotFlow)
	}
	if after := lenMustList(t, b.store); after != before {
		t.Errorf("CompleteBind wrote %d binding(s) for a retired source", after-before)
	}
}

// lenMustList counts a store's rows through its own interface.
func lenMustList(t *testing.T, store BindingStore) int {
	t.Helper()
	all, err := store.ListAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return len(all)
}

// ---------------------------------------------------------------------------
// S05-8: the vault failure log does not carry the subject identity
// ---------------------------------------------------------------------------

// TestP3S05_8VaultFailureLogDoesNotCarryTheSubject: vault.Use reports an
// unconfigured KEK by naming the Identity it was asked for, which is
// "provider:subject" -- and revokeUpstream passed that whole error to slog. The
// log line must keep the diagnostic (which key, which operation) and drop the
// person.
func TestP3S05_8VaultFailureLogDoesNotCarryTheSubject(t *testing.T) {
	const subject = "usr_s05_8"

	repo := vault.NewMemoryRepo()
	enrollKey, err := vault.NewLocalKeyWrapper("old", bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	enroller, err := vault.NewService(repo, enrollKey, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{User: subject, Game: game, Source: sourceName, Version: 1}
	if err := enroller.Enroll(context.Background(), BindingIdentity(binding), mustSecret(t, "tok"), nil); err != nil {
		t.Fatal(err)
	}

	// A service configured with a DIFFERENT key id: the record's KEK is not
	// configured, which is the error that embeds the identity.
	otherKey, err := vault.NewLocalKeyWrapper("rotated", bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svcVault, err := vault.NewService(repo, otherKey, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}

	store := NewMemoryBindingStore()
	if err := store.Put(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: "https://src.example",
		TokenClass: tokenClassRevocable,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := mustService(t, Config{Registry: reg, Doer: nopDoer{}}, backend{store: store, vault: svcVault})

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	result, err := svc.Unbind(context.Background(), subject, game, sourceName)
	if err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if result.Upstream != RevocationUnavailable {
		t.Fatalf("Upstream = %q, want %q: the probe did not reach the vault failure",
			result.Upstream, RevocationUnavailable)
	}

	logged := buf.String()
	t.Logf("captured log: %s", logged)
	// Anti-vacuity: the line exists and still names the failure and the record's
	// KEK id, so the redaction did not simply delete the log. (The handler escapes
	// the quotes around the id, so the id is matched as a plain substring.)
	if !strings.Contains(logged, "could not open the binding secret") {
		t.Fatalf("the vault failure was not logged at all: %q", logged)
	}
	if !strings.Contains(logged, "which is not configured") || !strings.Contains(logged, "old") {
		t.Errorf("the redacted line lost the record's KEK id, which is what makes it actionable: %q", logged)
	}
	if strings.Contains(logged, subject) {
		t.Errorf("the log line carries the subject identity %q: %s", subject, logged)
	}
	if strings.Contains(logged, BindingIdentity(binding).String()) {
		t.Errorf("the log line carries the binding identity %q: %s", BindingIdentity(binding).String(), logged)
	}
}

// ---------------------------------------------------------------------------
// S06-9: the Doer-only fallback client has the address guard on
// ---------------------------------------------------------------------------

// TestP3S06_9DoerOnlyFallbackClientGuardsPrivateAddresses: when the caller
// supplies a Doer that is not an *http.Client and no HTTPClient, NewService builds
// the token-exchange client itself. It was built from an empty OutboundConfig,
// whose DenyPrivateAddresses is the zero value, so a source whose issuer resolved
// to a loopback (or metadata-service) address got the authorization code and the
// client secret posted there. The guard is now on unless the deployment declares
// AllowPrivateUpstreams.
func TestP3S06_9DoerOnlyFallbackClientGuardsPrivateAddresses(t *testing.T) {
	var exchanges int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			http.NotFound(w, r)
			return
		}
		exchanges++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600}`))
	}))
	defer upstream.Close()

	newReg := func(t *testing.T) *Registry {
		t.Helper()
		reg, err := NewRegistry(Source{
			Game: game, Name: sourceName, DisplayName: "Fake", Issuer: upstream.URL,
			ClientID: "cid", ClientSecret: "sec",
		})
		if err != nil {
			t.Fatal(err)
		}
		return reg
	}
	// A Doer that is not an *http.Client, so the fallback is what performs the
	// exchange. It only satisfies NewService.
	doer := httpclient.DoerFunc(func(req *http.Request) (*http.Response, error) {
		return http.DefaultClient.Do(req)
	})
	bind := func(t *testing.T, cfg Config) (Binding, error) {
		t.Helper()
		svc := mustService(t, cfg, backend{store: NewMemoryBindingStore(), vault: newVault(t)})
		ctx := context.Background()
		ch, err := svc.BeginBind(ctx, "usr_1", game, sourceName, "/app/sources")
		if err != nil {
			return Binding{}, err
		}
		binding, _, err := svc.CompleteBind(ctx, "usr_1", ch.ID, "upstream-code")
		return binding, err
	}

	// Default: the private address is refused before any request is sent.
	_, err := bind(t, Config{Registry: newReg(t), Doer: doer, BaseURL: "https://re0auth.test"})
	if err == nil {
		t.Fatalf("the fallback client reached the loopback token endpoint (%d exchange(s)): the address "+
			"guard is off", exchanges)
	}
	if !strings.Contains(err.Error(), "allow_private_addresses") {
		t.Fatalf("the fallback client refused the loopback endpoint for another reason, so the probe is not "+
			"discriminating: %v", err)
	}
	if exchanges != 0 {
		t.Fatalf("the loopback token endpoint was reached %d time(s) despite the refusal", exchanges)
	}

	// Opt-in: a deployment whose sources are private says so, and the exchange
	// happens. This is the control that shows the refusal above is the guard and
	// not a broken fixture.
	binding, err := bind(t, Config{
		Registry: newReg(t), Doer: doer, BaseURL: "https://re0auth.test",
		AllowPrivateUpstreams: true,
	})
	if err != nil {
		t.Fatalf("AllowPrivateUpstreams did not let the fallback client through: %v", err)
	}
	if binding.User != "usr_1" || exchanges != 1 {
		t.Fatalf("control binding = %+v, exchanges = %d, want one successful exchange", binding, exchanges)
	}
}
