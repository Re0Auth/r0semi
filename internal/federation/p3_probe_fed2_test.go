package federation

// P3 probes for S05-9, S05-10, S14-12, Z09-2, Z09-3, Z09V-2, Z09V-3, G-18 and
// FO-04.
//
// Each probe was written to be RED against the code before its fix and GREEN
// after, and none of them may be satisfied by asserting something true for an
// unrelated reason: every probe carries a control (the well-formed value that
// must still be accepted, the at-the-cap body that must still succeed, the live
// flow the sweeper must spare) next to the property it pins.
//
// Z09-3 and Z09V-3 overlap S05-7 and S05-6 and were already closed by those
// fixes; their probes here pin the specific claims of the Z09 entries (no token
// exchange and no vault entry for a retired source; the browser is never sent to
// an origin the issuer did not name) rather than repeating the earlier ones.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/vault"
)

// ---------------------------------------------------------------------------
// S05-10: a foreign state must not consume the owner's pending flow
// ---------------------------------------------------------------------------

// TestP3S05_10ForeignStateDoesNotDestroyTheOwnersFlow: Consume is single-use and
// ran before the owner check, so CompleteBind called with another account's state
// destroyed that account's pending bind — a cross-account denial of the victim's
// own binding. The refusal must put the flow back.
func TestP3S05_10ForeignStateDoesNotDestroyTheOwnersFlow(t *testing.T) {
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: "https://src.example",
		ClientID: "cid",
	})
	if err != nil {
		t.Fatal(err)
	}
	flows := NewMemoryBindFlowStore()
	svc := mustService(t, Config{
		Registry: reg, Flows: flows, Doer: nopDoer{}, BaseURL: "https://re0auth.test",
	}, backend{store: NewMemoryBindingStore(), vault: newVault(t)})

	ctx := context.Background()
	ch, err := svc.BeginBind(ctx, "usr_owner", game, sourceName, "/app/sources")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.CompleteBind(ctx, "usr_attacker", ch.ID, "code"); !errors.Is(err, ErrBindUser) {
		t.Fatalf("CompleteBind with a foreign user = %v, want ErrBindUser", err)
	}

	// The owner's flow must still be there, with its owner, and still consumable.
	flow, cerr := flows.Consume(ctx, ch.ID)
	if cerr != nil {
		t.Fatalf("the foreign-user attempt consumed the owner's pending flow: %v "+
			"(the victim can no longer finish the bind it started)", cerr)
	}
	if flow.User != "usr_owner" || flow.Game != game || flow.Source != sourceName {
		t.Fatalf("restored flow = %+v, want the owner's flow", flow)
	}
}

// ---------------------------------------------------------------------------
// S05-9: the flow sweeper reads the service clock
// ---------------------------------------------------------------------------

// TestP3S05_9SweepAndEnforcementShareTheServiceClock: BeginBind stamps ExpiresAt
// from Config.Now and CompleteBind enforces it with the same clock, but
// SweepExpired used the wall clock. With an injected clock the sweeper and the
// enforcement therefore disagree about which flows are expired. The clock here is
// deliberately AHEAD of the wall clock, so a wall-clock sweep removes nothing
// while the service clock says both flows are past their deadline.
func TestP3S05_9SweepAndEnforcementShareTheServiceClock(t *testing.T) {
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: "https://src.example",
		ClientID: "cid",
	})
	if err != nil {
		t.Fatal(err)
	}
	logical := time.Now().Add(24 * time.Hour)
	flows := NewMemoryBindFlowStore()
	svc := mustService(t, Config{
		Registry: reg, Flows: flows, Doer: nopDoer{}, BaseURL: "https://re0auth.test",
		Now: func() time.Time { return logical },
	}, backend{store: NewMemoryBindingStore(), vault: newVault(t)})

	ctx := context.Background()
	toSweep, err := svc.BeginBind(ctx, "usr_1", game, sourceName, "/app")
	if err != nil {
		t.Fatal(err)
	}
	toEnforce, err := svc.BeginBind(ctx, "usr_1", game, sourceName, "/app")
	if err != nil {
		t.Fatal(err)
	}

	// Control: while both flows are inside their TTL the sweep removes nothing.
	if removed := flows.SweepExpired(); removed != 0 {
		t.Fatalf("the sweep removed %d live flows", removed)
	}

	logical = logical.Add(11 * time.Minute) // BindTTL is 10 minutes.

	// Enforcement: CompleteBind uses the service clock, so it refuses the expired
	// flow (and consumes it on the way).
	if _, _, err := svc.CompleteBind(ctx, "usr_1", toEnforce.ID, "code"); !errors.Is(err, ErrUnknownBind) {
		t.Errorf("CompleteBind of a flow the service clock says expired = %v, want ErrUnknownBind", err)
	}

	// The property: the sweeper agrees, because it reads the same clock.
	if removed := flows.SweepExpired(); removed != 1 {
		t.Errorf("the sweep removed %d flows expired by the service clock, want 1: the sweeper is reading "+
			"a different clock than the one expiry is enforced with (S05-9)", removed)
	}
	_ = toSweep
}

// ---------------------------------------------------------------------------
// Z09-2: the normalized read refuses a body past the cap
// ---------------------------------------------------------------------------

// TestP3Z09_2NormalizedReadRefusesABodyPastTheCap: the normalized path read
// io.LimitReader(..., maxBody) and never compared the result to the cap, so a body
// whose first maxBody bytes are a complete JSON value followed by padding was cut
// mid-padding and still passed json.Valid — a truncated body handed back as a
// complete result. The raw path already refuses the same body.
func TestP3Z09_2NormalizedReadRefusesABodyPastTheCap(t *testing.T) {
	const head = `{"served_by":"padded"}`
	var (
		mu   sync.Mutex
		body []byte
	)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		b := body
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	t.Cleanup(up.Close)

	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: up.URL,
		Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	b := backend{store: NewMemoryBindingStore(), vault: newVault(t)}
	b.bind(t, "usr_1", sourceName, "upstream-token", "", time.Now().Add(time.Hour))
	svc := mustService(t, Config{
		Registry: reg, Doer: up.Client(), HTTPClient: up.Client(), BaseURL: "https://re0auth.test",
	}, b)
	ctx := context.Background()

	// Control: a body exactly AT the cap is not past it and must still be served.
	atCap := make([]byte, maxBody)
	copy(atCap, head)
	for i := len(head); i < len(atCap); i++ {
		atCap[i] = ' '
	}
	mu.Lock()
	body = atCap
	mu.Unlock()
	res, err := svc.Fetch(ctx, FetchRequest{User: "usr_1", Game: game, Resource: "profile"})
	if err != nil {
		t.Fatalf("a body exactly at the cap was refused: %v", err)
	}
	if len(res.Data) != maxBody {
		t.Fatalf("at-cap body length = %d, want %d", len(res.Data), maxBody)
	}
	if res.Release != nil {
		res.Release()
	}

	// The finding: one byte past the cap, padded so the truncated value would
	// still parse as JSON.
	overCap := append(append([]byte(nil), atCap...), ' ')
	if !json.Valid(overCap[:maxBody]) {
		t.Fatal("harness: the truncated prefix must still be valid JSON, or this probe is not about truncation")
	}
	mu.Lock()
	body = overCap
	mu.Unlock()
	_, err = svc.Fetch(ctx, FetchRequest{User: "usr_1", Game: game, Resource: "profile"})
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("a %d-byte normalized body (cap %d) = %v, want ErrResponseTooLarge: the path is serving a "+
			"truncated 200 as if it were complete", len(overCap), maxBody, err)
	}
}

// ---------------------------------------------------------------------------
// Z09-3: a retired source fetches no token and stores nothing
// ---------------------------------------------------------------------------

// TestP3Z09_3RetiredSourceFetchesNoTokenAndStoresNothing: the Z09-3 claim is that
// BeginBind/CompleteBind had no Status gate, so an upstream token could be stored
// for a source the data plane never uses. S05-7 added both gates; this probe pins
// the two consequences the Z09 entry names — the token endpoint is never called
// and the vault never receives an entry — rather than only the binding row count.
func TestP3Z09_3RetiredSourceFetchesNoTokenAndStoresNothing(t *testing.T) {
	var exchanges atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			exchanges.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(up.Close)

	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Retired", Issuer: up.URL,
		Status: StatusRetired, ClientID: "cid", ClientSecret: "sec",
	})
	if err != nil {
		t.Fatal(err)
	}
	flows := NewMemoryBindFlowStore()
	b := backend{store: NewMemoryBindingStore(), vault: newVault(t)}
	svc := mustService(t, Config{
		Registry: reg, Flows: flows, Doer: up.Client(), HTTPClient: up.Client(),
		BaseURL: "https://re0auth.test",
	}, b)
	ctx := context.Background()

	if _, err := svc.BeginBind(ctx, "usr_1", game, sourceName, "/app"); !errors.Is(err, ErrSourceRetired) {
		t.Errorf("BeginBind against a retired source = %v, want ErrSourceRetired", err)
	}

	// A flow that began while the source was live, completed after it retired.
	flow := BindFlow{
		ID: "bnd_z09_3", User: "usr_1", Game: game, Source: sourceName,
		Verifier: "v", State: "bnd_z09_3", ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := flows.Put(ctx, flow); err != nil {
		t.Fatal(err)
	}
	_, _, err = svc.CompleteBind(ctx, "usr_1", flow.State, "upstream-code")
	if !errors.Is(err, ErrSourceRetired) {
		t.Fatalf("CompleteBind against a retired source = %v, want ErrSourceRetired", err)
	}
	if n := exchanges.Load(); n != 0 {
		t.Errorf("the token endpoint was called %d time(s) for a retired source", n)
	}
	identity := BindingIdentity(Binding{User: "usr_1", Game: game, Source: sourceName})
	if exists, _ := b.vault.Exists(ctx, identity); exists {
		t.Error("a credential was stored in the vault for a source the data plane never uses")
	}
	if rows := lenMustList(t, b.store); rows != 0 {
		t.Errorf("the retired source wrote %d binding row(s)", rows)
	}
}

// ---------------------------------------------------------------------------
// Z09V-2: a store read failure is not a "version did not move"
// ---------------------------------------------------------------------------

// probeFlakyGetStore fails Get while err is set, and delegates otherwise. It
// stands in for a transient store fault during refreshRejected's re-read.
type probeFlakyGetStore struct {
	*MemoryBindingStore
	err error
}

func (s *probeFlakyGetStore) Get(ctx context.Context, user account.UserID, game, source string) (Binding, error) {
	if s.err != nil {
		return Binding{}, s.err
	}
	return s.MemoryBindingStore.Get(ctx, user, game, source)
}

var errProbeStoreDown = errors.New("federation: probe store is down")

// TestP3Z09V_2StoreReadFailureDoesNotShredTheBinding: refreshRejected treated any
// non-nil error from its re-read as "the version did not move", so one read fault
// deleted the binding row and crypto-shredded a vault key that could still belong
// to a valid binding. Only ErrNotBound may share the destructive branch's meaning.
func TestP3Z09V_2StoreReadFailureDoesNotShredTheBinding(t *testing.T) {
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: "https://src.example",
		TokenClass: tokenClassRevocable,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &probeFlakyGetStore{MemoryBindingStore: NewMemoryBindingStore()}
	b := backend{store: store, vault: newVault(t)}
	b.bind(t, "usr_1", sourceName, "stale", "rt-1", time.Now().Add(-time.Hour))
	svc := mustService(t, Config{Registry: reg, Doer: nopDoer{}}, b)

	store.err = errProbeStoreDown
	spent := Binding{User: "usr_1", Game: game, Source: sourceName, Version: 1}
	_, err = svc.(*service).refreshRejected(context.Background(), spent)
	if !errors.Is(err, errProbeStoreDown) {
		t.Fatalf("refreshRejected under a store fault = %v, want the store error", err)
	}

	// The destructive branch must not have run: the row and its secret survive,
	// so the next attempt can still use them.
	store.err = nil
	if _, gerr := b.store.Get(context.Background(), "usr_1", game, sourceName); gerr != nil {
		t.Errorf("a store read fault destroyed the binding: %v", gerr)
	}
	if exists, _ := b.vault.Exists(context.Background(), BindingIdentity(spent)); !exists {
		t.Error("a store read fault crypto-shredded the binding's vault secret")
	}
}

// ---------------------------------------------------------------------------
// Z09V-3: the issuer cannot send the browser to another origin
// ---------------------------------------------------------------------------

// TestP3Z09V_3IssuerCannotOffOriginTheBrowser: Issuer is the base of the /bind 302
// target, so a scheme-relative "//evil.example" would send the browser to another
// origin. It is refused at the registry, and a legitimate absolute issuer's
// authorize URL — and the redirect_uri registered with the source — stay on the
// origins the operator wrote.
func TestP3Z09V_3IssuerCannotOffOriginTheBrowser(t *testing.T) {
	if _, err := NewRegistry(Source{Game: game, Name: sourceName, Issuer: "//evil.example"}); err == nil {
		t.Error("NewRegistry accepted the scheme-relative issuer \"//evil.example\": /bind would answer a 302 " +
			"naming another origin")
	} else if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("the refusal does not name the issuer field: %v", err)
	}

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(up.Close)
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: up.URL, ClientID: "cid",
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := mustService(t, Config{
		Registry: reg, Doer: up.Client(), HTTPClient: up.Client(), BaseURL: "https://re0auth.test",
	}, backend{store: NewMemoryBindingStore(), vault: newVault(t)})

	ch, err := svc.BeginBind(context.Background(), "usr_1", game, sourceName, "/app")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := url.Parse(ch.AuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.TrimPrefix(up.URL, "http://"); auth.Host != want {
		t.Errorf("authorize URL host = %q, want the configured issuer host %q", auth.Host, want)
	}
	redirect, err := url.Parse(auth.Query().Get("redirect_uri"))
	if err != nil {
		t.Fatal(err)
	}
	if redirect.Host != "re0auth.test" {
		t.Errorf("redirect_uri host = %q, want Re0Auth's own origin: the per-source redirect is not joined "+
			"to the configured base URL", redirect.Host)
	}
}

// ---------------------------------------------------------------------------
// G-18: the vault's dotted (game, source) namespace cannot collide
// ---------------------------------------------------------------------------

// TestP3G18DottedNamesCannotShareAVaultIdentity: BindingIdentity joins game and
// source with a bare "." and the separator cannot change (existing ciphertext is
// bound to it as AAD), so with "." allowed in either half two distinct registry
// entries map to ONE credential row. The registry must refuse the separator in
// the halves, which is what keeps the join injective.
func TestP3G18DottedNamesCannotShareAVaultIdentity(t *testing.T) {
	collideA := BindingIdentity(Binding{User: "usr_1", Game: "phigros", Source: "official.beta"})
	collideB := BindingIdentity(Binding{User: "usr_1", Game: "phigros.official", Source: "beta"})
	if collideA != collideB {
		t.Fatalf("harness: the two pairs no longer share the dotted identity (%v vs %v)", collideA, collideB)
	}

	for _, tc := range []struct{ game, name string }{
		{"phigros", "official.beta"},
		{"phigros.official", "beta"},
	} {
		_, err := NewRegistry(Source{Game: tc.game, Name: tc.name, Issuer: "https://api.example"})
		if err == nil {
			t.Errorf("NewRegistry accepted game=%q name=%q: both share the vault identity %v, so binding one "+
				"overwrites the other's credential and unbinding either shreds it (G-18)", tc.game, tc.name, collideA)
			continue
		}
		if !strings.Contains(err.Error(), "game") && !strings.Contains(err.Error(), "name") {
			t.Errorf("the refusal of game=%q name=%q names neither field: %v", tc.game, tc.name, err)
		}
	}

	// Control: the same pairs without the separator are accepted, and their vault
	// identities are distinct — the objection is the join, not the names.
	reg, err := NewRegistry(
		Source{Game: "phigros", Name: "official-beta", Issuer: "https://a.example"},
		Source{Game: "phigros-official", Name: "beta", Issuer: "https://b.example"},
	)
	if err != nil {
		t.Fatalf("the separator-free counterparts were refused: %v", err)
	}
	okA := BindingIdentity(Binding{User: "usr_1", Game: "phigros", Source: "official-beta"})
	okB := BindingIdentity(Binding{User: "usr_1", Game: "phigros-official", Source: "beta"})
	if okA == okB {
		t.Errorf("two accepted sources share one vault identity: %v", okA)
	}
	if _, exists := reg.Get("phigros", "official-beta"); !exists {
		t.Error("the accepted source is not retrievable")
	}
}

// ---------------------------------------------------------------------------
// FO-04: names and scopes are validated at the registry
// ---------------------------------------------------------------------------

// TestP3FO04MalformedNamesAndScopesAreRefusedAtTheRegistry: the game, source and
// resource names are joined into the callback URL and the registry key, and a
// resource's scope is sent upstream verbatim. Operator input, but it is checked
// rather than trusted — the rule idp.validateProviderName already applies to the
// same class of value.
func TestP3FO04MalformedNamesAndScopesAreRefusedAtTheRegistry(t *testing.T) {
	badNames := []string{
		"../evil", "src/../other", "src?x=1", "src#f", `src\evil`,
		"src\nnewline", "src with space", "src\x00null", "Official", "-leading", "_leading", "",
	}
	for _, name := range badNames {
		if _, err := NewRegistry(Source{Game: game, Name: name, Issuer: "https://api.example"}); err == nil {
			t.Errorf("NewRegistry accepted source name %q; it would reach the callback URL and the registry key",
				name)
		}
	}
	for _, g := range []string{"../..", "..", "Phi", "phi gros", "phigros/other", ""} {
		if _, err := NewRegistry(Source{Game: g, Name: sourceName, Issuer: "https://api.example"}); err == nil {
			t.Errorf("NewRegistry accepted game %q", g)
		}
	}

	badScopes := []string{
		"phigros.profile.read account.id", // the whitespace that splits one scope into two
		"a.b\tc", "a.b\nc", "a.b\rc", "a.b/c", "a.b?x=1", "a.b#f", `a.b\c`,
	}
	for _, scope := range badScopes {
		_, err := NewRegistry(Source{
			Game: game, Name: sourceName, Issuer: "https://api.example",
			Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: scope}},
		})
		if err == nil {
			t.Errorf("NewRegistry accepted resource scope %q: oauth2 would send it as several scopes the "+
				"operator never declared", scope)
		}
	}

	for _, rname := range []string{"../evil", "pro file", "pro/file", "pro?x=1", "Profile"} {
		_, err := NewRegistry(Source{
			Game: game, Name: sourceName, Issuer: "https://api.example",
			Resources: []Resource{{Name: rname, Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
		})
		if err == nil {
			t.Errorf("NewRegistry accepted resource name %q", rname)
		}
	}

	// Control: a well-formed source is still accepted, its scopes are exactly the
	// ones declared (one per resource, plus the account scope), and an empty scope
	// still means "no scope for this resource".
	reg, err := NewRegistry(Source{
		Game: game, Name: "next-phi", DisplayName: "Next", Issuer: "https://api.example",
		Resources: []Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope},
			{Name: "scores", Schema: "re0auth.phigros.scores/1", Scope: ""},
		},
	})
	if err != nil {
		t.Fatalf("a well-formed source was refused: %v", err)
	}
	src, ok := reg.Get(game, "next-phi")
	if !ok {
		t.Fatal("the accepted source is not retrievable")
	}
	scopes := src.bindScopes()
	if len(scopes) != 2 || scopes[0] != "account.read" || scopes[1] != profileScope {
		t.Errorf("bindScopes = %v, want [account.read %s]: one declared scope per resource", scopes, profileScope)
	}
	for _, s := range scopes {
		if strings.ContainsAny(s, " \t\r\n") {
			t.Errorf("a wired scope carries whitespace: %q", s)
		}
	}
}

// ---------------------------------------------------------------------------
// S14-12: the row is claimed before the vault, losers never write, serialized
// ---------------------------------------------------------------------------

// probeEventStore records the outcome of each PutIfVersion claim.
type probeEventStore struct {
	*MemoryBindingStore
	mu     *sync.Mutex
	events *[]string
}

func (s *probeEventStore) PutIfVersion(ctx context.Context, b Binding, expected uint64) (bool, error) {
	won, err := s.MemoryBindingStore.PutIfVersion(ctx, b, expected)
	s.mu.Lock()
	*s.events = append(*s.events, fmt.Sprintf("row:%v", won))
	s.mu.Unlock()
	return won, err
}

// probeEventVault records every vault write.
type probeEventVault struct {
	vault.Service
	mu     *sync.Mutex
	events *[]string
}

func (v probeEventVault) Enroll(ctx context.Context, id vault.Identity, secret []byte, meta map[string]string) error {
	v.mu.Lock()
	*v.events = append(*v.events, "secret")
	v.mu.Unlock()
	return v.Service.Enroll(ctx, id, secret, meta)
}

// TestP3S14_12RowIsClaimedBeforeTheVaultAndLosersNeverWrite pins what makes
// refreshBinding's row-then-secret order safe rather than suspicious: the row is
// claimed FIRST, the per-binding lock serializes the two callers, and a writer
// that loses the claim must not touch the vault. Two concurrent refreshes of one
// binding therefore produce exactly one claim and exactly one vault write, in
// that order.
func TestP3S14_12RowIsClaimedBeforeTheVaultAndLosersNeverWrite(t *testing.T) {
	up := refreshUpstream(t, "fresh-token", http.StatusOK)
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: up.URL,
		ClientID: "cid", ClientSecret: "sec", TokenClass: tokenClassRevocable,
		Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu     sync.Mutex
		events []string
	)
	store := &probeEventStore{MemoryBindingStore: NewMemoryBindingStore(), mu: &mu, events: &events}
	b := backend{store: store, vault: probeEventVault{Service: newVault(t), mu: &mu, events: &events}}
	b.bind(t, "usr_1", sourceName, "stale-token", "rt-1", time.Now().Add(-time.Hour))
	svc := mustService(t, Config{
		Registry: reg, Doer: up.Client(), HTTPClient: up.Client(), BaseURL: "https://re0auth.test",
	}, b)

	ctx := context.Background()
	current, err := store.Get(ctx, "usr_1", game, sourceName)
	if err != nil {
		t.Fatal(err)
	}
	if !current.HasRefresh {
		t.Fatal("harness: the fixture binding has no refresh token")
	}
	src, _ := reg.Get(game, sourceName)

	mu.Lock()
	events = nil
	mu.Unlock()

	var wg sync.WaitGroup
	versions := make([]uint64, 2)
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, rerr := svc.(*service).refreshBinding(ctx, src, current, true)
			errs[i], versions[i] = rerr, got.Version
		}(i)
	}
	wg.Wait()

	for i, rerr := range errs {
		if rerr != nil {
			t.Fatalf("refresh %d: %v", i, rerr)
		}
	}
	for i, v := range versions {
		if v != 2 {
			t.Errorf("refresh %d returned version %d, want 2 (the winner's row)", i, v)
		}
	}

	mu.Lock()
	seq := append([]string(nil), events...)
	mu.Unlock()
	if len(seq) != 2 || seq[0] != "row:true" || seq[1] != "secret" {
		t.Errorf("claim/vault sequence = %v, want exactly [row:true secret]: the row must be claimed before the "+
			"vault is written, and a writer that loses the claim must not touch it (S14-12)", seq)
	}
}
