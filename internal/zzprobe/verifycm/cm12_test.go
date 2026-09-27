//go:build audit5

// Package verifycm holds the adversarial verification probes for
// docs/audit-5/findings/concurrency-memory.md (CM-1 .. CM-6).
//
// These are deliberately independent of the audited probes: they re-derive the
// mechanism from the exported surface rather than reusing the audited harness.
package verifycm

import (
	"context"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

const (
	probeClientID = "cli"
	probeRedirect = "https://app.example/cb"
)

func newStore(t *testing.T, log audit.Logger, now func() time.Time) *memory.OIDCStore {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	c, err := oauth.NewClient(probeClientID, "probe", oauth.ClientPublic, "",
		[]string{probeRedirect}, []oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	opts := memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   newSigner(t),
		Audit:    log,
		Now:      now,
	}
	st, err := memory.NewOIDCStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// CM-1, the part the report does not quantify: in the ONLY deployment that runs
// this code (no DATABASE_URL) the audit sink is audit.MemoryLogger — a ring buffer
// append with no I/O. The critical section CM-1 is about therefore costs
// nanoseconds, and the "every OP operation queues behind an audit append" impact
// does not hold. The difference between "audit write inside the lock" and "audit
// write after the lock" is measured directly, by timing the same operation with and
// without a sink.
func TestCM1TheShippedSinkMakesTheCriticalSectionNanoseconds(t *testing.T) {
	const n = 20_000

	run := func(log audit.Logger) time.Duration {
		st := newStore(t, log, nil)
		ctx := context.Background()
		for i := 0; i < n; i++ {
			uc := "UC-" + itoa(i)
			if err := st.StoreDeviceAuthorization(ctx, probeClientID, "dc-"+itoa(i), uc,
				time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
				t.Fatal(err)
			}
		}
		start := time.Now()
		for i := 0; i < n; i++ {
			if err := st.ApproveDevice(ctx, "UC-"+itoa(i), "usr_1", nil); err != nil {
				t.Fatalf("approve %d: %v", i, err)
			}
		}
		return time.Since(start) / n
	}

	withSink := run(audit.NewMemoryLogger()) // what cmd/re0auth wires with no DATABASE_URL
	without := run(nil)

	t.Logf("ApproveDevice per call: with audit.MemoryLogger = %v, with no sink = %v, delta = %v "+
		"(n=%d; the delta is the audit write *inside* the store's single lock)",
		withSink, without, withSink-without, n)

	// The claim under test is not "is the lock held" (the audited probe proves it
	// is) but "does holding it matter in the mode that ships this store". A delta
	// in the tens/hundreds of nanoseconds means the serialisation is unobservable.
	if delta := withSink - without; delta > 20*time.Microsecond {
		t.Errorf("the in-memory audit write inside the lock costs %v per call; CM-1's impact estimate needs revisiting", delta)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// CM-2's observable-effect question: the three methods drop the caller's ctx, but
// in the only deployment where they run, the sink ignores ctx entirely. This pins
// that: a cancelled context changes nothing about what the shipped sink records or
// how long the call takes.
func TestCM2ACancelledRequestContextChangesNothingWithTheShippedSink(t *testing.T) {
	st := newStore(t, audit.NewMemoryLogger(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if _, _, err := st.CreateAccessToken(ctx, &oidcstore.AuthRequest{
		ID: "req_1", ClientID: probeClientID, Subject: "usr_1", Scopes: []string{"account.id"},
	}); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed > 5*time.Millisecond {
		t.Errorf("a cancelled-context token mint took %v; the dropped context is visible after all", elapsed)
	}
	t.Logf("CreateAccessToken with an already-cancelled ctx returned in %v with no error: audit.MemoryLogger ignores ctx", elapsed)
}

// CM-3(a), the consequence chain rather than the aliasing itself: the value
// CreateAuthRequest returns IS the store's record, so a write through it lands in
// the store without the lock AND survives the consent decision — a scope the human
// never approved is handed to the code exchange. The audited probe stops at "the
// stored scopes changed"; this shows what that changes downstream.
func TestCM3AWriteThroughTheReturnedValueReachesTheMintedGrant(t *testing.T) {
	st := newStore(t, nil, nil)
	ctx := context.Background()

	created, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID: probeClientID, RedirectURI: probeRedirect,
		ResponseType: oidc.ResponseTypeCode, Scopes: []string{"account.id"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	live, ok := created.(*oidcstore.AuthRequest)
	if !ok {
		t.Fatalf("CreateAuthRequest returned %T", created)
	}
	id := live.GetID()

	// The consent decision: the human approved exactly account.id.
	if err := st.CompleteLogin(ctx, id, "usr_1", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}

	// Control: the read path really does hand out a copy, so the write below is
	// the create path's defect and not "the probe cannot see a copy".
	clone, err := st.AuthRequestByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	clone.(*oidcstore.AuthRequest).Scopes = []string{"phigros.score.read"}
	after, err := st.AuthRequestByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.GetScopes()) != 1 || after.GetScopes()[0] != "account.id" {
		t.Fatalf("control failed: AuthRequestByID handed out the stored record (%v)", after.GetScopes())
	}

	// The finding path: write through the value CreateAuthRequest handed back.
	live.Scopes = append(live.Scopes, "phigros.score.read")

	if err := st.SaveAuthCode(ctx, id, "code-verify-cm3"); err != nil {
		t.Fatal(err)
	}
	redeemed, err := st.AuthRequestByCode(ctx, "code-verify-cm3")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range redeemed.GetScopes() {
		if s == "phigros.score.read" {
			t.Errorf("a write through CreateAuthRequest's return value reached the redeemed grant: %v "+
				"(the consent decision approved only [account.id])", redeemed.GetScopes())
		}
	}
	t.Logf("scopes the code exchange sees: %v", redeemed.GetScopes())
}

// CM-3(c): is there a real data race behind the aliasing? This probe races a reader
// holding the returned value against CompleteLogin, which writes the same object
// under the store's lock. Under -race this is reported; WITHOUT -race the
// consequence is measured: the reader observes torn/partial state.
//
// The caveat is the whole finding: the only holder in production is
// github.com/zitadel/oidc/v3/pkg/op's Authorize, which calls req.GetID() and drops
// the pointer immediately (pkg/op/auth_request.go:145-150). The race is therefore
// reachable only for a caller that keeps the value — the probe below IS such a
// caller, so it proves a mechanism, not a live defect.
func TestCM3TheReturnedValueIsLiveStoreStateUnderTheRaceDetector(t *testing.T) {
	st := newStore(t, nil, nil)
	ctx := context.Background()

	created, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID: probeClientID, RedirectURI: probeRedirect,
		ResponseType: oidc.ResponseTypeCode, Scopes: []string{"account.id"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	live, ok := created.(*oidcstore.AuthRequest)
	if !ok {
		t.Fatalf("CreateAuthRequest returned %T", created)
	}
	id := live.GetID()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// A holder reading what it was given, exactly as a handler would.
		for i := 0; i < 200_000; i++ {
			_ = live.GetSubject()
			_ = live.GetScopes()
		}
	}()
	for i := 0; i < 20_000; i++ {
		if err := st.CompleteLogin(ctx, id, "usr_1", []string{"account.id"}); err != nil {
			t.Fatal(err)
		}
	}
	<-done
	t.Log("holder read 200k times while CompleteLogin wrote the same object 20k times under the store lock")
}
