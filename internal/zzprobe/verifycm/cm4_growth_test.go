//go:build audit5

package verifycm

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// CM-4 arithmetic check 1: is the "~335 bytes per entry" measurement an artefact of
// the audited probe's minimal fixture (one shared *oidc.AuthRequest with a single
// scope and no state/nonce/PKCE)? This measures the same thing with the fields a
// real /oauth/authorize leaves behind, so the growth estimate is either confirmed
// or corrected.
func TestCM4RealisticPendingRequestCost(t *testing.T) {
	ctx := context.Background()

	measure := func(name string, build func(i int) *oidc.AuthRequest) int64 {
		// A fresh store per measurement: records from the first measurement would
		// otherwise still be reachable from the second one's baseline.
		st := newStore(t, nil, nil)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		const n = 50_000
		for i := 0; i < n; i++ {
			if _, err := st.CreateAuthRequest(ctx, build(i), ""); err != nil {
				t.Fatal(err)
			}
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		per := int64(after.HeapAlloc-before.HeapAlloc) / n
		t.Logf("%s: %d requests retain ~%d bytes each (~%d MiB total)", name, n, per, int64(after.HeapAlloc-before.HeapAlloc)/(1<<20))
		if st.Counts().AuthRequests != n {
			t.Fatalf("store holds %d requests, want %d", st.Counts().AuthRequests, n)
		}
		return per
	}

	// The audited probe's fixture, reproduced (one shared request object, one scope,
	// anonymous so userID is empty).
	shared := &oidc.AuthRequest{
		ClientID: probeClientID, RedirectURI: probeRedirect,
		ResponseType: oidc.ResponseTypeCode, Scopes: []string{"account.id"},
	}
	audited := measure("audited fixture (shared request, no state/nonce/PKCE)", func(int) *oidc.AuthRequest {
		return shared
	})

	// What the HTTP surface actually produces: per-request values, state, nonce and
	// an S256 challenge, which is what the growth probe's query string sends.
	realistic := measure("HTTP-realistic (state, nonce, PKCE challenge, 2 scopes)", func(i int) *oidc.AuthRequest {
		return &oidc.AuthRequest{
			ClientID: probeClientID, RedirectURI: probeRedirect,
			ResponseType: oidc.ResponseTypeCode,
			State:        "st-" + itoa(i), Nonce: "nnn-" + itoa(i),
			CodeChallenge: "0123456789012345678901234567890123456789012",
			Scopes:        []string{"account.id", "phigros.score.read"},
			Prompt:        []string{"consent"},
		}
	})
	if realistic == 0 || audited == 0 {
		t.Fatal("the probe measured no retained memory; nothing to compare")
	}
	ratio := float64(realistic) / float64(audited)
	t.Logf("realistic/audited per-entry ratio = %.2f", ratio)
	if ratio < 0.8 {
		t.Errorf("the audited fixture OVER-states per-entry cost by %.2fx; CM-4's MiB figure must be corrected", 1/ratio)
	}
}

// CM-4 arithmetic check 2: is the growth sustained or bounded? The audited probe
// shows the janitor removes only expired records; this shows the ceiling that
// implies — a population of N is entirely removed once the clock passes the TTL, so
// the peak is arrivals x TTL, not "unbounded over days".
func TestCM4ThePeakIsSetByArrivalsTimesTTLNotByTime(t *testing.T) {
	now := time.Now()
	st := newStore(t, nil, func() time.Time { return now })
	ctx := context.Background()

	const n = 5_000
	for i := 0; i < n; i++ {
		if _, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{
			ClientID: probeClientID, RedirectURI: probeRedirect,
			ResponseType: oidc.ResponseTypeCode, Scopes: []string{"account.id"},
		}, ""); err != nil {
			t.Fatal(err)
		}
	}
	if got := st.Counts().AuthRequests; got != n {
		t.Fatalf("auth requests = %d, want %d", got, n)
	}
	if removed := st.SweepExpired(); removed != 0 {
		t.Fatalf("the janitor removed %d unexpired requests", removed)
	}
	now = now.Add(31 * time.Minute) // past the 30-minute request TTL
	removed := st.SweepExpired()
	if got := st.Counts().AuthRequests; got != 0 || removed != n {
		t.Errorf("after the TTL the janitor removed %d of %d requests (%d left): the population is not bounded by the TTL",
			removed, n, got)
	}
	t.Logf("%d pending requests were all removed once the clock passed the 30-minute TTL: peak = arrivals x TTL", n)
}
