//go:build audit || audit6

package federation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/account"
)

// zz_audit_timeoutchain_test.go —audit probe.
//
// Question: Config.TotalTimeout is documented as "bounds ONE data-plane request
// end to end" and the server's write timeout is kept larger so the refusal has a
// connection to be written on (service.go:253-264, cmd/re0auth/timeouts_test.go).
// Which outbound paths actually get it?
//
// The probe drives one service whose Doer answers after `delay` and whose
// TotalTimeout is far below it, then compares:
//
//	Fetch            (wrapped by withinTotalTimeout)
//	RevokeAllBindings(the Kill Switch sweep —NOT wrapped)
type slowDoer struct {
	delay time.Duration
	calls atomic.Int64
}

func (d *slowDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls.Add(1)
	timer := time.NewTimer(d.delay)
	defer timer.Stop()
	select {
	case <-req.Context().Done():
		return nil, req.Context().Err()
	case <-timer.C:
		return nil, errors.New("zz-audit: simulated upstream failure")
	}
}

func TestZZAuditKillSwitchSweepIsNotBoundedByTotalTimeout(t *testing.T) {
	const (
		delay = 200 * time.Millisecond
		total = 20 * time.Millisecond
		users = 24
	)
	ctx := context.Background()
	doer := &slowDoer{delay: delay}

	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: "https://source.example",
		TokenClass: tokenClassRevocable,
		// A cascade endpoint makes every binding cost TWO outbound calls in
		// revokeBinding (cascade, then the unbind fallback).
		CascadeRevocationEndpoint: "https://source.example/oauth/cascade_revocation",
		Resources:                 []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	b := backend{store: NewMemoryBindingStore(), vault: newVault(t)}
	svc := mustService(t, Config{
		Registry: reg, Doer: doer, TotalTimeout: total, KillSwitchPageSize: 500,
	}, b)

	// One binding to drive the data plane's own bound.
	b.bind(t, "usr_fetch", sourceName, "tok", "", time.Time{})
	fetchStart := time.Now()
	_, ferr := svc.Fetch(ctx, FetchRequest{User: "usr_fetch", Game: game, Resource: "profile"})
	fetchElapsed := time.Since(fetchStart)

	before := doer.calls.Load()
	// A deployment-wide sweep over `users` bindings.
	for i := 0; i < users; i++ {
		b.bind(t, account.UserID(fmt.Sprintf("usr_sweep_%02d", i)), sourceName, "tok", "", time.Time{})
	}
	sweepStart := time.Now()
	summary, serr := svc.RevokeAllBindings(ctx)
	sweepElapsed := time.Since(sweepStart)
	calls := doer.calls.Load() - before

	t.Logf("TotalTimeout = %v, per-outbound-call latency = %v", total, delay)
	t.Logf("Fetch:             err=%v elapsed=%v (deadline error: %v)",
		ferr, fetchElapsed.Round(time.Millisecond), errors.Is(ferr, context.DeadlineExceeded))
	t.Logf("RevokeAllBindings: err=%v elapsed=%v summary=%+v outbound calls=%d",
		serr, sweepElapsed.Round(time.Millisecond), summary, calls)

	if fetchElapsed > 5*total {
		t.Errorf("Fetch was not bounded by TotalTimeout: %v", fetchElapsed)
	}
	if sweepElapsed <= 10*total {
		t.Logf("the sweep finished inside 10x TotalTimeout (%v); the probe needs more bindings or a "+
			"slower Doer to separate the two paths", sweepElapsed)
	}
	if serr != nil {
		t.Errorf("sweep error = %v, want nil (the caller is told the sweep succeeded)", serr)
	}
	// users + the fetch probe's own binding.
	if summary.Revoked != users+1 {
		t.Errorf("summary.Revoked = %d, want %d", summary.Revoked, users+1)
	}
	// The arithmetic the report uses: 8 workers (killSwitchWorkers), 2 outbound
	// calls per binding, `delay` each.
	t.Logf("sweep wall time is ~ceil(N/%d)*2*delay = ~%v for N=%d: unbounded in N",
		killSwitchWorkers, time.Duration(users/killSwitchWorkers)*2*delay, users)
}
