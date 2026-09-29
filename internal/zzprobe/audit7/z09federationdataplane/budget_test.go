//go:build audit7

// Z09-4: the upstream response budget has no per-caller share, and the reservation
// is taken before a single body byte arrives.
//
// Config.MaxBufferedBytes (shipped default 64 MiB) is a joint budget; each
// buffering read reserves the worst case it may hold — `maxBody+1` = 4 MiB + 1 for
// a raw passthrough, `maxBody` for a normalized read whose Content-Length is
// unknown — and `bufferBudget.acquire` sheds (ErrBufferBudget → 503 +
// Retry-After) rather than blocking. The direction is documented.
//
// What is not: fifteen in-flight reads are all it takes to consume the shipped
// budget, they need transfer ZERO body bytes (a source that flushes headers and
// stalls holds the reservation), and the callers they shed are unrelated users'
// reads. This probe drives the real HTTP surface with the SHIPPED default (it does
// not tune MaxBufferedBytes), so the numbers are the ones a default deployment
// has.
package zzprobe_z09federationdataplane

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/federation"
)

const zzVictimScope = "phigros.profile.read"
const zzSleeperScope = "phigros.score.read"

func TestZ09SleeperReadsShedAFullCapReadForAnotherUser(t *testing.T) {
	ctx := context.Background()

	// The sleeper upstream: headers, then stall. The client has its reservation by
	// then (rawFetch acquires after Do returns and before it reads), and no body
	// byte has crossed the wire.
	release := make(chan struct{})
	var releaseOnce sync.Once
	stop := func() { releaseOnce.Do(func() { close(release) }) }
	var inHandler atomic.Int64
	sleeper := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		inHandler.Add(1)
		<-release
	}))
	t.Cleanup(sleeper.Close) // registered first, so it runs LAST
	t.Cleanup(stop)          // registered second, so it runs FIRST

	// The victim upstream: a small body with an unknown length (flushed headers),
	// so the normalized read reserves the full cap rather than a few bytes.
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(victim.Close)

	reg, err := federation.NewRegistry(
		federation.Source{
			Game: zzGame, Name: "sleeper", Issuer: sleeper.URL, RawBase: sleeper.URL + "/native",
			Resources: []federation.Resource{
				{Name: "scores", Schema: "re0auth.phigros.scores/1", Scope: zzSleeperScope},
			},
		},
		federation.Source{
			Game: zzGame, Name: "victim", Issuer: victim.URL,
			Resources: []federation.Resource{
				{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: zzVictimScope},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	srv, mint := zzHarness(t, reg, []zzBind{
		{User: "usr_atk", Game: zzGame, Source: "sleeper", Access: "atk-token"},
		{User: "usr_vic", Game: zzGame, Source: "victim", Access: "vic-token"},
	}, nil)
	atk := mint("usr_atk", zzSleeperScope)
	vic := mint("usr_vic", zzVictimScope)

	sleeperURL := srv.URL + "/v1/games/" + zzGame + "/sources/sleeper/raw/data"
	victimURL := srv.URL + "/v1/games/" + zzGame + "/profile?source=victim"

	// Baseline: the victim's read works on its own.
	if code, _, _ := zzGet(t, srv.Client(), victimURL, vic); code != http.StatusOK {
		t.Fatalf("baseline victim read = %d, want 200; the probe cannot attribute anything to the sleepers", code)
	}

	// 16 sleepers: 15 x (4 MiB + 1) fits the 64 MiB budget, the 16th does not.
	const sleepers = 16
	for i := 0; i < sleepers; i++ {
		go func() {
			req, err := http.NewRequest(http.MethodGet, sleeperURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "Bearer "+atk)
			resp, err := srv.Client().Do(req)
			if err != nil {
				return
			}
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}()
	}

	waitUntil(t, 3*time.Second, func() bool { return inHandler.Load() >= sleepers-1 })
	time.Sleep(200 * time.Millisecond) // let every admitted client take its reservation

	// The victim's read, polled so a slow scheduling of the sleepers cannot turn
	// this into a false green.
	deadline := time.Now().Add(3 * time.Second)
	code := http.StatusServiceUnavailable
	for time.Now().Before(deadline) {
		code, _, _ = zzGet(t, srv.Client(), victimURL, vic)
		if code == http.StatusOK {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("with %d sleepers holding reservations (handlers reached: %d of %d), an unrelated user's read = %d",
		sleepers, inHandler.Load(), sleepers, code)
	if code == http.StatusServiceUnavailable {
		t.Errorf("an unrelated account's read was SHED (503) while %d zero-byte reads were in flight. The "+
			"budget is joint and first-come-first-served: 15 reservations of maxBody+1 exhaust the shipped 64 MiB, "+
			"the reservation is taken before a single body byte arrives (a source that flushes headers and stalls "+
			"holds it), and the failure lands on other users. Cost to the attacker: 15 sockets and one token",
			sleepers)
	} else {
		t.Logf("the read was not shed (%d): the budget arithmetic changed, so re-derive this probe", code)
	}

	// Control: releasing the sleepers frees the budget, so the 503 above was
	// caused by the held reservations and not by anything else on the path.
	stop()
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		code, _, _ = zzGet(t, srv.Client(), victimURL, vic)
		if code == http.StatusOK {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("after releasing the sleepers, the unrelated user's read = %d", code)
	if code != http.StatusOK {
		t.Errorf("the read did not recover after the sleepers were released: %d (the shed above is not "+
			"attributable to the held reservations)", code)
	}
	_ = ctx
}

func waitUntil(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
