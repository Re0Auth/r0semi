//go:build audit7

// Z09-4: the upstream response budget needs a per-caller share, not just a global
// first-come-first-served limit.
//
// Config.MaxBufferedBytes (shipped default 64 MiB) is a joint budget; each
// buffering read reserves the worst case it may hold — `maxBody+1` = 4 MiB + 1 for
// a raw passthrough, `maxBody` for a normalized read whose Content-Length is
// unknown — and `bufferBudget.acquire` sheds (ErrBufferBudget → 503 +
// Retry-After) rather than blocking. The direction is documented.
//
// What was missing: the budget was global first-come-first-served only, so fifteen
// in-flight reads were all it took to consume the shipped budget, they needed
// transfer ZERO body bytes (a source that flushes headers and stalls holds the
// reservation), and the callers they shed were unrelated users' reads. Cost to the
// attacker: 15 sockets and one token.
//
// The fix gives every caller (keyed by subject) its own share,
// `max(2*maxBody, limit/4)` = 16 MiB under the shipped default, so the sleeper's
// subject can hold at most its own share while the remaining budget stays as
// headroom for everyone else. This probe drives the real HTTP surface with the
// SHIPPED default (it does not tune MaxBufferedBytes), so the numbers are the ones
// a default deployment has. It guards the property directly: with 15 sleepers in
// flight the victim's full-cap read must still be answered 200, while the
// sleepers' own excess reservations are the ones that get shed.
package zzprobe_z09federationdataplane

import (
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

	// 16 sleepers, all one subject: without a share, 15 x (4 MiB + 1) fits the
	// 64 MiB budget and the 16th does not, but every one of them shares usr_atk's
	// 16 MiB share, which admits only three full-cap raw reservations.
	const sleepers = 16
	var shed, admitted atomic.Int64
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
			switch resp.StatusCode {
			case http.StatusOK:
				admitted.Add(1)
			case http.StatusServiceUnavailable:
				shed.Add(1)
			}
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}()
	}

	waitUntil(t, 3*time.Second, func() bool { return inHandler.Load() >= sleepers-1 })
	// Every sleeper has seen its headers by now; the ones inside their subject's
	// share hold reservations, the rest have been shed onto their own subject.
	waitUntil(t, 3*time.Second, func() bool { return shed.Load() >= 1 })
	time.Sleep(200 * time.Millisecond)

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
	t.Logf("with %d sleepers of one subject in flight (handlers reached %d of %d, shed %d), "+
		"an unrelated user's read = %d",
		sleepers, inHandler.Load(), sleepers, shed.Load(), code)
	if code == http.StatusServiceUnavailable {
		t.Errorf("an unrelated account's read was SHED (503) while %d zero-byte reads were in flight. The "+
			"budget for one subject is still first-come-first-served: 15 reservations of maxBody+1 exhaust the "+
			"shipped 64 MiB, the reservation is taken before a single body byte arrives (a source that flushes "+
			"headers and stalls holds it), and the failure lands on other users. Cost to the attacker: 15 "+
			"sockets and one token", sleepers)
	} else {
		t.Logf("the read was not shed (%d): the budget arithmetic changed, so re-derive this probe", code)
	}

	// The fix is visible on the sleeper's own subject too: the excess reservations
	// must be refused THERE, not paid for by the other caller.
	if shed.Load() == 0 {
		t.Errorf("none of the %d sleepers was shed: a single subject held every reservation it asked for, "+
			"so the byte budget has no per-caller share", sleepers)
	}

	// Control: releasing the sleepers frees the budget, so the shed above was
	// caused by the held reservations and not by anything else on the path.
	stop()

	// The admitted sleepers were parked inside the upstream read (our server
	// buffers the whole body before writing any response), so their 200 is only
	// observable after the release. At least one must have been admitted, or the
	// victim's read above proves nothing about sharing the budget.
	waitUntil(t, 3*time.Second, func() bool { return admitted.Load() >= 1 })
	if admitted.Load() == 0 {
		t.Errorf("no sleeper was admitted, so the victim's read proves nothing about sharing the budget")
	}

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
