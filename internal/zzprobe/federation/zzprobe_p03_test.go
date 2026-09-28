//go:build audit5

package zzprobe_federation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/federation"
)

// The dedicated guard for P0-3: "in-flight requests x response body" must have a
// joint bound, and it has to be counted in BYTES.
//
// The finding: the raw passthrough buffers the whole upstream body
// (`io.ReadAll`, internal/federation/service.go), 5.80 MB per request measured and
// linear in the number of requests, while the concurrency cap counted REQUESTS.
// With `max_in_flight = 512` and a 512Mi container limit that product is 2834 MiB
// ⇒ OOMKill, and an OOM kill takes every request in flight with it rather than
// refusing the one that did not fit.
//
// The guard drives the real service through its real entry point, against an
// upstream that parks inside the body read, so what is asserted is the property
// the fix exists for: how many upstream bodies this process may hold at once — and
// that a read which does not fit is refused rather than allocated.
func TestZZProbeUpstreamBufferBudgetIsJointAndInBytes(t *testing.T) {
	// Mirrors internal/federation's unexported maxBody, like the other probes do.
	const maxBody = 4 << 20

	// Each read reserves what it may hold. A body declaring Content-Length =
	// maxBody-1 reserves maxBody on the raw path (which reads up to maxBody+1), so
	// a 3x maxBody budget admits exactly 3 concurrent reads.
	const budget = 3 * maxBody
	const declared = maxBody - 1
	const callers = 8

	upstream := newParkingUpstream(declared)
	svc := budgetService(t, upstream, budget)

	results := make(chan error, callers)
	for i := 0; i < callers; i++ {
		go func() {
			res, err := svc.Raw(context.Background(), federation.RawRequest{
				User: "usr_1", Game: "phigros", Source: "src", Path: "records",
			})
			if err == nil && len(res.Body) != declared {
				err = errors.New("the body was truncated to " + strconv.Itoa(len(res.Body)))
			}
			results <- err
		}()
	}

	// Exactly the admitted number of readers may be parked in the upstream body,
	// and no more.
	if got := upstream.waitForReaders(t, 3); got != 3 {
		t.Fatalf("the upstream has %d concurrent readers, want 3 (budget %d / reservation %d)",
			got, budget, maxBody)
	}

	// The surplus callers are SHED, not queued: they must already have returned.
	// Queueing would be the wrong answer — a queue of goroutines still holds the
	// connections and requests whose memory this bound exists for.
	deadline := time.After(10 * time.Second)
	for shed := 0; shed < callers-3; shed++ {
		select {
		case err := <-results:
			if !errors.Is(err, federation.ErrBufferBudget) {
				t.Errorf("a surplus read was refused with %v, want ErrBufferBudget (a refusal, not a failure)", err)
			}
		case <-deadline:
			t.Fatalf("only %d of %d surplus reads were refused; the rest are queued, which is exactly "+
				"what a byte budget is for", shed, callers-3)
		}
	}

	// Releasing the upstream lets the admitted reads finish with whole bodies,
	// which is what makes this a shed rather than a broken read path.
	upstream.release()
	for done := 0; done < 3; done++ {
		select {
		case err := <-results:
			if err != nil {
				t.Errorf("an admitted read failed: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("an admitted read never finished after the upstream was released")
		}
	}

	if peak := upstream.peakReaders(); peak > 3 {
		t.Errorf("peak concurrent upstream readers = %d, want at most 3: the budget let more through", peak)
	}

	// The budget is in BYTES, not a hidden request cap: with the same budget and
	// small bodies, the same number of callers all get through. Without this, a
	// request-counting implementation would satisfy every assertion above.
	small := newParkingUpstream(1 << 10)
	smallSvc := budgetService(t, small, budget)
	smallResults := make(chan error, callers)
	for i := 0; i < callers; i++ {
		go func() {
			_, err := smallSvc.Raw(context.Background(), federation.RawRequest{
				User: "usr_1", Game: "phigros", Source: "src", Path: "records",
			})
			smallResults <- err
		}()
	}
	if got := small.waitForReaders(t, callers); got != callers {
		t.Fatalf("only %d of %d callers with 1 KiB bodies were admitted under the same budget: "+
			"the budget is counting requests, not bytes", got, callers)
	}
	small.release()
	for i := 0; i < callers; i++ {
		select {
		case err := <-smallResults:
			if err != nil {
				t.Errorf("a small read failed: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a small read never finished after the upstream was released")
		}
	}
}

// budgetService wires a federation service whose only relevant knob is the buffer
// budget: one source, one bound user, and the upstream under test.
func budgetService(t *testing.T, upstream *parkingUpstream, budget int) federation.Service {
	t.Helper()
	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "src", DisplayName: "Src", Issuer: "https://upstream.example",
		TokenClass: "revocable",
		RawBase:    "https://upstream.example/v1",
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings := federation.NewMemoryBindingStore()
	v := newTestVault(t)
	b := federation.Binding{User: "usr_1", Game: "phigros", Source: "src", Version: 1}
	if err := bindings.Put(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if err := v.Enroll(context.Background(), federation.BindingIdentity(b),
		mustPair(t, "upstream-token", ""), nil); err != nil {
		t.Fatal(err)
	}
	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: bindings, Vault: v,
		Doer: upstream, HTTPClient: http.DefaultClient,
		MaxBufferedBytes: budget,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// parkingUpstream answers with a response that declares size bytes and then parks
// INSIDE THE BODY READ, so the test can observe how many bodies the service is
// willing to hold at once. Parking in the body is what makes this measure the
// budget: a read the budget refuses never reaches its first Read, while a read the
// upstream merely answered has not committed any memory yet.
type parkingUpstream struct {
	size int

	mu      sync.Mutex
	readers int
	peak    int

	gate    chan struct{}
	entered chan int
}

func newParkingUpstream(size int) *parkingUpstream {
	return &parkingUpstream{size: size, gate: make(chan struct{}), entered: make(chan int, 64)}
}

func (u *parkingUpstream) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {"text/plain"}},
		ContentLength: int64(u.size),
		Request:       req,
		Body: &parkedBody{
			upstream: u,
			ctx:      req.Context(),
			rest:     u.size,
		},
	}, nil
}

// peakReaders reports the most bodies that were ever being read at once.
func (u *parkingUpstream) peakReaders() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.peak
}

// waitForReaders waits until n readers are parked at once and returns how many it
// saw when it stopped waiting. It returns early rather than failing, so the caller
// can report the number it actually observed.
func (u *parkingUpstream) waitForReaders(t *testing.T, n int) int {
	t.Helper()
	deadline := time.After(10 * time.Second)
	best := 0
	for {
		select {
		case got := <-u.entered:
			best = got
			if got >= n {
				return got
			}
		case <-deadline:
			return best
		}
	}
}

func (u *parkingUpstream) release() { close(u.gate) }

func (u *parkingUpstream) enter() {
	u.mu.Lock()
	u.readers++
	if u.readers > u.peak {
		u.peak = u.readers
	}
	n := u.readers
	u.mu.Unlock()
	select {
	case u.entered <- n:
	default:
	}
}

func (u *parkingUpstream) leave() {
	u.mu.Lock()
	u.readers--
	u.mu.Unlock()
}

// parkedBody blocks on its first Read until the gate opens, then serves the
// declared number of bytes and reports EOF. It never returns fewer bytes than the
// Content-Length it announced, which is what lets a reservation based on that
// declared length be trusted.
type parkedBody struct {
	upstream *parkingUpstream
	ctx      context.Context
	rest     int
	entered  bool
	left     bool
	mu       sync.Mutex
}

func (b *parkedBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	if !b.entered {
		b.entered = true
		b.mu.Unlock()
		b.upstream.enter()
	} else {
		b.mu.Unlock()
	}
	select {
	case <-b.upstream.gate:
	case <-b.ctx.Done():
		b.release()
		return 0, b.ctx.Err()
	}
	if b.rest <= 0 {
		b.release()
		return 0, io.EOF
	}
	n := len(p)
	if n > b.rest {
		n = b.rest
	}
	for i := 0; i < n; i++ {
		p[i] = 'x'
	}
	b.rest -= n
	return n, nil
}

func (b *parkedBody) Close() error {
	b.release()
	return nil
}

func (b *parkedBody) release() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.entered || b.left {
		return
	}
	b.left = true
	b.upstream.leave()
}
