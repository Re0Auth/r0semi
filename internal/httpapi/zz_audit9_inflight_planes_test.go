package httpapi

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// AUDIT9 / S10-1 (fixed) — the in-flight per-client share is keyed by the CLIENT
// alone, so one address cannot consume the process-wide cap by spreading across
// planes.
//
// The counter used to share bucketKey with the rate limiter, i.e. "plane|address".
// With maxInFlight = 4 that gave one address two independent halves of 2, whose sum
// was the WHOLE cap: 2 slow /oauth requests plus 2 slow /v1 requests left every
// other client with 503 "server busy". The counter is now keyed by the client, so
// the share is a real half of the semaphore.
func TestAudit9OneAddressCannotHoldTheCapAcrossPlanes(t *testing.T) {
	s := &Server{maxInFlight: 4} // per-client share = 2

	var (
		mu      sync.Mutex
		entered = map[string]int{}
	)
	release := make(chan struct{})
	handler := s.withInFlightLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		entered[r.RemoteAddr]++
		mu.Unlock()
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	call := func(remote, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	waitEntered := func(remote string, want int) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			n := entered[remote]
			mu.Unlock()
			if n >= want {
				return
			}
			time.Sleep(time.Millisecond)
		}
		mu.Lock()
		n := entered[remote]
		mu.Unlock()
		t.Fatalf("%s entered the handler %d time(s), want %d", remote, n, want)
	}

	const a, b = "192.0.2.1:1", "192.0.2.2:1"
	done := make(chan int, 4)

	// One address holds its half across two planes: one protocol slot, one
	// business slot. Both are admitted.
	go func() { done <- call(a, "/oauth/token").Code }()
	waitEntered(a, 1)
	go func() { done <- call(a, "/v1/me").Code }()
	waitEntered(a, 2)

	// Its next request — on either plane — is refused: the share is per client.
	if rec := call(a, "/v1/me"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a third request from one address = %d, want 503 (its share is spent)", rec.Code)
	}
	if rec := call(a, "/oauth/token"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a cross-plane request from the same address = %d, want 503", rec.Code)
	}

	// The other half of the cap is still reachable by a different address.
	go func() { done <- call(b, "/v1/me").Code }()
	waitEntered(b, 1)
	go func() { done <- call(b, "/oauth/token").Code }()
	waitEntered(b, 2)

	mu.Lock()
	held := entered[a]
	other := entered[b]
	mu.Unlock()
	if held != 2 || other != 2 {
		t.Errorf("slots held: one address %d, another %d; want 2 and 2 "+
			"(the cap must not collapse onto one address)", held, other)
	}

	close(release)
	for i := 0; i < 4; i++ {
		if code := <-done; code != http.StatusOK {
			t.Errorf("a held request finished %d, want 200", code)
		}
	}
}
