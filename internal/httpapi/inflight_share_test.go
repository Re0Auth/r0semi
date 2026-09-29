package httpapi

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Z11-5: the in-flight cap is shared per (plane, client), not owned by whichever
// address arrives first. With maxInFlight = 2, one client may hold at most one
// slot; the other is headroom a different client can still use. Before this, one
// address could hold both slots with slow-body sockets and every other client got
// 503 while /healthz and /readyz stayed 200.
func TestInFlightCapIsSharedPerClient(t *testing.T) {
	s := &Server{maxInFlight: 2}

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
	call := func(remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
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
		t.Fatalf("%s never entered the handler %d time(s)", remote, want)
	}

	const a, b = "192.0.2.1:1", "192.0.2.2:1"
	done := make(chan int, 2)
	go func() { done <- call(a).Code }()
	waitEntered(a, 1)

	if rec := call(a); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a second request from the same client = %d, want 503 (its share is spent)", rec.Code)
	}
	go func() { done <- call(b).Code }()
	waitEntered(b, 1)

	close(release)
	for i := 0; i < 2; i++ {
		if code := <-done; code != http.StatusOK {
			t.Fatalf("a held request finished %d, want 200", code)
		}
	}
}
