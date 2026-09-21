package httpclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fastRetry() RetryOptions {
	return RetryOptions{
		MaxRetries:      3,
		InitialInterval: time.Millisecond,
		MaxInterval:     5 * time.Millisecond,
		MaxElapsedTime:  100 * time.Millisecond,
	}
}

func TestRetryRecoversFromTransientStatus(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	doer := Retry(srv.Client(), fastRetry())
	resp, err := doer.Do(mustNewRequest(t, http.MethodGet, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
}

func TestRetryGivesUpAndReturnsLastResponse(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	doer := Retry(srv.Client(), fastRetry())
	resp, err := doer.Do(mustNewRequest(t, http.MethodGet, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// The caller sees the upstream's own failure, not a synthetic error.
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if got := attempts.Load(); got != 4 { // first try + 3 retries
		t.Fatalf("attempts = %d, want 4", got)
	}
}

// A POST must never be replayed implicitly: doing so can create a second
// resource. This is the whole reason retry is opt-out for non-idempotent verbs.
func TestRetryDoesNotReplayPost(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	doer := Retry(srv.Client(), fastRetry())
	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := doer.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
}

func TestRetryRetriesNetworkErrors(t *testing.T) {
	var attempts atomic.Int32
	doer := Retry(DoerFunc(func(*http.Request) (*http.Response, error) {
		if attempts.Add(1) < 3 {
			return nil, errors.New("connection reset")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	}), fastRetry())

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := doer.Do(mustNewRequest(t, http.MethodGet, "https://example.invalid"))
	_ = ctx
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := attempts.Load(); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
}

func TestRetryHonoursContextCancellation(t *testing.T) {
	doer := Retry(DoerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("still down")
	}), RetryOptions{MaxRetries: 100, InitialInterval: 50 * time.Millisecond, MaxElapsedTime: time.Minute})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := doer.Do(req); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
}

func mustNewRequest(t *testing.T, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
