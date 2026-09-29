//go:build audit7

// Z11-4 verification from the HTTP side: the reviewed probe drives
// ratelimit.Limiter.Check directly, which is the same call the middleware makes
// (middleware.go:355) but not the same entry point. This probe mounts the
// saturated limiter in the REAL middleware chain and shows the 429 a brand-new
// client receives, with an unsaturated limiter as the positive control.
package zzprobe_z11verify

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

func z11vKey(i int) string { return fmt.Sprintf("business|2001:db8:ff::%x", i) }

// TestZ11VOverflowStarvesThroughTheRealMiddleware is red when a table filled from
// one IPv6 /64 makes an unrelated client's real HTTP request a 429.
func TestZ11VOverflowStarvesThroughTheRealMiddleware(t *testing.T) {
	const rate = 1e-6 // one token per ~11.6 days: no refill during the probe
	l := ratelimit.New(rate, 2)
	prefix := netip.MustParsePrefix("2001:db8:ff::/64")

	// Positive control: the request shape used below is not a 429 on an
	// unsaturated limiter (it is the business plane's 401).
	fresh := miniAPI(t, miniConfig{Limiter: ratelimit.New(rate, 2)})
	freshCode := status(t, fresh.URL+"/v1/me")
	t.Logf("positive control (unsaturated limiter, same request): /v1/me = %d", freshCode)
	if freshCode != http.StatusUnauthorized {
		t.Fatalf("the control answered %d, want 401: the probe cannot attribute a 429 below to the table", freshCode)
	}

	// Fill every shard from one /64, then drain every shard's overflow bucket.
	tracked := 0
	for i := 1; i <= 400_000 && l.Size() < l.MaxKeys(); i++ {
		k := z11vKey(i)
		before := l.Size()
		l.Allow(k)
		if l.Size() > before {
			tracked++
		}
	}
	if l.Size() != l.MaxKeys() {
		t.Fatalf("Size=%d, want MaxKeys=%d: could not fill from one /64", l.Size(), l.MaxKeys())
	}
	for i := 400_001; i <= 900_000; i++ {
		l.Allow(z11vKey(i))
	}
	// Sanity: every key we created is inside the one /64, so the resources to
	// fill this table are one delegated prefix.
	for i := 1; i <= tracked; i++ {
		if a, err := netip.ParseAddr(strings.TrimPrefix(z11vKey(i), "business|")); err != nil || !prefix.Contains(a) {
			t.Fatalf("probe escaped its /64 at i=%d", i)
		}
	}

	srv := miniAPI(t, miniConfig{Limiter: l})
	code := status(t, srv.URL+"/v1/me")
	body := bodyOf(t, srv.URL+"/v1/me")
	t.Logf("after one /64 filled all %d buckets and drained every overflow bucket: an unrelated client's "+
		"GET /v1/me = %d %s", l.MaxKeys(), code, body)
	if code != http.StatusTooManyRequests {
		t.Errorf("the unrelated client was answered %d although the table is full and every overflow bucket is "+
			"empty: re-derive the probe", code)
	}
}

func status(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func bodyOf(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
