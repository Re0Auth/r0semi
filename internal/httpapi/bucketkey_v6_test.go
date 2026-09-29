package httpapi

import (
	"net/http"
	"testing"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// Z11-4: the rate-limit (and in-flight) bucket key coarsens an IPv6 client to its
// /64. Keying each /128 separately let one host with one delegated prefix mint
// 2^64 keys, fill the bucket table, and leave every client it had not already
// seen sharing a drained overflow bucket.
//
// Driven through the real middleware chain: two different /128s inside one /64
// must spend ONE bucket, and an unrelated /64 must not.
func TestBucketKeyAggregatesIPv6ToSlash64(t *testing.T) {
	srv := healthServer(t, nil, ratelimit.New(0.001, 1)) // one token, effectively no refill
	h := srv.Handler()

	if rec := probe(t, h, "/v1/me", "[2001:db8:ff::1]:5555"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first request from 2001:db8:ff::1 = %d, want 401 (the limiter is not engaged)", rec.Code)
	}
	// A DIFFERENT /128 in the same /64 must be the same bucket.
	if rec := probe(t, h, "/v1/me", "[2001:db8:ff::2]:5555"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a second address in the same /64 = %d, want 429: each /128 minted its own bucket", rec.Code)
	}
	// An unrelated /64 is a different bucket and is still admitted.
	if rec := probe(t, h, "/v1/me", "[2001:db8:1::5]:5555"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an unrelated /64 = %d, want 401: the coarsening crossed a prefix boundary", rec.Code)
	}
}
