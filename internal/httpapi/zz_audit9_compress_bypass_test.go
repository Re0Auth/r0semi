package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/oauth"
)

// AUDIT9 / S13-1 (fixed) — a compressor negotiation refusal is rate limited and
// counted in flight.
//
// The compressor can answer on its own: negotiate() finds nothing acceptable and
// compress.Handler writes a 406 without ever calling next. It used to wrap the
// limiter and the in-flight cap, so that path spent no rate-limit token and held
// no slot, and any unauthenticated caller could drive it without limit. It is now
// installed INSIDE both. These tests drive the real Server.Handler() chain, so a
// future re-ordering is caught here rather than by a hand-built chain.

func TestAudit9CompressorRefusalIsRateLimited(t *testing.T) {
	env := newTestEnv(t)
	limited, err := New(Config{
		Issuer:            testIssuer,
		OIDC:              env.handler,
		TokenIntrospector: env.handler,
		GrantStore:        env.store,
		DeviceStore:       env.store,
		Limiter:           ratelimit.New(0.001, 1), // one token, effectively no refill
	})
	if err != nil {
		t.Fatal(err)
	}
	// One handler instance, as a real server serves every request through the same
	// chain: withInFlightLimit allocates its semaphore when the chain is built, so
	// calling Handler() per request would give each request its own.
	h := limited.Handler()
	do := func(accept string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
		req.RemoteAddr = "203.0.113.9:1"
		if accept != "" {
			req.Header.Set("Accept-Encoding", accept)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	do("") // spend the single token
	if rec := do("identity;q=0"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("compressor refusal = %d, want 429: the limiter must run before the "+
			"compressor can answer", rec.Code)
	}
}

// audit9BlockingIntrospector parks an authenticated request inside the handler, so
// the single in-flight slot is held while a second request is sent.
type audit9BlockingIntrospector struct {
	entered chan struct{}
	release chan struct{}
}

func (b *audit9BlockingIntrospector) Introspect(context.Context, string) (oauth.TokenInfo, error) {
	close(b.entered)
	<-b.release
	return oauth.TokenInfo{}, nil
}

func TestAudit9CompressorRefusalCountsInFlight(t *testing.T) {
	env := newTestEnv(t)
	block := &audit9BlockingIntrospector{entered: make(chan struct{}), release: make(chan struct{})}
	srv, err := New(Config{
		Issuer:            testIssuer,
		OIDC:              env.handler,
		TokenIntrospector: block,
		GrantStore:        env.store,
		DeviceStore:       env.store,
		MaxInFlight:       1,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	do := func(accept string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
		req.RemoteAddr = "203.0.113.10:1"
		req.Header.Set("Authorization", "Bearer stub")
		if accept != "" {
			req.Header.Set("Accept-Encoding", accept)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	held := make(chan int, 1)
	go func() { held <- do("").Code }()
	<-block.entered

	// The only slot is held by that request. A negotiation refusal must now be
	// refused for concurrency instead of being answered.
	if rec := do("identity;q=0"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("compressor refusal = %d, want 503: the in-flight cap must run before "+
			"the compressor can answer", rec.Code)
	}

	close(block.release)
	if code := <-held; code == http.StatusServiceUnavailable {
		t.Errorf("the request that held the slot was refused (%d)", code)
	}
}
