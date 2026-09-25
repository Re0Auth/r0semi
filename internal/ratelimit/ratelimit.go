// Package ratelimit provides a per-key token-bucket limiter built on
// golang.org/x/time/rate.
//
// Keys are evicted once idle, so a caller that varies its key cannot grow the
// map without bound. The limiter is transport-agnostic; the HTTP layer decides
// what a key is and how to render a rejection.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	defaultTTL     = 10 * time.Minute
	defaultMaxKeys = 10_000
)

// Limiter is a per-key limiter. It is safe for concurrent use.
type Limiter struct {
	limit   rate.Limit
	burst   int
	ttl     time.Duration
	maxKeys int

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// Option tunes a Limiter.
type Option func(*Limiter)

// WithTTL sets how long an idle key is remembered. Defaults to ten minutes.
func WithTTL(d time.Duration) Option { return func(l *Limiter) { l.ttl = d } }

// WithMaxKeys caps how many keys are tracked at once. Defaults to 10,000.
func WithMaxKeys(n int) Option { return func(l *Limiter) { l.maxKeys = n } }

// New returns a limiter allowing perSecond events per key, with the given burst.
//
// It uses golang.org/x/time/rate internally, which reads the wall clock itself;
// there is deliberately no clock injection, because mixing an injected clock
// with rate.Limiter's own time bookkeeping silently mis-computes refills.
func New(perSecond float64, burst int, opts ...Option) *Limiter {
	if burst <= 0 {
		burst = 1
	}
	l := &Limiter{
		limit:   rate.Limit(perSecond),
		burst:   burst,
		ttl:     defaultTTL,
		maxKeys: defaultMaxKeys,
		buckets: make(map[string]*bucket),
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// Allow reports whether one event for key may proceed now.
func (l *Limiter) Allow(key string) bool { return l.AllowN(key, 1) }

// AllowN reports whether n events for key may proceed now.
func (l *Limiter) AllowN(key string, n int) bool {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		l.evictLocked(now)
		b = &bucket{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.buckets[key] = b
	}
	b.lastSeen = now
	return b.limiter.AllowN(now, n)
}

// Status reports the bucket's quota, remaining tokens and the delay until one
// more token is available. It is what the RateLimit-* response headers are made
// from. It does not consume a token; unknown keys report the full burst.
func (l *Limiter) Status(key string) (limit int, remaining int, reset time.Duration) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		return l.burst, l.burst, 0
	}
	remaining = int(b.limiter.TokensAt(now))
	reservation := b.limiter.ReserveN(now, 1)
	if reservation.OK() {
		reset = reservation.DelayFrom(now)
		reservation.Cancel()
	}
	return l.burst, remaining, reset
}

// RetryAfter reports how long until one more event for key would be allowed. It
// is a hint for the Retry-After header.
func (l *Limiter) RetryAfter(key string) time.Duration {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		return 0
	}
	reservation := b.limiter.ReserveN(now, 1)
	if !reservation.OK() {
		return 0
	}
	delay := reservation.DelayFrom(now)
	reservation.Cancel()
	return delay
}

// evictLocked drops idle buckets, and if that is not enough, the oldest-looking
// ones, so the map cannot exceed maxKeys.
func (l *Limiter) evictLocked(now time.Time) {
	if len(l.buckets) < l.maxKeys {
		return
	}
	for key, b := range l.buckets {
		if now.Sub(b.lastSeen) > l.ttl {
			delete(l.buckets, key)
		}
	}
	for key := range l.buckets {
		if len(l.buckets) < l.maxKeys {
			return
		}
		delete(l.buckets, key)
	}
}
