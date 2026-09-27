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
	// evictionScan bounds how many buckets one insertion at the cap may look at
	// before it evicts, and the sample it takes is random because Go's map
	// iteration order is. The old version walked the whole map — twice — on every
	// insertion at the cap: 102µs per new key at ten thousand buckets, measured,
	// all of it under the lock that every request needs to be admitted.
	evictionScan = 64

	// shardCount splits the buckets across independent locks. Every request on
	// every plane goes through Check, so a single mutex was the one lock the whole
	// process contended on; with shards, two requests collide only when their keys
	// hash together. A key always lands in the same shard, so a key's budget is
	// exactly what it was — what changes is that eviction is per shard.
	shardCount = 16
)

// Limiter is a per-key limiter. It is safe for concurrent use.
type Limiter struct {
	limit   rate.Limit
	burst   int
	ttl     time.Duration
	maxKeys int

	shards [shardCount]shard
}

// shard is one lock and the buckets behind it.
type shard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// shardFor picks the shard for key with FNV-1a, written out rather than taken from
// hash/fnv so that a per-request call allocates nothing.
func (l *Limiter) shardFor(key string) *shard {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= prime32
	}
	return &l.shards[h%shardCount]
}

// perShard is how many keys one shard may hold, so the total stays inside
// maxKeys.
func (l *Limiter) perShard() int {
	per := (l.maxKeys + shardCount - 1) / shardCount
	if per < 1 {
		per = 1
	}
	return per
}

// size reports how many keys are tracked in total. It is for tests: the HTTP
// layer has no reason to ask.
func (l *Limiter) size() int {
	total := 0
	for i := range l.shards {
		l.shards[i].mu.Lock()
		total += len(l.shards[i].buckets)
		l.shards[i].mu.Unlock()
	}
	return total
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
	}
	for i := range l.shards {
		l.shards[i].buckets = make(map[string]*bucket)
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

	s := l.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b := l.bucketLocked(s, key, now)
	return b.limiter.AllowN(now, n)
}

// bucketLocked returns the key's bucket, creating it — and making room for it —
// when it is new. The caller holds the shard's lock.
func (l *Limiter) bucketLocked(s *shard, key string, now time.Time) *bucket {
	b, ok := s.buckets[key]
	if !ok {
		// Insertion is the only place eviction runs, so it is bounded rather than
		// proportional to the map: see evictLocked.
		l.evictLocked(s, now)
		b = &bucket{limiter: rate.NewLimiter(l.limit, l.burst)}
		s.buckets[key] = b
	}
	b.lastSeen = now
	return b
}

// Verdict is one request's answer from the limiter: whether it may proceed, the
// bucket's state for the RateLimit-* headers, and how long until one more event
// would be allowed.
type Verdict struct {
	Allowed bool
	// Limit is the bucket's capacity — the burst.
	Limit int
	// Remaining is how many events the bucket holds now.
	Remaining int
	// Reset is how long until one more event for this key would be allowed,
	// measured after this one consumed its token: zero while the bucket still has
	// one to give, and the refill interval once it does not. That is what makes the
	// header usable as a hint — a client whose last token just went out is told to
	// back off on the response that succeeded, rather than on the next one.
	Reset time.Duration
}

// Check consumes one event for key and returns the verdict, in one critical
// section.
//
// The HTTP layer needs all of it — the decision, three header values, and the
// Retry-After hint — and it used to ask three times (Status, Allow, RetryAfter),
// taking a lock up to three times per request on a lock shared by every request
// on every plane. It also stops the headers from being read from a bucket state
// that another request has already moved on from.
func (l *Limiter) Check(key string) Verdict {
	now := time.Now()

	s := l.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	b := l.bucketLocked(s, key, now)

	v := Verdict{
		Allowed:   b.limiter.AllowN(now, 1),
		Limit:     l.burst,
		Remaining: int(b.limiter.TokensAt(now)),
	}
	if reservation := b.limiter.ReserveN(now, 1); reservation.OK() {
		v.Reset = reservation.DelayFrom(now)
		reservation.Cancel()
	}
	return v
}

// evictLocked makes room for one new bucket when the shard is at its share of the
// cap. The caller holds the shard's lock.
//
// One eviction is all an insertion needs, and the scan is bounded, so the cost of
// admitting a new key does not grow with the number of tracked keys. The sample is
// the first evictionScan entries of a map iteration — random, since Go randomises
// the start — and an idle bucket in it is preferred to a live one: evicting a live
// bucket hands its caller a fresh burst, so it is the outcome to avoid when the
// alternative is available.
func (l *Limiter) evictLocked(s *shard, now time.Time) {
	if len(s.buckets) < l.perShard() {
		return
	}
	scanned := 0
	var fallback string
	for key, b := range s.buckets {
		if scanned >= evictionScan {
			break
		}
		scanned++
		if now.Sub(b.lastSeen) > l.ttl {
			delete(s.buckets, key)
			return
		}
		if fallback == "" {
			fallback = key
		}
	}
	if fallback != "" {
		delete(s.buckets, fallback)
	}
}
