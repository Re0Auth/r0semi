// Package ratelimit provides a per-key token-bucket limiter built on
// golang.org/x/time/rate.
//
// The map of buckets is bounded, and the bound is enforced by REFUSING to track
// more keys rather than by dropping a bucket that still holds quota. A key that
// cannot be tracked shares its shard's overflow bucket, so a caller that varies
// its key buys itself nothing: it spends the same shared budget as every other
// untracked key. Eviction exists, but only for buckets whose owner provably loses
// nothing when it happens (see reclaimLocked).
//
// The limiter is transport-agnostic; the HTTP layer decides what a key is and how
// to render a rejection — and, because a key is the whole of a client's budget, it
// must derive that key from something the client cannot write.
package ratelimit

import (
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	defaultTTL     = 10 * time.Minute
	defaultMaxKeys = 10_000
	// reclaimScan bounds how many buckets one insertion at the cap may look at
	// before giving up and sharing the overflow bucket, and the sample it takes is
	// random because Go's map iteration order is. The old version walked the whole
	// map — twice — on every insertion at the cap: 102µs per new key at ten
	// thousand buckets, measured, all of it under the lock that every request needs
	// to be admitted.
	reclaimScan = 64

	// shardCount splits the buckets across independent locks. Every request on
	// every plane goes through Check, so a single mutex was the one lock the whole
	// process contended on; with shards, two requests collide only when their keys
	// hash together. A key always lands in the same shard, so a key's budget is
	// exactly what it was — what changes is that the cap is per shard.
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
	// overflow is the bucket every key that cannot be tracked shares once the
	// shard is full. It is created on first use and is NOT in the map: it tracks
	// no key. It lives under this shard's own lock, so sharing it needs no second
	// lock and introduces no lock order to get wrong.
	overflow *bucket
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

// Size reports how many keys the limiter is tracking, across every shard. The
// overflow buckets are not counted: they track no key.
//
// It is exported for the two things that need it and cannot infer it. A guard has
// to assert "the table did not grow", and no verdict says that — the first request
// on a shared overflow bucket is admitted exactly like the first request on a
// fresh per-key bucket. An operator has to see the table approaching its cap,
// because at the cap new clients stop having budgets of their own.
func (l *Limiter) Size() int {
	total := 0
	for i := range l.shards {
		l.shards[i].mu.Lock()
		total += len(l.shards[i].buckets)
		l.shards[i].mu.Unlock()
	}
	return total
}

// MaxKeys reports the cap Size is bounded by.
func (l *Limiter) MaxKeys() int { return l.maxKeys }

// refillWindow is how long an empty bucket needs to be full again.
func (l *Limiter) refillWindow() time.Duration {
	if l.limit <= 0 {
		return 0 // rate.Inf: the bucket is full at every instant
	}
	d := float64(time.Second) * float64(l.burst) / float64(l.limit)
	if d <= 0 || d > float64(math.MaxInt64) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(d)
}

// reclaimWindow is the shortest idle time after which dropping a bucket is
// provably free: its owner's next request is admitted with a full bucket either
// way, so nothing is refunded and no quota is restored.
//
// It is deliberately NOT the TTL. A bucket idle for ten minutes is not
// necessarily full — at one token per thousand seconds it holds 0.6 of a token —
// so reclaiming on the TTL alone is a quota reset, which is precisely what a
// caller varying its key used to be able to arrange.
func (l *Limiter) reclaimWindow() time.Duration {
	w := l.refillWindow()
	if l.ttl > w {
		w = l.ttl
	}
	return w
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

// bucketLocked returns the bucket key is limited by, creating it when it is new
// and making room for it when it can. The caller holds the shard's lock.
//
// A key that is not tracked and cannot be tracked — the shard is full and nothing
// in it may be dropped — shares the shard's overflow bucket instead of displacing
// a live one. The map stays bounded, the configured rate is not weakened, and the
// caller still gets a decision rather than an error. The cost is that keys which
// arrive while the table is full share one budget; that is the fail-closed
// direction, and it is what stops "vary your key" from being a way to buy quota.
func (l *Limiter) bucketLocked(s *shard, key string, now time.Time) *bucket {
	if b, ok := s.buckets[key]; ok {
		b.lastSeen = now
		return b
	}
	if len(s.buckets) >= l.perShard() && !l.reclaimLocked(s, now) {
		if s.overflow == nil {
			s.overflow = &bucket{limiter: rate.NewLimiter(l.limit, l.burst)}
		}
		s.overflow.lastSeen = now
		return s.overflow
	}
	b := &bucket{limiter: rate.NewLimiter(l.limit, l.burst)}
	b.lastSeen = now
	s.buckets[key] = b
	return b
}

// reclaimLocked drops at most one bucket that is provably free to drop, and
// reports whether it made room. The caller holds the shard's lock.
//
// The scan is bounded (reclaimScan), so the cost of admitting a new key does not
// grow with the number of tracked keys. What changed is the condition: a bucket is
// dropped only when its owner loses nothing — see reclaimWindow — never merely
// because it is the first one the scan happened to see. Dropping an exhausted
// bucket handed its caller a fresh burst, which made a key spray a way to reset an
// honest client's budget.
func (l *Limiter) reclaimLocked(s *shard, now time.Time) bool {
	window := l.reclaimWindow()
	scanned := 0
	for key, b := range s.buckets {
		if scanned >= reclaimScan {
			break
		}
		scanned++
		if now.Sub(b.lastSeen) >= window {
			delete(s.buckets, key)
			return true
		}
	}
	return false
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
	// Shared reports that this verdict came from a shard's overflow bucket, i.e.
	// that the key is not tracked and is sharing one budget with every other
	// untracked key. It is always false for a tracked key.
	//
	// A caller that wants to surface "the limiter is at capacity" has to be told:
	// the verdict itself looks exactly like a verdict for a key of its own.
	Shared bool
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
		Shared:    b == s.overflow,
	}
	if reservation := b.limiter.ReserveN(now, 1); reservation.OK() {
		v.Reset = reservation.DelayFrom(now)
		// CancelAt(now), not Cancel: Cancel cancels at a fresh time.Now(), and
		// when the bucket still had a token the reservation's timeToAct is `now`
		// itself — already in the past by then, so CancelAt refuses to run and
		// the reserved token silently leaks out of the bucket.
		reservation.CancelAt(now)
	}
	return v
}

// evictLocked is gone: making room now happens only in reclaimLocked, under
// conditions that guarantee the key it drops loses nothing.
