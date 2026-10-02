//go:build audit7

// Zone 15 (performance / capacity / memory / allocation) probes for round 7.
//
// What this file claims and what it does not:
//
//   - It measures PER-OPERATION ALLOCATION (B/op, allocs/op) and COMPLEXITY CLASS
//     (how a cost scales with a population, measured inside one process so the
//     machine's concurrent load cancels out). No absolute wall-clock number is
//     quoted as a capacity figure anywhere.
//   - Every "the cost must be flat / must not allocate" assertion is deliberately
//     written in the invariant's direction, so it is RED while the defect is
//     present. Each such probe is paired with a positive control on the same
//     instrument (a flatness/allocation control that must pass), so a green
//     control failing means the instrument is broken rather than the claim true.
package z15performancecapacity

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/compress"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

// --- shared fixtures ---------------------------------------------------------

var (
	probeKeyOnce sync.Once
	probeKey     *rsa.PrivateKey
)

// probeSigner shares one RSA key: generating a 2048-bit key per store would cost
// more than the measurement and contribute nothing (the key is held, never used,
// on the paths below).
func probeSigner(tb testing.TB) *oidcstore.Signer {
	tb.Helper()
	probeKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic("z15 probe: generate RSA key: " + err.Error())
		}
		probeKey = key
	})
	return oidcstore.NewSigner("z15", probeKey)
}

func probeStore(tb testing.TB) *memory.OIDCStore {
	tb.Helper()
	clients := oauth.NewMemoryClientRegistry()
	c, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		tb.Fatal(err)
	}
	if err := clients.Create(context.Background(), c); err != nil {
		tb.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   probeSigner(tb),
	})
	if err != nil {
		tb.Fatal(err)
	}
	return store
}

// repoRoot walks up from this file to the module root, so a probe can read the
// source it makes a claim about without depending on the shell's cwd.
func repoRoot(tb testing.TB) string {
	tb.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..", "..", "..")
	root = filepath.Clean(root)
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		tb.Fatalf("repo root %q has no go.mod: %v", root, err)
	}
	return root
}

// perCall runs f calls times and returns the MINIMUM per-call cost over reps
// repetitions, plus the mean of the last repetition's total. The minimum is used
// because the machine is shared with other audit agents: noise can only add time.
func perCall(calls, reps int, f func()) time.Duration {
	best := time.Duration(1<<62 - 1)
	for r := 0; r < reps; r++ {
		start := time.Now()
		for i := 0; i < calls; i++ {
			f()
		}
		if d := time.Since(start) / time.Duration(calls); d < best {
			best = d
		}
	}
	return best
}

// --- Z15-3: the memory store's DeleteAuthRequest scans every pending code -----

// TestZ15MemoryDeleteAuthRequestScalesWithEveryPendingCode
//
// The invariant: resolving one id in a hash-keyed store is O(1). The reference
// backend agrees with it — `postgres.OIDCStore.DeleteAuthRequest` is
// `DELETE ... WHERE request_id = $1` against an index on `oidc_codes.request_id`
// (internal/store/postgres/oidc.go, migration 0008/0012).
//
// The in-memory backend does not: it ranges the WHOLE `s.codes` map under the
// store's single mutex (internal/store/memory/oidc.go:449-468) to find rows whose
// `requestID` matches. That call is not rare — the OP library invokes it on every
// token response that carries an auth request
// ($GOMODCACHE/github.com/zitadel/oidc/v3@v3.51.3/pkg/op/token.go:50,
// CreateTokenResponse), i.e. on every authorization-code exchange — so the cost
// of a token exchange grows with the number of codes other users have minted but
// not yet redeemed, and it grows while holding the lock every introspection takes.
//
// Positive control: `Counts()` (a fixed number of map lengths) must be flat across
// the same two populations. If the control is not flat, the harness — not the
// claim — is at fault.
func TestZ15MemoryDeleteAuthRequestScalesWithEveryPendingCode(t *testing.T) {
	const (
		smallCodes = 500
		largeCodes = 50_000
		smallCalls = 4_000
		largeCalls = 100
		reps       = 3
	)
	ctx := context.Background()

	fill := func(n int) *memory.OIDCStore {
		st := probeStore(t)
		for i := 0; i < n; i++ {
			if err := st.SaveAuthCode(ctx, fmt.Sprintf("req-%06d", i), fmt.Sprintf("code-%06d", i)); err != nil {
				t.Fatalf("SaveAuthCode: %v", err)
			}
		}
		got := st.Counts().Codes
		if got != n {
			t.Fatalf("anti-vacuity: the store holds %d codes, want %d (nothing to scan if this is 0)", got, n)
		}
		return st
	}

	small := fill(smallCodes)
	large := fill(largeCodes)

	// The id is deliberately absent from `authRequests`, so nothing is deleted and
	// the population does not move while it is measured. It is not absent from the
	// scan: `DeleteAuthRequest` walks the codes map either way.
	const absent = "req-that-does-not-exist"

	smallCall := perCall(smallCalls, reps, func() { _ = small.DeleteAuthRequest(ctx, absent) })
	largeCall := perCall(largeCalls, reps, func() { _ = large.DeleteAuthRequest(ctx, absent) })
	smallCtl := perCall(smallCalls, reps, func() { _ = small.Counts() })
	largeCtl := perCall(largeCalls, reps, func() { _ = large.Counts() })

	if got := small.Counts().Codes; got != smallCodes {
		t.Fatalf("the measured calls mutated the population: codes = %d, want %d", got, smallCodes)
	}
	if got := large.Counts().Codes; got != largeCodes {
		t.Fatalf("the measured calls mutated the population: codes = %d, want %d", got, largeCodes)
	}

	t.Logf("control Counts():             %8d codes -> %-12v ; %8d codes -> %-12v",
		smallCodes, smallCtl, largeCodes, largeCtl)
	t.Logf("DeleteAuthRequest(absent id): %8d codes -> %-12v ; %8d codes -> %-12v  (x%.1f)",
		smallCodes, smallCall, largeCodes, largeCall, float64(largeCall)/float64(smallCall))

	// Positive control: an O(1) store call must not care about the population.
	if ctlRatio := float64(largeCtl) / float64(smallCtl); ctlRatio > 3 {
		t.Fatalf("harness broken: the O(1) control grew x%.1f across populations; timing here is not usable", ctlRatio)
	}

	// The invariant. The scan makes the per-call cost track the population, and it
	// runs inside the store's single mutex, so every concurrent authenticated read
	// waits behind it.
	if ratio := float64(largeCall) / float64(smallCall); ratio >= 10 {
		t.Errorf("CONFIRMED: O(pending codes) scan under the store-wide lock: "+
			"DeleteAuthRequest costs %v at %d pending codes and %v at %d (x%.1f) "+
			"while the O(1) control is flat; the OP library calls it on every "+
			"authorization-code token response (pkg/op/token.go:50)",
			smallCall, smallCodes, largeCall, largeCodes, ratio)
	}
}

// --- Z15-1: the Postgres sweep has no bound on a single cycle -----------------

// TestZ15SweepDeletesAreUnboundedAndAtomic
//
// The invariant: a maintenance pass that runs on a timer must make bounded
// progress per cycle, so that a backlog larger than one cycle's budget is worked
// off over several cycles instead of never.
//
// What the source does instead (internal/store/postgres/sweep.go:26-71): ten
// unbounded `DELETE FROM <table> WHERE <col> < $1` statements, all inside ONE
// transaction, driven by the sweepLoop ticker (cmd/re0auth/main.go:1101-1124)
// which logs a failure and tries the same work again next tick. The pool's
// statement_timeout is 30s by default and is applied per statement on every
// connection (internal/store/postgres/postgres.go:128,235-246).
//
// Consequences, in the order they matter: (a) the unit of progress is "all expired
// rows or nothing", so a backlog whose delete exceeds 30s is rolled back in full
// and re-attempted forever — the tables are never swept again until an operator
// deletes by hand; (b) that retry holds a pooled connection for up to the sum of
// the per-statement budgets, in exactly the outage window where the pool is
// already the scarce resource; (c) a single 15-minute window's deletions are one
// transaction, so autovacuum and every concurrent INSERT into those tables meet
// the whole batch at once.
//
// Positive control: the same boundedness detector must classify a synthetic
// `DELETE ... LIMIT` statement as bounded, and the parser must find all ten
// configured tables. Both are asserted before the claim is made, so a parser that
// silently matches nothing fails here rather than "passing".
func TestZ15SweepDeletesAreUnboundedAndAtomic(t *testing.T) {
	root := repoRoot(t)

	sweepSrc := readFile(t, filepath.Join(root, "internal", "store", "postgres", "sweep.go"))
	poolSrc := readFile(t, filepath.Join(root, "internal", "store", "postgres", "postgres.go"))
	mainSrc := readFile(t, filepath.Join(root, "cmd", "re0auth", "main.go"))

	// --- instrument, with its positive control -------------------------------
	deleteStmt := regexp.MustCompile(`DELETE FROM %s WHERE %s < \$1`)
	tableEntry := regexp.MustCompile(`\{"([a-z_]+)", "([a-z_]+)"\}`)
	limitRe := regexp.MustCompile(`(?i)\bLIMIT\b`)

	if !limitRe.MatchString("DELETE FROM t WHERE c < $1 LIMIT 1000") {
		t.Fatal("harness broken: the boundedness detector does not see a LIMIT")
	}
	if limitRe.MatchString("DELETE FROM t WHERE c < $1") {
		t.Fatal("harness broken: the boundedness detector sees a LIMIT where there is none")
	}

	tables := tableEntry.FindAllStringSubmatch(sweepSrc, -1)
	stmts := deleteStmt.FindAllString(sweepSrc, -1)
	if len(tables) == 0 || len(stmts) == 0 {
		t.Fatalf("harness broken: parsed %d table entries and %d delete templates from sweep.go; "+
			"the file no longer has the shape this probe reads", len(tables), len(stmts))
	}
	if !strings.Contains(sweepSrc, "for _, t := range expiredTables") {
		t.Fatal("harness broken: the loop over expiredTables was not found; the probe reads the wrong construct")
	}

	// --- the claim -----------------------------------------------------------
	var problems []string
	if !limitRe.MatchString(sweepSrc) {
		problems = append(problems, fmt.Sprintf(
			"%d DELETE statements (one per configured table, now %d tables) carry no LIMIT, so one "+
				"cycle removes every expired row or none", len(stmts), len(tables)))
	}
	if strings.Count(sweepSrc, "Begin(ctx)") != 1 || strings.Count(sweepSrc, "Commit(ctx)") != 1 {
		problems = append(problems, "the per-table deletes are not in exactly one transaction")
	}
	if !regexp.MustCompile(`StatementTimeout:\s+30 \* time\.Second`).MatchString(poolSrc) ||
		!strings.Contains(poolSrc, `RuntimeParams["statement_timeout"]`) {
		problems = append(problems, "the statement_timeout ceiling this reasoning depends on was not found")
	}
	if !strings.Contains(mainSrc, `slog.Warn("expiry sweep failed"`) {
		problems = append(problems, "sweepLoop no longer logs a failed sweep; the reasoning about retry changed")
	}
	if len(problems) > 0 {
		t.Errorf("%s", "CONFIRMED (source level): the expiry sweep makes unbounded, all-or-nothing progress per cycle:\n  - "+
			strings.Join(problems, "\n  - "))
	}
	t.Logf("sweep shape: %d tables, %d delete templates, LIMIT present=%v, one transaction=%v",
		len(tables), len(stmts), limitRe.MatchString(sweepSrc),
		strings.Count(sweepSrc, "Begin(ctx)") == 1)
}

func readFile(tb testing.TB, path string) string {
	tb.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// --- Z15-2: a benchmark whose janitor guard cannot run -------------------------

// TestZ15JanitorBenchmarkGuardIsVacuousAtSmallIterationCounts — 原为发现演示，现为回归守卫.
//
// Z15-2: BenchmarkTokenLifecycleWithJanitor put its sampling, its janitor call and
// its `janitor found nothing` guard behind `i%sweepEvery == sweepEvery-1` with
// sweepEvery = 1024, so a fixed iteration count below 1024 never reached them: the
// benchmark reported `peak_records 0` and exited 0.
//
// It is fixed at internal/store/memory/oidc_bench_test.go:108-113: after the loop,
// if the janitor never ran, the same pass runs once, and a zero peak is itself a
// b.Fatalf. The reported high-water mark is therefore reachable at every count.
//
// The guard is deterministic: -benchtime=Nx pins the iteration count, so no
// wall-clock threshold is involved. At 200x and 2000x the run must exit 0 and
// report a NONZERO peak_records, the number must stay bounded by the sweep
// interval (two records per iteration, sampled before the sweep), and it must not
// grow with the run length.
func TestZ15JanitorBenchmarkGuardIsVacuousAtSmallIterationCounts(t *testing.T) {
	root := repoRoot(t)

	run := func(benchtime string) (peak int, ok bool, out string) {
		cmd := exec.Command("go", "test", "-count=1", "-run", "^$",
			"-bench", "BenchmarkTokenLifecycleWithJanitor",
			"-benchtime="+benchtime, "./internal/store/memory/")
		cmd.Dir = root
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		err := cmd.Run()
		out = buf.String()
		if err != nil {
			return 0, false, out
		}
		line := ""
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "peak_records") && strings.Contains(l, "ns/op") {
				line = l
			}
		}
		if line == "" {
			return 0, false, out
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "peak_records" && i > 0 {
				// go's benchmark metric formatter uses four significant digits,
				// so a small count prints as "400.0" and a larger one as "2048".
				n, perr := strconv.ParseFloat(fields[i-1], 64)
				if perr != nil {
					return 0, false, out
				}
				return int(n), true, out
			}
		}
		return 0, false, out
	}

	// The benchmark mints two records per iteration and samples the high-water
	// mark before the sweep, so a bounded population cannot exceed 2*sweepEvery.
	const sweepEvery = 1024
	const peakBound = 2 * sweepEvery

	largePeak, largeOK, largeOut := run("2000x")
	if !largeOK {
		t.Fatalf("harness broken: the 2000x run produced no parsable result:\n%s", tail(largeOut, 20))
	}
	if largePeak <= 0 {
		t.Fatalf("positive control failed: the 2000x run reported peak_records=%d, so the guard is "+
			"unreachable at every count and this probe cannot attribute the cause", largePeak)
	}
	if largePeak > peakBound {
		t.Errorf("the 2000x run reported peak_records=%d, above the %d the sweep interval bounds: the "+
			"population no longer looks bounded", largePeak, peakBound)
	}

	smallPeak, smallOK, smallOut := run("200x")
	if !smallOK {
		t.Fatalf("REGRESSION: the 200x run produced no parsable result (exit != 0 or no line):\n%s",
			tail(smallOut, 20))
	}

	t.Logf("peak_records: 2000x -> %d ; 200x -> %d", largePeak, smallPeak)
	if smallPeak <= 0 {
		t.Errorf("REGRESSION: at -benchtime=200x the janitor benchmark reports peak_records=%d and exits 0; "+
			"the post-loop pass at oidc_bench_test.go:108-113 must make the sweep, the sampling and the "+
			"`janitor found nothing` guard reachable at every iteration count (2000x reports %d)",
			smallPeak, largePeak)
	}
	if smallPeak > largePeak {
		t.Errorf("the reported population grew with the run length (200x=%d > 2000x=%d), so peak_records "+
			"no longer shows the sweep interval bounding it", smallPeak, largePeak)
	}
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// --- Z15-4 guard: listing the registry must not hand callers the live slice ----

// TestZ15RegistryListingCannotMutateTheRegistry
//
// `Registry` is built once at startup and never mutated afterwards, so the only
// defensible contract for a listing read is "a snapshot the caller owns": a caller
// that sorts, truncates or overwrites what it got back must not change what the
// next caller sees. That is the property this probe asserts; it is a guard, not a
// finding.
//
// It also logs the per-call allocation, which is the quantified form of round 5's
// PERF-8 sub-item ("Registry.Sources(game) 每次调用都复制 + 排序",
// internal/federation/federation.go:250-254). **That item is already recorded in
// round 5 and is deliberately NOT re-reported here** — the number is printed so a
// future reader can see whether the copy is still there, not as a new claim.
//
// Aliasing was a real alternative (returning the internal slice with no copy would
// allocate 0 per call and be wrong for exactly this reason), so the control below
// asserts the snapshot is genuinely independent before the allocation note is
// printed.
func TestZ15RegistryListingCannotMutateTheRegistry(t *testing.T) {
	sources := make([]federation.Source, 0, 8)
	for i := 0; i < 8; i++ {
		sources = append(sources, federation.Source{
			Game:      "phigros",
			Name:      fmt.Sprintf("src-%02d", i),
			Issuer:    "https://src.example",
			Resources: []federation.Resource{{Name: "score", Scope: "phigros.score.read"}},
		})
	}
	reg, err := federation.NewRegistry(sources...)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	first := reg.Sources("phigros")
	if len(first) != len(sources) {
		t.Fatalf("anti-vacuity: Sources returned %d sources, want %d", len(first), len(sources))
	}
	// The caller owns its snapshot: overwriting it must not be visible to the next
	// caller. If the registry returned its internal slice, this next read would see
	// the clobbered entry and the probe would fail here.
	first[0] = federation.Source{Game: "clobbered", Name: "clobbered"}
	second := reg.Sources("phigros")
	if second[0].Name == "clobbered" {
		t.Fatalf("Sources() handed the caller the registry's own backing array: " +
			"a caller's write was visible to the next read")
	}
	if second[0].Name != "src-00" {
		t.Fatalf("anti-vacuity: expected the first registered source, got %q", second[0].Name)
	}

	sourcesAllocs := testing.AllocsPerRun(500, func() { _ = reg.Sources("phigros") })
	b := testing.Benchmark(func(b *testing.B) {
		for b.Loop() {
			_ = reg.Sources("phigros")
		}
	})
	t.Logf("note (PERF-8 repro, not a new finding): Sources(game) allocs/call=%.1f, %d B/op",
		sourcesAllocs, b.AllocedBytesPerOp())
}

// --- held: the limiter's admission path must not allocate per request ----------

// TestZ15RateLimiterCheckAllocatesNothing
//
// `Limiter.Check` is the one call every request on every plane makes
// (internal/httpapi/middleware.go:355), and its own doc explains that the hash is
// written out rather than taken from hash/fnv "so that a per-request call
// allocates nothing" (internal/ratelimit/ratelimit.go:69-82). This asserts that
// property on the admitted, tracked-key path: the bucket exists, so admission is a
// map lookup plus rate.Limiter bookkeeping.
//
// It is a guard in the invariant's direction (a nonzero count fails), and the
// control is the anti-vacuity assertion that the same key really was admitted —
// otherwise "0 allocs" could just mean "Check did nothing".
func TestZ15RateLimiterCheckAllocatesNothing(t *testing.T) {
	l := ratelimit.New(1000, 100)
	const key = "business|203.0.113.7"

	if v := l.Check(key); !v.Allowed {
		t.Fatalf("anti-vacuity: the first Check was refused (%+v)", v)
	}
	if l.Size() != 1 {
		t.Fatalf("anti-vacuity: the limiter tracks %d keys, want the one just admitted", l.Size())
	}

	allocs := testing.AllocsPerRun(2000, func() { _ = l.Check(key) })
	b := testing.Benchmark(func(b *testing.B) {
		for b.Loop() {
			_ = l.Check(key)
		}
	})
	t.Logf("Check(tracked key): allocs/call=%.1f, %d B/op; tracked keys=%d", allocs, b.AllocedBytesPerOp(), l.Size())
	if allocs > 0 {
		t.Errorf("CONFIRMED: Check allocates %.0f time(s) per request on the tracked-key path (%d B/op); "+
			"the FNV write-out at ratelimit.go:69-82 was supposed to keep this at zero",
			allocs, b.AllocedBytesPerOp())
	}
}

// --- Z15-5: negotiation allocates once per configured coding ------------------

// TestZ15CompressionNegotiationAllocatesPerConfiguredCoding — 原为发现演示，现为回归守卫.
//
// Z15-4: negotiate's fast path (`Accept-Encoding` with no `;` or `*`) asked
// `offered(name)` for each configured coding in server-preference order, and each
// call ran its own `strings.Split(header, ",")`, so a client whose header matched
// only the last preferred coding paid one slice allocation per configured coding
// ahead of it.
//
// It is fixed at internal/compress/compress.go:192-205: the fast path splits the
// header once, outside the per-coding loop, so its cost no longer grows with the
// server's own configuration.
//
// The guard measures a full request through the compressor and requires the
// allocation count not to grow when a leading, non-matching coding is added. The
// general path (`;`) is the anti-vacuity control: it must still allocate measurably
// more, otherwise allocations are not what the probe is measuring.
func TestZ15CompressionNegotiationAllocatesPerConfiguredCoding(t *testing.T) {
	coding := func(name string) compress.Encoding {
		return compress.Encoding{Name: name, New: func() compress.WriteCloser {
			return gzip.NewWriter(io.Discard)
		}}
	}

	measure := func(codings []compress.Encoding, accept string) float64 {
		c, err := compress.New(compress.Config{Encodings: codings})
		if err != nil {
			t.Fatalf("compress.New: %v", err)
		}
		h := c.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("ok"))
		}))
		req := httptest.NewRequest(http.MethodGet, "/v1/thing", nil)
		req.Header.Set("Accept-Encoding", accept)
		return testing.AllocsPerRun(300, func() {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
		})
	}

	// The header names only the second preferred coding, so the fast path must
	// evaluate (but not re-split for) the first one before it matches.
	one := measure([]compress.Encoding{coding("gzip")}, "gzip")
	two := measure([]compress.Encoding{coding("zstd"), coding("gzip")}, "gzip")
	general := measure([]compress.Encoding{coding("zstd"), coding("gzip")}, "gzip;q=1.0")

	t.Logf("allocs/request through the compressor: 1 coding=%.1f, 2 codings=%.1f (delta %.1f); "+
		"general path=%.1f", one, two, two-one, general)

	// Anti-vacuity: a header with `;` takes the general path, which parses the
	// header into a map, so it must cost measurably more. If it does not, the
	// allocation counts below are not attributable to negotiation at all.
	if general <= two {
		t.Fatalf("harness broken: a header with `;` did not allocate measurably more than the fast path "+
			"(fast=%.1f general=%.1f); the probe is not measuring the negotiation path", two, general)
	}
	if delta := two - one; delta >= 1 {
		t.Errorf("REGRESSION: adding a leading, non-matching coding added %.1f allocation(s) per request "+
			"(compress.go:192-205 must `strings.Split` the header once, outside the per-coding loop)", delta)
	}
}
