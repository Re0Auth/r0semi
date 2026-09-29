//go:build audit7

// Zone 15 adversarial verification probes (round 7).
//
// Each probe here tries to FALSIFY a claim made by the Z15 report
// (scratchpad/audit7/findings/Z15-performance-capacity.md). A probe that fails
// means the report's mechanism or its instrument is wrong; a probe that passes
// with the expected numbers is independent evidence FOR the report.
//
// These probes re-derive their numbers through their own fixtures rather than
// reusing the reviewed probe package, so a bug in the reviewed instrument cannot
// hide here too.
package z15verify

import (
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/compress"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

var (
	vKeyOnce sync.Once
	vKey     *rsa.PrivateKey
)

func vSigner(tb testing.TB) *oidcstore.Signer {
	tb.Helper()
	vKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			tb.Fatalf("generate RSA key: %v", err)
		}
		vKey = k
	})
	return oidcstore.NewSigner("z15verify", vKey)
}

// --- shared fixture -----------------------------------------------------------

func vRepoRoot(tb testing.TB) string {
	tb.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		tb.Fatalf("repo root %q has no go.mod: %v", root, err)
	}
	return root
}

func vRead(tb testing.TB, path string) string {
	tb.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// vClock is the injectable clock, so a record can be aged past its deadline
// without sleeping.
type vClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *vClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *vClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// --- FALSIFICATION 1: is the fast path really split once per configured coding?-

// TestZ15VCompressionSplitScalesPerConfiguredCoding re-derives the Z15-4 delta.
//
// Z15-4 claims the header is re-split once for every server-preferred coding
// ahead of the client's match, so the allocation delta over a one-coding
// configuration must be exactly (number of codings ahead). The reviewed probe
// only compared 1 vs 2 codings — a single +1 could equally come from any one-off
// in the two-element configuration. This probe measures 1, 2, 3 and 4 codings
// where the client's `gzip` is always last: if the delta is not (n-1) the
// mechanism is mis-attributed and the report's explanation is wrong.
func TestZ15VCompressionSplitScalesPerConfiguredCoding(t *testing.T) {
	coding := func(name string) compress.Encoding {
		return compress.Encoding{Name: name, New: func() compress.WriteCloser {
			return gzip.NewWriter(io.Discard)
		}}
	}
	preceding := []string{"zstd", "br", "deflate"}

	measure := func(names []string, accept string) float64 {
		encs := make([]compress.Encoding, 0, len(names))
		for _, n := range names {
			encs = append(encs, coding(n))
		}
		c, err := compress.New(compress.Config{Encodings: encs})
		if err != nil {
			t.Fatalf("compress.New: %v", err)
		}
		h := c.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("ok"))
		}))
		req := httptest.NewRequest(http.MethodGet, "/v1/thing", nil)
		req.Header.Set("Accept-Encoding", accept)
		return testing.AllocsPerRun(200, func() {
			h.ServeHTTP(httptest.NewRecorder(), req)
		})
	}

	base := measure([]string{"gzip"}, "gzip")
	deltas := make([]float64, 4)
	for n := 2; n <= 4; n++ {
		names := append(append([]string(nil), preceding[:n-1]...), "gzip")
		got := measure(names, "gzip")
		deltas[n-1] = got - base
		t.Logf("%d codings (matching one last): allocs/req=%.1f, delta vs 1 coding=%.1f (want %.1f)",
			n, got, got-base, float64(n-1))
	}

	// Instrument control: the general path (`;`) must be a genuinely different
	// path, otherwise "fast path" is not what is being measured at all.
	general := measure([]string{"zstd", "gzip"}, "gzip;q=1.0")
	fast := measure([]string{"zstd", "gzip"}, "gzip")
	if general <= fast {
		t.Fatalf("harness broken: a header with `;` did not take a measurably different path "+
			"(fast=%.1f general=%.1f); the `;`-routing assumption this probe rests on is false",
			fast, general)
	}
	t.Logf("route control: fast path=%.1f allocs/req, general path (gzip;q=1.0)=%.1f", fast, general)

	for n := 2; n <= 4; n++ {
		if deltas[n-1] != float64(n-1) {
			t.Errorf("REPORT MECHANISM REFUTED: with %d configured codings the delta over one coding is "+
				"%.1f, not %d; Z15-4's per-coding `strings.Split` attribution does not hold",
				n, deltas[n-1], n-1)
		}
	}
}

// --- FALSIFICATION 2: does the janitor benchmark's guard really never run? ----

// TestZ15VJanitorGuardUnreachableBelow1024 independently reproduces Z15-2's
// number without the reviewed probe's output parser: it runs the benchmark at
// 200x and greps the raw line, requiring the run to exit 0 (i.e. no b.Fatal
// fired) while reporting peak_records 0. If the benchmark fails or reports a
// non-zero peak, Z15-2 is refuted.
func TestZ15VJanitorGuardUnreachableBelow1024(t *testing.T) {
	root := vRepoRoot(t)

	run := func(benchtime string) string {
		cmd := exec.Command("go", "test", "-count=1", "-run", "^$",
			"-bench", "BenchmarkTokenLifecycleWithJanitor", "-benchtime="+benchtime,
			"./internal/store/memory/")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("harness broken: the %s run exited non-zero (a b.Fatal may have fired):\n%s",
				benchtime, string(out))
		}
		return string(out)
	}

	line := func(out string) string {
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "peak_records") {
				return l
			}
		}
		t.Fatalf("harness broken: no peak_records line in the benchmark output:\n%s", out)
		return ""
	}

	big := line(run("2000x"))
	small := line(run("200x"))
	t.Logf("2000x line: %s", strings.TrimSpace(big))
	t.Logf("200x  line: %s", strings.TrimSpace(small))

	peak := func(l string) string {
		f := strings.Fields(l)
		for i, x := range f {
			if x == "peak_records" && i > 0 {
				return f[i-1]
			}
		}
		return "?"
	}
	if peak(big) == "0" {
		t.Fatalf("harness broken: the positive control (2000x) reported peak 0")
	}
	if peak(small) != "0" {
		t.Errorf("Z15-2 REFUTED: at -benchtime=200x the benchmark reports peak_records=%s and exits 0; "+
			"the reviewed finding claims it reports 0", peak(small))
	}
}

// --- NEW FINDING: the session sweep on the same 15-minute loop is unbounded ----

// TestZ15VSessionsSweepIsAlsoUnbounded
//
// Z15-1 analyses postgres/sweep.go only. The composition root's sweep closure
// (cmd/re0auth/main.go:942-951, run by the same sweepLoop at main.go:405 every
// 15 minutes) also calls Sessions.SweepExpired, and that one issues two further
// DELETE statements with no LIMIT: `DELETE FROM sessions WHERE expiry < $1`
// (internal/store/postgres/sessions.go:144) and an unbounded, correlated
// anti-join that removes orphan session_subjects rows (:148-151). The report
// mentions only the cost of that anti-join, under "未能到达", and never reports
// the second unbounded maintenance delete on the production backend.
//
// Positive control: the LIMIT detector is proven to distinguish a bounded
// statement from an unbounded one before any conclusion is drawn, and the loop
// wiring is asserted so the probe fails rather than passing vacuously if the
// composition root stops calling it.
func TestZ15VSessionsSweepIsAlsoUnbounded(t *testing.T) {
	root := vRepoRoot(t)
	sessSrc := vRead(t, filepath.Join(root, "internal", "store", "postgres", "sessions.go"))
	mainSrc := vRead(t, filepath.Join(root, "cmd", "re0auth", "main.go"))

	limitRe := regexp.MustCompile(`(?i)\bLIMIT\b`)
	if !limitRe.MatchString("DELETE FROM t WHERE c < $1 LIMIT 100") {
		t.Fatal("harness broken: the LIMIT detector does not see a LIMIT")
	}
	if limitRe.MatchString("DELETE FROM t WHERE c < $1") {
		t.Fatal("harness broken: the LIMIT detector sees a LIMIT where there is none")
	}

	// Extract the SweepExpired body so an unrelated LIMIT elsewhere in the file
	// cannot make this pass.
	start := strings.Index(sessSrc, "func (s *Sessions) SweepExpired")
	if start < 0 {
		t.Fatal("harness broken: Sessions.SweepExpired not found; the probe reads the wrong construct")
	}
	rest := sessSrc[start:]
	if end := strings.Index(rest[len("func"):], "\nfunc "); end >= 0 {
		rest = rest[:len("func")+end]
	}
	delCount := strings.Count(rest, "DELETE FROM")
	if delCount < 2 {
		t.Fatalf("harness broken: parsed %d DELETE statements from Sessions.SweepExpired, want 2", delCount)
	}
	if !strings.Contains(rest, "DELETE FROM sessions WHERE expiry < $1") {
		t.Fatal("harness broken: the dated-sessions DELETE was not found in the sweep body")
	}

	// Wire-up: the same closure that sweepLoop runs must call the session sweep.
	wireIdx := strings.Index(mainSrc, "sweep: func(ctx context.Context) (int64, error) {")
	if wireIdx < 0 {
		t.Fatal("harness broken: the postgres sweep closure was not found in main.go")
	}
	wireBody := mainSrc[wireIdx:]
	if end := strings.Index(wireBody[10:], "\n\t\t},"); end >= 0 {
		wireBody = wireBody[:10+end]
	}

	t.Logf("Sessions.SweepExpired: %d DELETE statements, LIMIT present=%v", delCount, limitRe.MatchString(rest))
	t.Logf("same sweepLoop closure calls db.SweepExpired=%v sessions.SweepExpired=%v",
		strings.Contains(wireBody, "db.SweepExpired(ctx)"), strings.Contains(wireBody, "sessions.SweepExpired(ctx)"))

	if !strings.Contains(wireBody, "sessions.SweepExpired(ctx)") {
		t.Fatalf("harness broken: the loop that runs every 15 minutes no longer enters the session sweep")
	}
	if !limitRe.MatchString(rest) {
		t.Errorf("NEW: the session sweep on the same 15-minute ticker is unbounded too: %d DELETE "+
			"statements in Sessions.SweepExpired carry no LIMIT (sessions.go:144 and the correlated "+
			"anti-join at :148-151), so Z15-1's mechanism applies to a second production maintenance "+
			"path the report does not report", delCount)
	}
}

// --- FALSIFICATION 3: is the memory sweep really a "bounded progress" control? --

// TestZ15VMemorySweepRemovesWholePopulationInOneCall
//
// Z15-1 offers internal/store/memory/oidc.go:945-980 as its positive control:
// "the memory backend advances in a bounded way, Postgres does not". That is the
// wrong control. One call to OIDCStore.SweepExpired walks every record map and
// removes the ENTIRE expired population before returning, under the store-wide
// mutex — the per-cycle work grows with the backlog exactly like the Postgres
// statement, it is just not one SQL statement. This probe ages N records with an
// injected clock and shows that a single call removes all N.
//
// Control: the same N records must be present before the call, otherwise
// "removed N" would prove nothing.
func TestZ15VMemorySweepRemovesWholePopulationInOneCall(t *testing.T) {
	ctx := context.Background()
	for _, n := range []int{1_000, 100_000} {
		clock := &vClock{t: time.Unix(1_700_000_000, 0).UTC()}
		clients := oauth.NewMemoryClientRegistry()
		st, err := memory.NewOIDCStore(memory.OIDCOptions{
			Clients:    clients,
			Registry:   oauth.DefaultRegistry(),
			Signer:     vSigner(t),
			Now:        clock.now,
			RequestTTL: time.Minute,
		})
		if err != nil {
			t.Fatalf("NewOIDCStore: %v", err)
		}
		for i := 0; i < n; i++ {
			if err := st.SaveAuthCode(ctx, fmt.Sprintf("req-%07d", i), fmt.Sprintf("code-%07d", i)); err != nil {
				t.Fatalf("SaveAuthCode: %v", err)
			}
		}
		if got := st.Counts().Codes; got != n {
			t.Fatalf("harness broken: %d codes stored, want %d", got, n)
		}
		clock.advance(2 * time.Minute) // every record is now past its deadline
		removed := st.SweepExpired()   // one call, one pass
		t.Logf("one SweepExpired call over %7d expired codes removed %7d (remaining %d)",
			n, removed, st.Counts().Codes)
		if removed != n || st.Counts().Codes != 0 {
			t.Fatalf("harness broken: removed=%d remaining=%d, want all %d (the population must be "+
				"entirely expired and then entirely gone)", removed, st.Counts().Codes, n)
		}
	}
}

// --- NEW FINDING: the corpus/CI context of Z15-2 ------------------------------

// TestZ15VCIRunsBenchmarksAt200x
//
// Z15-2 says "any fixed-count run (-benchtime=Nx, which this repo's probes and
// perfreport use) prints peak_records 0". The repository source places that
// fixed-count run in CI itself: .github/workflows/ci.yml:394-405 runs
// `go test -run '^$' -bench . -benchmem -benchtime=200x ./...` and its only gate
// counts lines containing `ns/op`. So the CI capacity job produces peak_records 0
// for this benchmark and the gate cannot notice — stronger than the report's
// wording (cmd/perfreport never passes -benchtime). This probe is RED if the CI
// step stops using 200x (the premise changes); it logs the wiring otherwise.
func TestZ15VCIRunsBenchmarksAt200x(t *testing.T) {
	root := vRepoRoot(t)
	ci := vRead(t, filepath.Join(root, ".github", "workflows", "ci.yml"))
	if !strings.Contains(ci, "ns/op") {
		t.Fatal("harness broken: the benchmark step's `ns/op` gate is not in ci.yml; the probe reads the wrong file")
	}
	if !strings.Contains(ci, "-benchtime=200x") {
		t.Fatalf("premise changed: ci.yml no longer runs the benchmarks at -benchtime=200x")
	}
	if regexp.MustCompile(`(?i)peak_records`).MatchString(ci) {
		t.Errorf("Z15-2 REFUTED: the CI benchmark step appears to check peak_records")
	}
	t.Logf("ci.yml runs `-bench . -benchtime=200x ./...` and gates only on the count of `ns/op` lines; " +
		"peak_records is never inspected, so the vacuous 0 is a green CI number")
}
