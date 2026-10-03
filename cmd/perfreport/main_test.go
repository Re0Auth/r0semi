package main

import (
	"math"
	"strings"
	"testing"
)

// The bench output format is parsed by hand, so the parser is pinned here: a
// report that silently reads zero samples would print "—" everywhere and be
// believed, which is worse than no report.
func TestParseBenchAggregatesAcrossCounts(t *testing.T) {
	raw := strings.Join([]string{
		"goos: linux",
		"goarch: amd64",
		"pkg: github.com/Re0Auth/r0semi/internal/httpapi",
		"cpu: AMD EPYC 7R32 48-Core Processor",
		"BenchmarkBusinessPlaneBearerMe-4         54836     19727 ns/op   14913 B/op   180 allocs/op",
		"BenchmarkBusinessPlaneBearerMe-4         54836     20727 ns/op   14913 B/op   180 allocs/op",
		"BenchmarkBusinessPlaneBearerMe-4         54836     18727 ns/op   14913 B/op   180 allocs/op",
		"ok  \tgithub.com/Re0Auth/r0semi/internal/httpapi\t4.764s",
		"goos: linux",
		"goarch: amd64",
		"pkg: github.com/Re0Auth/r0semi/internal/store/memory",
		"cpu: AMD EPYC 7R32 48-Core Processor",
		"BenchmarkIntrospect/serial-4   6953683   160.5 ns/op   192 B/op   4 allocs/op",
		"BenchmarkTokenLifecycleWithJanitor-4   763576   2314 ns/op   2048 peak_records   1565 B/op   25 allocs/op",
		"BenchmarkCheckAtCapacity/maxkeys=1000-4   1225132   970.4 ns/op   129 B/op   3 allocs/op",
	}, "\n")

	env, benches, err := parseBench(raw)
	if err != nil {
		t.Fatal(err)
	}
	if env.goos != "linux" || env.goarch != "amd64" || env.cpu != "AMD EPYC 7R32 48-Core Processor" {
		t.Fatalf("env = %+v", env)
	}
	if len(benches) != 4 {
		t.Fatalf("parsed %d benchmarks, want 4: %v", len(benches), benches)
	}

	byName := make(map[string]*bench, len(benches))
	for _, b := range benches {
		byName[b.name] = b
	}

	// Three -count samples of one benchmark become one row whose median is the
	// middle sample; the package tag comes from the pkg: line above each block.
	me, ok := byName["BusinessPlaneBearerMe"]
	if !ok {
		t.Fatalf("BusinessPlaneBearerMe missing from %v", byName)
	}
	if me.pkg != "github.com/Re0Auth/r0semi/internal/httpapi" {
		t.Fatalf("pkg = %q", me.pkg)
	}
	if me.gomaxprocs != 4 {
		t.Fatalf("gomaxprocs = %d, want 4", me.gomaxprocs)
	}
	if len(me.samples) != 3 {
		t.Fatalf("samples = %d, want 3", len(me.samples))
	}
	if got := me.median(); got != 19727 {
		t.Fatalf("median = %v, want 19727", got)
	}
	if bOp, _ := me.metric("B/op"); bOp != 14913 {
		t.Fatalf("B/op = %v", bOp)
	}

	// A fractional ns/op and a custom metric must survive the pair parser. A
	// sub-benchmark keeps its full path: the slash is part of the name.
	lc, ok := byName["Introspect/serial"]
	if !ok {
		t.Fatalf("sub-benchmark name missing from %v", byName)
	}
	if lc.median() != 160.5 {
		t.Fatalf("sub-benchmark median %v", lc.median())
	}
	if v, ok := byName["TokenLifecycleWithJanitor"].metric("peak_records"); !ok || v != 2048 {
		t.Fatalf("peak_records = %v, %v", v, ok)
	}
	// The slash in a sub-benchmark path is part of the name, not a separator.
	if _, ok := byName["CheckAtCapacity/maxkeys=1000"]; !ok {
		t.Fatalf("slash-bearing name missing from %v", byName)
	}
}

func TestParseBenchRejectsWhatItCannotTrust(t *testing.T) {
	for name, line := range map[string]string{
		// An odd trailing field means a metric value lost its name (or a name lost
		// its value): the pairs cannot be trusted, so neither can the table.
		"trailing orphan field": "BenchmarkFoo-4   1000   12.5 ns/op   64 B/op   2",
		"no ns/op token":        "BenchmarkFoo-4   1000   12.5 seconds/op",
		"non-numeric ns/op":     "BenchmarkFoo-4   1000   fast ns/op   64 B/op   2 allocs/op",
		"non-numeric count":     "BenchmarkFoo-4   many   12.5 ns/op   64 B/op   2 allocs/op",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseBench(line); err == nil {
				t.Fatalf("accepted %q", line)
			}
		})
	}
}

func TestParseLoad(t *testing.T) {
	raw := strings.Join([]string{
		"=== RUN   TestLoadProfile",
		"capacity profile: 8 workers, 10s, 213472 requests, 21347.2 req/s",
		"  GET  /v1/me            n=106736  p50=<1.005ms  p95=1.03ms    p99=1.17ms    max=10.88ms",
		"  POST /oauth/introspect n=106736  p50=<1.005ms  p95=1.06ms    p99=1.27ms    max=10.88ms",
		"  goroutines 3 -> 9, heap 5.3 MiB, clock 1.005ms, GOMAXPROCS 20",
		"--- PASS: TestLoadProfile (10.50s)",
	}, "\n")

	p, err := parseLoad(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.workers != 8 || p.seconds != 10 || p.requests != 213472 || p.reqPerSec != 21347.2 {
		t.Fatalf("profile = %+v", p)
	}
	if len(p.raw) != 4 || !strings.HasPrefix(p.raw[0], "capacity profile:") {
		t.Fatalf("raw block = %q", p.raw)
	}
	// The verdict line after the block must not leak into it.
	if strings.Contains(strings.Join(p.raw, "\n"), "PASS") {
		t.Fatalf("raw block swallowed non-profile lines: %q", p.raw)
	}
}

func TestParseLoadRejectsItsAbsence(t *testing.T) {
	if _, err := parseLoad("ok  \tgithub.com/Re0Auth/r0semi/internal/httpapi\t4.764s"); err == nil {
		t.Fatal("output without a capacity profile block was accepted")
	}
}

// Under `-v` the profile is printed twice: once plain, once through t.Log with a
// `load_test.go:N:` prefix and deeper indent. The fenced section must contain the
// profile once; the duplicate is log noise, and swallowing it would put a copy of
// the whole block inside the report's code fence.
func TestParseLoadIgnoresTheVerboseLogDuplicate(t *testing.T) {
	raw := strings.Join([]string{
		"capacity profile: 32 workers, 10s, 439558 requests, 43955.8 req/s",
		"  GET  /v1/me            n=219779  p50=<1.011ms  p99=2.98ms    max=10.96ms",
		"  POST /oauth/introspect n=219779  p50=<1.011ms  p99=3.35ms    max=13.37ms",
		"  goroutines 3 -> 9, heap 9.5 MiB, clock 1.011ms, GOMAXPROCS 20",
		"  clock: this machine cannot resolve a request, so the latencies above are quantized (0 means \"below one tick\").",
		"  Read the Linux CI job for the tail numbers; the throughput and the goroutine figures are unaffected.",
		"    load_test.go:193: ",
		"        capacity profile: 32 workers, 10s, 439558 requests, 43955.8 req/s",
		"          GET  /v1/me            n=219779  p50=<1.011ms  p99=2.98ms    max=10.96ms",
		"          POST /oauth/introspect n=219779  p50=<1.011ms  p99=3.35ms    max=13.37ms",
		"          goroutines 3 -> 9, heap 9.5 MiB, clock 1.011ms, GOMAXPROCS 20",
		"--- PASS: TestLoadProfile (10.50s)",
	}, "\n")

	p, err := parseLoad(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.raw) != 6 {
		t.Fatalf("block = %d lines, want the 6 of one profile:\n%q", len(p.raw), strings.Join(p.raw, "\n"))
	}
	if strings.Contains(strings.Join(p.raw, "\n"), "load_test.go") {
		t.Fatalf("block swallowed the t.Log duplicate:\n%q", strings.Join(p.raw, "\n"))
	}
}

func TestMedian(t *testing.T) {
	// The contract is "sorted input", the same one nsValues() satisfies before
	// calling; these literals are sorted on purpose.
	if got := median([]float64{1, 2, 3}); got != 2 {
		t.Fatalf("odd median = %v", got)
	}
	if got := median([]float64{1, 2, 3, 4}); got != 2.5 {
		t.Fatalf("even median = %v", got)
	}
}

func mkBench(pkg, name string, ns []float64) *bench {
	b := &bench{pkg: pkg, name: name}
	for _, v := range ns {
		b.samples = append(b.samples, sample{nsPerOp: v})
	}
	return b
}

// A renamed benchmark is one new plus one missing, never a fabricated ±100%.
func TestComparePairsByNameAndFlagsRenames(t *testing.T) {
	current := []*bench{
		mkBench("pkg/a", "Same", []float64{110}),   // +10%, inside the threshold
		mkBench("pkg/a", "Slower", []float64{200}), // +100%
		mkBench("pkg/a", "BrandNew", []float64{50}),
	}
	baseline := []*bench{
		mkBench("pkg/a", "Same", []float64{100}),
		mkBench("pkg/a", "Slower", []float64{100}),
		mkBench("pkg/a", "RenamedAway", []float64{100}),
	}

	c := compare(current, baseline, 15)
	if c.shared != 2 {
		t.Fatalf("shared = %d, want 2", c.shared)
	}
	if len(c.newNames) != 1 || !strings.Contains(c.newNames[0], "BrandNew") {
		t.Fatalf("new = %v", c.newNames)
	}
	if len(c.missingNames) != 1 || !strings.Contains(c.missingNames[0], "RenamedAway") {
		t.Fatalf("missing = %v", c.missingNames)
	}
	if len(c.regressions) != 1 || !strings.Contains(c.regressions[0], "Slower") {
		t.Fatalf("regressions = %v", c.regressions)
	}
	// Geomean of (+10%, +100%) is sqrt(1.1*2)-1 ≈ +48.3%, not the +55% an
	// arithmetic mean would wrongly suggest.
	if want := (math.Sqrt(1.1*2) - 1) * 100; math.Abs(c.geomeanDelta-want) > 1e-9 {
		t.Fatalf("geomean = %v, want %v", c.geomeanDelta, want)
	}
}

// TestCompareRefusesAZeroMedianInsteadOfFabricatingADelta: the parser accepts
// `ns/op=0` and an empty sample set reports 0, so a ratio is ±Inf and the geomean
// becomes NaN for every other benchmark. Such a pair must be reported as not
// comparable, and the healthy pairs must keep their real geomean.
func TestCompareRefusesAZeroMedianInsteadOfFabricatingADelta(t *testing.T) {
	current := []*bench{
		mkBench("pkg/a", "ZeroBaseline", []float64{100}),
		mkBench("pkg/a", "ZeroCurrent", []float64{0}),
		mkBench("pkg/a", "Healthy", []float64{110}),
	}
	baseline := []*bench{
		mkBench("pkg/a", "ZeroBaseline", []float64{0}),
		mkBench("pkg/a", "ZeroCurrent", []float64{100}),
		mkBench("pkg/a", "Healthy", []float64{100}),
	}
	c := compare(current, baseline, 15)
	if c.shared != 1 {
		t.Fatalf("shared = %d, want 1 (only the healthy pair is comparable)", c.shared)
	}
	if len(c.zeroBaseline) != 2 {
		t.Fatalf("zeroBaseline = %v, want the two unusable pairs", c.zeroBaseline)
	}
	if math.IsNaN(c.geomeanDelta) || math.IsInf(c.geomeanDelta, 0) {
		t.Fatalf("geomean = %v: a zero median poisoned it", c.geomeanDelta)
	}
	if want := 10.0; math.Abs(c.geomeanDelta-want) > 1e-9 {
		t.Fatalf("geomean = %v, want %v", c.geomeanDelta, want)
	}
}

func TestRenderIncludesWhatTheReaderCameFor(t *testing.T) {
	benches := []*bench{
		mkBench("github.com/Re0Auth/r0semi/internal/httpapi", "BusinessPlaneBearerMe", []float64{19727}),
		mkBench("github.com/Re0Auth/r0semi/internal/store/postgres", "AuditAppend", []float64{2.31e6}),
	}
	benches[0].samples[0] = sample{nsPerOp: 19727, metrics: map[string]float64{"B/op": 14913, "allocs/op": 180}}
	benches[1].samples[0] = sample{nsPerOp: 2.31e6, metrics: map[string]float64{"B/op": 279, "allocs/op": 12, "MB/s": 4889.88}}

	load, err := parseLoad("capacity profile: 8 workers, 10s, 213472 requests, 21347.2 req/s\n  GET /v1/me n=106736 p50=<1.005ms\n  goroutines 3 -> 9, heap 5.3 MiB, clock 1.005ms, GOMAXPROCS 20")
	if err != nil {
		t.Fatal(err)
	}

	report := render(benchEnv{goos: "linux", goarch: "amd64", cpu: "EPYC"}, benches, load, nil, options{commit: "abc1234", threshold: 15})

	for _, want := range []string{
		"# Performance report",
		"Commit: `abc1234`",
		"linux/amd64",
		"### internal/httpapi",
		"BusinessPlaneBearerMe",
		"19.73µs", // the adaptive unit, not a bare 19727
		"2.31ms",
		"| 14913 | 180 |", // B/op and allocs/op columns
		"## Capacity profile",
		"21.3k req/s",
		"capacity profile: 8 workers, 10s, 213472 requests, 21347.2 req/s",
		"## Reading notes",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q:\n%s", want, report)
		}
	}

	// Without a baseline the delta column is a dash, not a fabricated number.
	if !strings.Contains(report, "BusinessPlaneBearerMe | 19.73µs | — | 14913 | 180 | — | — |") {
		t.Errorf("delta column wrong without a baseline:\n%s", report)
	}
	// A custom metric (SetBytes' MB/s here) lands in the extra column of its own
	// row, not merged into a neighbouring cell.
	if !strings.Contains(report, "| 12 | MB/s=4889.88 | — |") {
		t.Errorf("custom metric not in its own extra column:\n%s", report)
	}
}

func TestRenderComparisonMarksTheTable(t *testing.T) {
	current := []*bench{mkBench("pkg/a", "Same", []float64{110})}
	baseline := []*bench{mkBench("pkg/a", "Same", []float64{100})}
	c := compare(current, baseline, 15)
	report := render(benchEnv{}, current, nil, &c, options{threshold: 15})

	if !strings.Contains(report, "vs baseline: geomean +10.0% across 1 shared benchmarks") {
		t.Errorf("headline missing:\n%s", report)
	}
	if !strings.Contains(report, "| Same | 110ns | — | — | — | — | +10.0% |") {
		t.Errorf("delta cell missing from the table:\n%s", report)
	}
}
