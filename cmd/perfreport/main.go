// Command perfreport renders a Markdown performance report from `go test -bench`
// output, optionally from the capacity profile `TestLoadProfile` prints, and
// optionally compares both against a baseline run of the same shape.
//
// It exists so the perf workflow and a laptop produce the same report from the
// same code, and so the comparison logic has tests: a percentage that only lives
// inside a workflow step cannot be pinned, and two implementations would drift —
// the same reasoning that produced cmd/covertable.
//
// The numbers it reports are descriptions, not gates. Shared runners are noisy
// and the load profile runs on in-memory stores, so the report carries a noise
// threshold (-threshold) and a reading-notes section instead of a pass/fail line;
// the workflow that calls this tool fails only when no numbers were produced at
// all, which is the anti-vacuous check.
//
// Usage:
//
//	go run ./cmd/perfreport [-load load.txt] [-baseline-bench base.txt]
//	                        [-baseline-load base-load.txt] [-commit sha]
//	                        [-out report.md] bench.txt
package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
)

// benchEnv is the platform a bench run printed in its preamble lines
// (goos:, goarch:, cpu:). Any field the output did not carry stays empty and the
// report simply omits it.
type benchEnv struct {
	goos   string
	goarch string
	cpu    string
}

// sample is one parsed benchmark result line: one -count iteration of one
// benchmark. Metrics beyond ns/op (B/op, allocs/op, a benchmark's custom metric
// such as peak_records) are stored as named pairs in the order the line carried
// them.
type sample struct {
	nsPerOp float64
	metrics map[string]float64
}

// bench aggregates every sample of one benchmark within one package across the
// -count runs, so a report can print a median and a spread instead of one
// one-second reading.
type bench struct {
	pkg        string
	name       string
	gomaxprocs int
	samples    []sample
}

// median returns the median ns/op across the -count samples. With one sample it
// is that sample; the spread column is where the difference shows.
func (b *bench) median() float64 {
	return median(b.nsValues())
}

// spread returns the smallest and largest ns/op across samples.
func (b *bench) spread() (min, max float64) {
	vals := b.nsValues()
	return vals[0], vals[len(vals)-1]
}

func (b *bench) nsValues() []float64 {
	vals := make([]float64, 0, len(b.samples))
	for _, s := range b.samples {
		vals = append(vals, s.nsPerOp)
	}
	slices.Sort(vals)
	return vals
}

// metric returns the median of one named metric (B/op, allocs/op, peak_records,
// MB/s), or false when no sample carried it. A metric a benchmark prints only
// sometimes (none here, but the format allows it) is a median of what exists.
func (b *bench) metric(name string) (float64, bool) {
	var vals []float64
	for _, s := range b.samples {
		if v, ok := s.metrics[name]; ok {
			vals = append(vals, v)
		}
	}
	if len(vals) == 0 {
		return 0, false
	}
	return median(vals), true
}

func (b *bench) extraMetrics() []string {
	seen := make(map[string]bool)
	var names []string
	for _, s := range b.samples {
		for name := range s.metrics {
			// B/op and allocs/op get columns of their own; anything else is a
			// custom metric a benchmark defined for itself.
			if name == "B/op" || name == "allocs/op" || seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func (b *bench) key() string { return b.pkg + "\x00" + b.name }

func median(sorted []float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// parseBench parses the output of `go test -bench` over one or more packages.
// Each package block carries its own goos/goarch/pkg/cpu preamble; the returned
// env is the last one seen (runs of the form `-bench ./...` use one platform, so
// the preamble lines agree), and every benchmark is tagged with the package whose
// block it appeared in.
//
// A line that starts a benchmark result but does not parse as one is an error,
// not something to skip: a silently dropped line is a silently missing number,
// which is exactly what this report must not be.
func parseBench(text string) (benchEnv, []*bench, error) {
	var env benchEnv
	byKey := make(map[string]*bench)
	var order []*bench
	current := "unknown-package"

	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "goos:"):
			env.goos = strings.TrimSpace(strings.TrimPrefix(line, "goos:"))
		case strings.HasPrefix(line, "goarch:"):
			env.goarch = strings.TrimSpace(strings.TrimPrefix(line, "goarch:"))
		case strings.HasPrefix(line, "cpu:"):
			env.cpu = strings.TrimSpace(strings.TrimPrefix(line, "cpu:"))
		case strings.HasPrefix(line, "pkg:"):
			current = strings.TrimSpace(strings.TrimPrefix(line, "pkg:"))
		case strings.HasPrefix(line, "Benchmark"):
			b, err := parseBenchLine(line, current)
			if err != nil {
				return env, nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
			existing, ok := byKey[b.key()]
			if !ok {
				existing = b
				byKey[b.key()] = existing
				order = append(order, existing)
				continue
			}
			existing.samples = append(existing.samples, b.samples...)
			if b.gomaxprocs > existing.gomaxprocs {
				existing.gomaxprocs = b.gomaxprocs
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return env, nil, err
	}
	return env, order, nil
}

// parseBenchLine parses one result line. The shape is
//
//	Benchmark<name>[-GOMAXPROCS]  <n>  <ns> ns/op  <value> <metric> ...
//
// where <name> may contain slashes (sub-benchmarks) and the metric pairs repeat:
// B/op and allocs/op always follow ns/op, and a benchmark with SetBytes or a
// custom metric (peak_records) carries more. `go test -bench` emits fixed-width
// columns, so fields, not positions.
func parseBenchLine(line, pkg string) (*bench, error) {
	fields := strings.Fields(line)
	// name[-procs], n, ns, "ns/op" at minimum, plus at least one metric pair
	// (B/op and allocs/op): 4 + 2.
	if len(fields) < 6 {
		return nil, fmt.Errorf("benchmark line has %d fields, want at least 6: %q", len(fields), line)
	}
	name := fields[0]
	procs := 1
	if base, suffix, ok := strings.Cut(name, "-"); ok {
		if p, err := strconv.Atoi(suffix); err == nil && p > 0 {
			name = base
			procs = p
		}
	}
	name = strings.TrimPrefix(name, "Benchmark")
	if _, err := strconv.Atoi(fields[1]); err != nil {
		return nil, fmt.Errorf("iteration count %q is not a number: %q", fields[1], line)
	}
	if fields[3] != "ns/op" {
		return nil, fmt.Errorf("expected ns/op in position 4, got %q: %q", fields[3], line)
	}
	ns, err := strconv.ParseFloat(fields[2], 64)
	if err != nil {
		return nil, fmt.Errorf("ns/op %q is not a number: %q", fields[2], line)
	}

	metrics := make(map[string]float64)
	rest := fields[4:]
	if len(rest)%2 != 0 {
		return nil, fmt.Errorf("metric pairs are unbalanced (%d fields): %q", len(rest), line)
	}
	for i := 0; i < len(rest); i += 2 {
		v, err := strconv.ParseFloat(rest[i], 64)
		if err != nil {
			return nil, fmt.Errorf("metric %s value %q is not a number: %q", rest[i+1], rest[i], line)
		}
		metrics[rest[i+1]] = v
	}

	b := &bench{
		pkg:        pkg,
		name:       name,
		gomaxprocs: procs,
		samples:    []sample{{nsPerOp: ns, metrics: metrics}},
	}
	return b, nil
}

// loadProfile is the capacity profile TestLoadProfile prints (make load):
// one headline line with the totals, then per-endpoint latency rows and a
// resource line, kept here verbatim for the report.
type loadProfile struct {
	workers   int
	seconds   int
	requests  int
	reqPerSec float64
	raw       []string
}

// parseLoad extracts the last capacity profile block in the output. A run prints
// one; a `-count=N` run would print N, and the last is the one to compare.
//
// Membership in the block is decided by content, not indentation, because the
// profile is printed twice under `-v` (once plain, once through t.Log with a
// `load_test.go:N:` prefix and deeper indent): an indentation rule would swallow
// the duplicate into the fenced section. A block closes at the first line that
// is none of the profile's line shapes, and only a new headline reopens one.
func parseLoad(text string) (*loadProfile, error) {
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var last *loadProfile
	inBlock := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "capacity profile:"):
			p, err := parseLoadHeadline(line)
			if err != nil {
				return nil, err
			}
			p.raw = append(p.raw, line)
			last = p
			inBlock = true
		case inBlock && isLoadBlockLine(trimmed):
			last.raw = append(last.raw, line)
		default:
			inBlock = false
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if last == nil {
		return nil, fmt.Errorf("no capacity profile block found (run the load profile with RE0AUTH_LOAD_PROFILE=1)")
	}
	return last, nil
}

// isLoadBlockLine reports whether a trimmed line is one of the shapes the
// profile block carries after its headline: an endpoint latency row, the
// resource line, or the clock caveat's two lines (load_test.go appends the
// caveat when the runner's timer is too coarse for the latencies).
func isLoadBlockLine(trimmed string) bool {
	switch {
	case strings.HasPrefix(trimmed, "goroutines"):
		return true
	case strings.HasPrefix(trimmed, "clock:"), strings.HasPrefix(trimmed, "Read the Linux CI job"):
		return true
	case (strings.HasPrefix(trimmed, "GET ") || strings.HasPrefix(trimmed, "POST ")) && strings.Contains(trimmed, "n="):
		return true
	default:
		return false
	}
}

// parseLoadHeadline reads
//
//	capacity profile: 8 workers, 10s, 213472 requests, 21347.2 req/s
//
// whose layout is fixed by load_test.go's one fmt.Printf.
func parseLoadHeadline(line string) (*loadProfile, error) {
	var p loadProfile
	n, err := fmt.Sscanf(line, "capacity profile: %d workers, %ds, %d requests, %f req/s",
		&p.workers, &p.seconds, &p.requests, &p.reqPerSec)
	if err != nil || n != 4 {
		return nil, fmt.Errorf("malformed capacity profile headline: %q", line)
	}
	return &p, nil
}

// comparison is the result of matching a current run against a baseline run by
// package-and-benchmark name.
type comparison struct {
	shared       int
	geomeanDelta float64 // percent; the geometric mean of per-benchmark deltas
	deltas       map[string]float64
	regressions  []string
	improvements []string
	newNames     []string
	missingNames []string
}

// compare pairs every current benchmark with its baseline counterpart. A name
// present on one side only is reported, not compared: a renamed benchmark shows
// up as one new and one missing rather than as a fabricated ±100%.
func compare(current, baseline []*bench, thresholdPct float64) comparison {
	byKey := make(map[string]*bench, len(baseline))
	for _, b := range baseline {
		byKey[b.key()] = b
	}
	currentKeys := make(map[string]bool, len(current))

	var c comparison
	c.deltas = make(map[string]float64)
	logSum := 0.0
	for _, cur := range current {
		currentKeys[cur.key()] = true
		base, ok := byKey[cur.key()]
		if !ok {
			c.newNames = append(c.newNames, label(cur))
			continue
		}
		delta := (cur.median() - base.median()) / base.median() * 100
		c.shared++
		c.deltas[cur.key()] = delta
		logSum += math.Log1p(delta / 100)
		entry := fmt.Sprintf("%s %s", label(cur), formatDelta(delta))
		switch {
		case delta > thresholdPct:
			c.regressions = append(c.regressions, entry)
		case delta < -thresholdPct:
			c.improvements = append(c.improvements, entry)
		}
	}
	for _, b := range baseline {
		if !currentKeys[b.key()] {
			c.missingNames = append(c.missingNames, label(b))
		}
	}
	if c.shared > 0 {
		c.geomeanDelta = (math.Exp(logSum/float64(c.shared)) - 1) * 100
	}
	return c
}

func label(b *bench) string {
	short := strings.TrimPrefix(b.pkg, "github.com/Re0Auth/r0semi/")
	if short == "unknown-package" || b.pkg == "" {
		return b.name
	}
	return short + "." + b.name
}

func formatDelta(delta float64) string {
	if math.Abs(delta) < 0.05 {
		return "±0.0%"
	}
	return fmt.Sprintf("%+.1f%%", delta)
}

// options carries everything render needs beyond the parsed inputs.
type options struct {
	commit     string
	threshold  float64
	baselineNS float64 // baseline load throughput, req/s; 0 = none
}

func render(env benchEnv, benches []*bench, load *loadProfile, comp *comparison, opts options) string {
	var sb strings.Builder
	fmt.Fprintln(&sb, "# Performance report")
	fmt.Fprintln(&sb)
	if opts.commit != "" {
		fmt.Fprintf(&sb, "Commit: `%s`\n", opts.commit)
	}
	var bits []string
	if env.goos != "" && env.goarch != "" {
		bits = append(bits, env.goos+"/"+env.goarch)
	}
	for _, b := range benches {
		if b.gomaxprocs > 0 {
			bits = append(bits, fmt.Sprintf("GOMAXPROCS=%d", b.gomaxprocs))
			break
		}
	}
	if env.cpu != "" {
		bits = append(bits, env.cpu)
	}
	if len(bits) > 0 {
		fmt.Fprintf(&sb, "Platform: %s\n", strings.Join(bits, ", "))
	}
	fmt.Fprintln(&sb)

	// The headline is the one-sentence version: what the whole table says at a
	// glance, so a reader who stops here still learned the answer.
	if comp != nil {
		fmt.Fprintf(&sb, "**vs baseline: geomean %s across %d shared benchmarks** (noise threshold ±%.0f%%).\n",
			formatDelta(comp.geomeanDelta), comp.shared, opts.threshold)
		if load != nil && opts.baselineNS > 0 {
			fmt.Fprintf(&sb, "Capacity profile: %s req/s vs baseline %s req/s (%s).\n",
				formatRate(load.reqPerSec), formatRate(opts.baselineNS),
				formatDelta(pctChange(load.reqPerSec, opts.baselineNS)))
		}
		fmt.Fprintln(&sb)
	}

	fmt.Fprintln(&sb, "## Micro benchmarks")
	fmt.Fprintln(&sb)
	fmt.Fprintln(&sb, "Each row is the median across the run's samples; the spread column is min–max, and a dash means a single-sample run.")
	fmt.Fprintln(&sb)
	current := ""
	for _, b := range benches {
		if b.pkg != current {
			if current != "" {
				fmt.Fprintln(&sb)
			}
			current = b.pkg
			fmt.Fprintf(&sb, "### %s\n\n", strings.TrimPrefix(current, "github.com/Re0Auth/r0semi/"))
			fmt.Fprintln(&sb, "| benchmark | ns/op | spread | B/op | allocs/op | extra | vs baseline |")
			fmt.Fprintln(&sb, "|---|---:|---|---:|---:|---|---:|")
		}
		// A benchmark with SetBytes or a custom metric (peak_records) carries
		// columns of its own; they render in extra rather than widening every
		// other table with a column one row would fill.
		extra := "—"
		var parts []string
		for _, name := range b.extraMetrics() {
			if v, ok := b.metric(name); ok {
				parts = append(parts, fmt.Sprintf("%s=%s", name, trimFloat(v)))
			}
		}
		if len(parts) > 0 {
			extra = strings.Join(parts, " ")
		}
		fmt.Fprintf(&sb, "| %s | %s | %s | %s | %s | %s | %s |\n",
			b.name, formatNS(b.median()), formatSpread(b), formatMetric(b, "B/op"), formatMetric(b, "allocs/op"), extra, deltaCell(b, comp))
	}
	fmt.Fprintln(&sb)

	if load != nil {
		fmt.Fprintln(&sb, "## Capacity profile")
		fmt.Fprintln(&sb)
		fmt.Fprintf(&sb, "Throughput **%s req/s** (%d workers × %ds, in-memory stores — a ceiling, not a promise).\n\n",
			formatRate(load.reqPerSec), load.workers, load.seconds)
		fmt.Fprintln(&sb, "```")
		for _, line := range load.raw {
			fmt.Fprintln(&sb, line)
		}
		fmt.Fprintln(&sb, "```")
		fmt.Fprintln(&sb)
	}

	if comp != nil {
		fmt.Fprintln(&sb, "## Baseline comparison details")
		fmt.Fprintln(&sb)
		writeList := func(header string, entries []string) {
			if len(entries) == 0 {
				return
			}
			fmt.Fprintf(&sb, "%s:\n", header)
			for _, e := range entries {
				fmt.Fprintf(&sb, "- %s\n", e)
			}
			fmt.Fprintln(&sb)
		}
		writeList("Beyond the noise threshold, slower", comp.regressions)
		writeList("Beyond the noise threshold, faster", comp.improvements)
		writeList("New since the baseline (no comparison)", comp.newNames)
		writeList("In the baseline but absent now", comp.missingNames)
	}

	fmt.Fprintln(&sb, "## Reading notes")
	fmt.Fprintln(&sb)
	fmt.Fprintln(&sb, "- Micro benchmarks and the capacity profile run on the in-memory stores: they bound the per-core cost of the code, and a Postgres deployment adds per-request round trips on top.")
	fmt.Fprintln(&sb, "- The audit-chain benchmarks (`internal/store/postgres`) run against a real Postgres service; they measure the one serialised step on the durable path (invariant I3).")
	fmt.Fprintln(&sb, "- Shared runners are noisy: differences inside the noise threshold are weather, not signal. Compare runs of the same runner size only.")
	fmt.Fprintln(&sb, "- The load profile's clock line shows this runner's timer resolution; `p50` values below it are unmeasured, not fast.")
	return sb.String()
}

func deltaCell(b *bench, comp *comparison) string {
	if comp == nil {
		return "—"
	}
	delta, ok := comp.deltas[b.key()]
	if !ok {
		return "new"
	}
	return formatDelta(delta)
}

// pctChange is (cur-base)/base as a percentage, the one arithmetic a throughput
// comparison needs.
func pctChange(cur, base float64) float64 {
	if base == 0 {
		return 0
	}
	return (cur - base) / base * 100
}

// formatNS renders ns/op in the unit its magnitude suggests, so a table mixes
// 160ns and 30µs without a reader counting zeros.
func formatNS(ns float64) string {
	switch {
	case ns >= 1e6:
		return fmt.Sprintf("%.2fms", ns/1e6)
	case ns >= 1e3:
		return fmt.Sprintf("%.2fµs", ns/1e3)
	default:
		return fmt.Sprintf("%.0fns", ns)
	}
}

func formatSpread(b *bench) string {
	if len(b.samples) < 2 {
		return "—"
	}
	min, max := b.spread()
	return formatNS(min) + "–" + formatNS(max)
}

func formatMetric(b *bench, name string) string {
	v, ok := b.metric(name)
	if !ok {
		return "—"
	}
	return trimFloat(v)
}

func trimFloat(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func formatRate(rps float64) string {
	if rps >= 1000 {
		return fmt.Sprintf("%.1fk", rps/1000)
	}
	return trimFloat(rps)
}

func main() {
	loadPath := flag.String("load", "", "output of the capacity profile (RE0AUTH_LOAD_PROFILE=1 go test -v -run TestLoadProfile)")
	baseBench := flag.String("baseline-bench", "", "bench output of a previous run to compare against")
	baseLoad := flag.String("baseline-load", "", "load output of a previous run, for a throughput comparison")
	commit := flag.String("commit", "", "commit the numbers describe (printed in the header)")
	threshold := flag.Float64("threshold", 15, "percentage beyond which a per-benchmark difference is called out rather than treated as noise")
	out := flag.String("out", "", "write the report here instead of stdout")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: perfreport [flags] <bench-output.txt>")
		os.Exit(2)
	}

	raw, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "perfreport: %v\n", err)
		os.Exit(1)
	}
	env, benches, err := parseBench(string(raw))
	if err != nil {
		fmt.Fprintf(os.Stderr, "perfreport: %v\n", err)
		os.Exit(1)
	}
	if len(benches) == 0 {
		fmt.Fprintf(os.Stderr, "perfreport: no benchmark results in %s\n", flag.Arg(0))
		os.Exit(1)
	}

	var load *loadProfile
	if *loadPath != "" {
		loadRaw, err := os.ReadFile(*loadPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "perfreport: %v\n", err)
			os.Exit(1)
		}
		load, err = parseLoad(string(loadRaw))
		if err != nil {
			fmt.Fprintf(os.Stderr, "perfreport: %v\n", err)
			os.Exit(1)
		}
	}

	var comp *comparison
	var baselineNS float64
	if *baseBench != "" {
		baseRaw, err := os.ReadFile(*baseBench)
		if err != nil {
			fmt.Fprintf(os.Stderr, "perfreport: %v\n", err)
			os.Exit(1)
		}
		_, baseBenches, err := parseBench(string(baseRaw))
		if err != nil {
			fmt.Fprintf(os.Stderr, "perfreport: baseline: %v\n", err)
			os.Exit(1)
		}
		c := compare(benches, baseBenches, *threshold)
		comp = &c
		if *baseLoad != "" {
			blRaw, err := os.ReadFile(*baseLoad)
			if err != nil {
				fmt.Fprintf(os.Stderr, "perfreport: %v\n", err)
				os.Exit(1)
			}
			if bl, err := parseLoad(string(blRaw)); err == nil {
				baselineNS = bl.reqPerSec
			}
		}
	}

	report := render(env, benches, load, comp, options{
		commit:     *commit,
		threshold:  *threshold,
		baselineNS: baselineNS,
	})

	if *out == "" {
		fmt.Print(report)
		return
	}
	// 0o600: the report names branch state and benchmark timings, but there is no
	// reason for it to be group- or world-readable on a shared host, and the
	// caller can always widen it. G306 is the reason this is not 0o644.
	// (Z16-2, docs/issues/P2-medium.md)
	if err := os.WriteFile(*out, []byte(report), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "perfreport: %v\n", err)
		os.Exit(1)
	}
}
