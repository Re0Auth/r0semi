//go:build audit7

package z16guardtestquality

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// This file proves the "computes a verdict and only prints it" anti-pattern on
// live code, without touching the tracked files: `go test -overlay` swaps in a
// mutated copy of the probe's source for one run.
//
// The recorded precedents are TestProbeRegistryAcceptsPathEscapingNames and
// TestProbeRetryIsNotInstalledOnTheDataPlane (see AUDIT-ISSUES.md:271 and
// scratchpad/audit7/findings/22-audit5-red-reconciliation.md:146). The probes
// named here are new instances of the same shape.

// overlayRun runs `go test` in pkg with one file replaced, and returns whether it
// passed plus the output.
func overlayRun(t *testing.T, root, overlay string, pkg string, tags []string, run string) (bool, string) {
	t.Helper()
	args := []string{"test", "-count=1", "-v"}
	if overlay != "" {
		args = append(args, "-overlay="+overlay)
	}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	args = append(args, "-run", run, pkg)
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	return err == nil, string(out)
}

// writeOverlay writes a Go overlay mapping orig -> replacement.
func writeOverlay(t *testing.T, dir, orig, replacement string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"Replace": map[string]string{orig: replacement},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestZ16PubAddrProbeAcceptsAWrongExpectation: TestPubAddrRanges builds a
// per-case verdict and a `status := "MISMATCH"`, then logs both. Flip one
// expectation with an overlay and the test still passes.
func TestZ16PubAddrProbeAcceptsAWrongExpectation(t *testing.T) {
	root := repoRoot(t)
	const pkg = "./internal/zzprobe/pubaddr/"
	orig := filepath.Join(root, "internal", "zzprobe", "pubaddr", "addr_test.go")
	src := readFile(t, orig)
	const good = `{"8.8.8.8", "public"},`
	if !strings.Contains(src, good) {
		t.Fatalf("addr_test.go no longer has %s; update this probe", good)
	}

	// Control 1: the unmutated test passes.
	if ok, out := overlayRun(t, root, "", pkg, []string{"audit5"}, "^TestPubAddrRanges$"); !ok {
		t.Fatalf("control 1: the unmutated probe fails:\n%s", out)
	}

	// Control 2: the overlay really reaches the compiler.
	tmp := t.TempDir()
	trip := filepath.Join(tmp, "trip_test.go")
	if err := os.WriteFile(trip, []byte(strings.Replace(src,
		"func TestPubAddrRanges(t *testing.T) {",
		"func TestPubAddrRanges(t *testing.T) {\n\tt.Fatal(\"overlay applied\")", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, _ := overlayRun(t, root, writeOverlay(t, tmp, orig, trip), pkg, []string{"audit5"}, "^TestPubAddrRanges$"); ok {
		t.Fatal("control 2: the overlay did not reach the test, so the mutation below proves nothing")
	}

	// The mutation: Google DNS is now expected to be non-public.
	mutated := filepath.Join(tmp, "mutated_test.go")
	if err := os.WriteFile(mutated, []byte(strings.Replace(src, good, `{"8.8.8.8", "nonpublic"},`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, out := overlayRun(t, root, writeOverlay(t, tmp, orig, mutated), pkg, []string{"audit5"}, "^TestPubAddrRanges$")
	if !ok {
		t.Fatalf("the probe unexpectedly failed on a wrong expectation; this finding is stale:\n%s", out)
	}
	if !regexp.MustCompile(`8\.8\.8\.8\s+public\s+want=nonpublic\s+MISMATCH`).MatchString(out) {
		t.Logf("output was:\n%s", out)
		t.Fatalf("the mutated case did not print a MISMATCH; update this probe")
	}
	t.Errorf("TestPubAddrRanges (internal/zzprobe/pubaddr/addr_test.go:12-54) computed a MISMATCH " +
		"and still passed: it is the `TestProbeRegistryAcceptsPathEscapingNames` shape again — a " +
		"verdict string built and logged, never asserted. A fake expectation for 169.254.169.254 " +
		"or any other of its 24 cases would be accepted in silence, and the package's whole purpose " +
		"is to pin which addresses the SSRF guard refuses.")
}

// TestZ16LogOnlyProbesInSafeURLFile: the two probes next to the recorded
// precedent in internal/zzprobe/federation/safeurl_test.go have no failing
// statement at all.
func TestZ16LogOnlyProbesInSafeURLFile(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "internal", "zzprobe", "federation", "safeurl_test.go")
	src := readFile(t, path)

	for _, name := range []string{
		"TestProbeURLHostNormalisation",
		"TestProbeZonedIPv6DialAddressIsJudgedNotCrashed",
	} {
		body := funcBody(t, src, name)
		if body == "" {
			t.Fatalf("cannot find func %s in safeurl_test.go; update this probe", name)
		}
		if regexp.MustCompile(`t\.(Errorf?|Fatalf?|FailNow|Fail)\b`).MatchString(body) {
			t.Logf("%s now asserts; the finding is fixed", name)
			continue
		}
		// Live control: it passes, and for the zoned-address one it prints the
		// very verdict its name claims.
		ok, out := overlayRun(t, root, "", "./internal/zzprobe/federation/", []string{"audit5"}, "^"+name+"$")
		if !ok {
			t.Fatalf("control: %s fails, so it is not the shape this finding describes:\n%s", name, out)
		}
		if !strings.Contains(out, "--- PASS: "+name) {
			t.Fatalf("control: %s did not report PASS:\n%s", name, out)
		}
		t.Errorf("%s (internal/zzprobe/federation/safeurl_test.go) has no failing statement anywhere: "+
			"it passes while printing its verdict (control above). It sits in the same file as the "+
			"recorded precedent TestProbeRegistryAcceptsPathEscapingNames, and it is the second and "+
			"third instance of that shape in this file — the SSRF host-normalisation and zone-id "+
			"reasoning is therefore carried by log text, not by a guard.", name)
	}
}

// funcBody returns the source of one top-level function, including nested braces.
func funcBody(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, "func "+name+"(")
	if start < 0 {
		return ""
	}
	open := strings.Index(src[start:], "{")
	if open < 0 {
		return ""
	}
	depth := 0
	for i := start + open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[start : i+1]
			}
		}
	}
	return ""
}
