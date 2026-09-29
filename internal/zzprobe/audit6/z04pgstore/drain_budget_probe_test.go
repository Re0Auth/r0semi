//go:build audit6

package z04pgstore

// The P2-31 fix's arithmetic, checked against the numbers the deployment
// actually runs with.
//
// Round 5's P2-31: the audit batcher's shutdown drain had no total bound, and
// "the k8s manifest's 45s only counted the HTTP 30s". The fix (5cd1690) gave
// the drain a 30s budget (auditDrainTimeout) so it would finish instead of
// being SIGKILLed. But the budget does not run in parallel with the HTTP
// drain — it starts after it (serveUntilSignal → loops.Wait → db.Close →
// closers → auditBatcher.Close), which itself starts after the 5s
// endpoint-removal wait. The stacked worst case is therefore
//
//	endpointRemovalWait + shutdownTimeout + auditDrainTimeout
//	  = 5s + 30s + 30s = 65s
//
// against a terminationGracePeriodSeconds of 45. The budget exceeds the
// grace by 20 seconds in exactly the scenario it exists for — the database
// slow enough that every batch burns its full 5s, which is also what makes the
// HTTP drain time out with handlers still parked on the audit queue. The pod is
// SIGKILLed at t=45 while the drain's refusal path would only start refusing
// at t=65.
//
// This probe reads the three constants from the tracked sources and the grace
// from the manifest, and fails while they do not fit.

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// constSeconds reads `name = N * time.Second` (or `name = ND` for literal
// durations) from a Go file, failing the test when it is absent — a missing
// constant must never read as zero, or the arithmetic below would pass
// vacuously.
func constSeconds(t *testing.T, path, name string) time.Duration {
	t.Helper()
	code := readShipped(t, path)
	re := regexp.MustCompile(regexp.QuoteMeta(name) + `\s*=\s*(\d+)\s*\*\s*time\.Second`)
	m := re.FindStringSubmatch(code)
	if m == nil {
		// Also accept a plain integer (seconds written without the time
		// multiplication), used by none of the current constants but kept so a
		// refactor that changes the spelling still fails loudly here instead
		// of silently.
		re2 := regexp.MustCompile(regexp.QuoteMeta(name) + `\s*=\s*(\d+)\b`)
		m = re2.FindStringSubmatch(code)
		if m == nil {
			t.Fatalf("constant %s not found in %s; the probe is not reading the file", name, path)
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		return time.Duration(n) * time.Second
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return time.Duration(n) * time.Second
}

// graceSeconds reads terminationGracePeriodSeconds from the deployment
// manifest.
func graceSeconds(t *testing.T) time.Duration {
	t.Helper()
	yaml := readShipped(t, repoRoot+"/deploy/k8s/base/deployment.yaml")
	m := regexp.MustCompile(`terminationGracePeriodSeconds:\s*(\d+)`).FindStringSubmatch(yaml)
	if m == nil {
		t.Fatal("terminationGracePeriodSeconds not found in deployment.yaml; the probe is not reading the manifest")
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse grace: %v", err)
	}
	return time.Duration(n) * time.Second
}

// TestTheShutdownStackFitsThePodGrace is the finding: the three sequential
// shutdown budgets together exceed the grace period, so in the slow-database
// case the SIGKILL arrives before the audit drain's own budget can expire and
// refuse what is left.
func TestTheShutdownStackFitsThePodGrace(t *testing.T) {
	removal := constSeconds(t, repoRoot+"/cmd/re0auth/main.go", "endpointRemovalWait")
	http := constSeconds(t, repoRoot+"/cmd/re0auth/main.go", "shutdownTimeout")
	audit := constSeconds(t, adapterDir+"/auditbatch.go", "auditDrainTimeout")
	grace := graceSeconds(t)

	stack := removal + http + audit
	t.Logf("shutdown stack: endpointRemovalWait %s + shutdownTimeout %s + auditDrainTimeout %s = %s; "+
		"terminationGracePeriodSeconds = %s", removal, http, audit, stack, grace)

	if stack > grace {
		t.Errorf("the sequential shutdown budgets stack to %s against a %s grace period: the audit drain "+
			"starts only after the endpoint-removal wait and the HTTP drain have both run, so a database "+
			"slow enough to make each batch burn its full auditBatchTimeout (the scenario the budget "+
			"exists for) is SIGKILLed at %s while the drain would only begin refusing rows at %s — the "+
			"refusal path never runs in k8s and the in-flight batch is lost anyway.\n"+
			"Fix directions: derive auditDrainTimeout from grace - removal - http (10s here), or raise "+
			"terminationGracePeriodSeconds and update deployment.yaml's own comment, which still says "+
			"the total is 35s", stack, grace, grace, stack)
	}
}

// TestTheManifestCommentCountsTheWholeStack is the documentation half: the
// deployment manifest's justification for its grace period still accounts only
// for the HTTP drain ("35s total"), which is the same stale arithmetic P2-31
// was filed against. A future reader sizing the grace from that comment
// reproduces the hole.
func TestTheManifestCommentCountsTheWholeStack(t *testing.T) {
	yaml := readShipped(t, repoRoot+"/deploy/k8s/base/deployment.yaml")
	graceLine := regexp.MustCompile(`(?m)^.*terminationGracePeriodSeconds:`).FindString(yaml)
	if graceLine == "" {
		t.Fatal("terminationGracePeriodSeconds not found; the probe is not reading the manifest")
	}
	// The justification block is the comment immediately above the setting.
	idx := strings.LastIndex(yaml, graceLine)
	start := idx - 600 // ~the five comment lines above it
	if start < 0 {
		start = 0
	}
	block := yaml[start:idx]

	if !regexp.MustCompile(`\baudit\b`).MatchString(block) {
		t.Errorf("the comment justifying terminationGracePeriodSeconds does not mention the audit drain "+
			"budget (auditDrainTimeout = %s): it accounts for the HTTP drain alone ('35s total'), which is "+
			"the same stale arithmetic P2-31 was filed against — a future reader sizing the grace from that "+
			"comment reproduces the hole",
			constSeconds(t, adapterDir+"/auditbatch.go", "auditDrainTimeout"))
	}
}
