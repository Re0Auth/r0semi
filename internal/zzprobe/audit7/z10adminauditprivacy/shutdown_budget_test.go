//go:build audit7

// Zone-10 probe: does the whole shutdown stack fit inside the pod's grace period?
//
// The audit batcher drains through Close, and Close runs from store.close, which
// is the LAST deferred call in the composition root — after the HTTP server's own
// drain. So the pod's grace budget has to cover, in series:
//
//	endpointRemovalWait (sleep) + shutdownTimeout (HTTP drain) + auditDrainTimeout
//
// The round-5 fix for "the shutdown drain budget can outlast the pod grace"
// (P2-31) bounded the third term but did not add the first two back in. That was
// G-12/Z10-3: `5 + 30 + 30 = 65s` against a 45s grace. It has since been fixed —
// auditDrainTimeout is 10s, the manifest comment counts all three terms
// (`5 + 30 + 10 = 45s`) and the CHANGELOG advises `terminationGracePeriodSeconds
// ≥ 45s` — and this test now guards the fixed arithmetic, failing if the total
// exceeds the grace again.
//
// The operational listener is not part of this series: it is marked noDrain and
// closed outright rather than sharing the drain context with the public listener
// (Z10V-2; the guard for that half lives in z10verify).
package z10adminauditprivacy

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// repoFile reads one source file from the repository, found by walking up to the
// module root. The test's working directory is this package, so the path is
// relative on purpose.
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find the module root above %s", dir)
		}
		dir = parent
	}
	body, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(body)
}

// secondsNamed extracts `name = <N> * time.Second` and fails loudly when the
// declaration moved, so a rename cannot turn this probe into a no-op.
func secondsNamed(t *testing.T, body, file, name string) int {
	t.Helper()
	re := regexp.MustCompile(`(?m)\b` + regexp.QuoteMeta(name) + `\s*=\s*(\d+)\s*\*\s*time\.Second`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("%s no longer declares %s = <N> * time.Second; this probe would be vacuous", file, name)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("%s: %s is not a number: %q", file, name, m[1])
	}
	return n
}

func TestZ10TheWholeShutdownStackFitsThePodGracePeriod(t *testing.T) {
	main := repoFile(t, filepath.Join("cmd", "re0auth", "main.go"))
	batch := repoFile(t, filepath.Join("internal", "store", "postgres", "auditbatch.go"))
	deploy := repoFile(t, filepath.Join("deploy", "k8s", "base", "deployment.yaml"))

	removal := secondsNamed(t, main, "cmd/re0auth/main.go", "endpointRemovalWait")
	shutdown := secondsNamed(t, main, "cmd/re0auth/main.go", "shutdownTimeout")
	drain := secondsNamed(t, batch, "internal/store/postgres/auditbatch.go", "auditDrainTimeout")

	re := regexp.MustCompile(`(?m)^\s*terminationGracePeriodSeconds:\s*(\d+)\s*$`)
	m := re.FindStringSubmatch(deploy)
	if m == nil {
		t.Fatalf("deploy/k8s/base/deployment.yaml no longer declares terminationGracePeriodSeconds")
	}
	grace, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	if removal == 0 || shutdown == 0 || drain == 0 || grace == 0 {
		t.Fatalf("a parsed value is zero (%d/%d/%d/%d): the probe is not reading what it thinks",
			removal, shutdown, drain, grace)
	}

	total := removal + shutdown + drain
	t.Logf("endpointRemovalWait=%ds + shutdownTimeout=%ds (HTTP drain) + auditDrainTimeout=%ds (audit batch drain, "+
		"the last deferred Close) = %ds, terminationGracePeriodSeconds=%ds", removal, shutdown, drain, total, grace)

	if total > grace {
		t.Errorf("the shutdown stack needs %ds but the pod is SIGKILLed after %ds: the audit drain runs only "+
			"after the HTTP drain has had its full %ds, so a slow drain is killed with rows still queued. "+
			"Those writers are never answered (a SIGKILL logs nothing), and the deployment comment and "+
			"CHANGELOG still say the budget is %ds.", total, grace, shutdown, removal+shutdown)
	}
}
