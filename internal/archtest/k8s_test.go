package archtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestKubernetesBaselineHasProbesAndLimits: the manifests under deploy/k8s are a
// claim that this service can be run safely on a cluster. Assert the pieces that
// are easy to drop and expensive to miss: probes, resource requests/limits,
// a non-root read-only container, a PDB, and a NetworkPolicy.
func TestKubernetesBaselineHasProbesAndLimits(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, "deploy", "k8s", "base")
	if _, err := os.Stat(base); err != nil {
		t.Fatalf("deploy/k8s/base is missing: %v", err)
	}

	docs := readYAMLDocs(t, base)

	var deployment map[string]any
	var kinds = map[string]bool{}
	for _, doc := range docs {
		kind, _ := doc["kind"].(string)
		kinds[kind] = true
		if kind == "Deployment" {
			deployment = doc
		}
	}
	for _, want := range []string{"Deployment", "Service", "PodDisruptionBudget", "NetworkPolicy", "ServiceAccount"} {
		if !kinds[want] {
			t.Fatalf("deploy/k8s/base has no %s", want)
		}
	}
	if deployment == nil {
		t.Fatal("no Deployment document parsed")
	}

	spec := nestedMap(t, deployment, "spec", "template", "spec")
	containers, _ := spec["containers"].([]any)
	if len(containers) == 0 {
		t.Fatal("Deployment has no containers")
	}
	container, _ := containers[0].(map[string]any)
	for _, probe := range []string{"livenessProbe", "readinessProbe"} {
		if _, ok := container[probe].(map[string]any); !ok {
			t.Fatalf("container has no %s", probe)
		}
	}
	resources, ok := container["resources"].(map[string]any)
	if !ok {
		t.Fatal("container has no resources block")
	}
	for _, field := range []string{"requests", "limits"} {
		if _, ok := resources[field].(map[string]any); !ok {
			t.Fatalf("container resources have no %s", field)
		}
	}
	security, ok := container["securityContext"].(map[string]any)
	if !ok {
		t.Fatal("container has no securityContext")
	}
	if security["allowPrivilegeEscalation"] != false {
		t.Fatalf("container allows privilege escalation: %v", security)
	}
	if security["readOnlyRootFilesystem"] != true {
		t.Fatalf("container does not use a read-only root filesystem: %v", security)
	}
	podSecurity, ok := spec["securityContext"].(map[string]any)
	if !ok || podSecurity["runAsNonRoot"] != true {
		t.Fatalf("pod is not runAsNonRoot: %v", podSecurity)
	}
	if _, ok := spec["terminationGracePeriodSeconds"]; !ok {
		t.Fatal("pod has no terminationGracePeriodSeconds; the 30s drain needs one")
	}
}

func readYAMLDocs(t *testing.T, dir string) []map[string]any {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, e := range entries {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(raw)))
		for {
			var doc map[string]any
			if err := dec.Decode(&doc); err != nil {
				break
			}
			if doc != nil {
				out = append(out, doc)
			}
		}
	}
	return out
}

func nestedMap(t *testing.T, doc map[string]any, path ...string) map[string]any {
	t.Helper()
	cur := doc
	for _, key := range path {
		next, ok := cur[key].(map[string]any)
		if !ok {
			t.Fatalf("missing %q in %v", key, path)
		}
		cur = next
	}
	return cur
}
