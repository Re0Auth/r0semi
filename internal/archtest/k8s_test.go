package archtest

import (
	"os"
	"path/filepath"
	"slices"
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
	for _, probe := range []string{"startupProbe", "livenessProbe", "readinessProbe"} {
		if _, ok := container[probe].(map[string]any); !ok {
			t.Fatalf("container has no %s", probe)
		}
	}
	// The startup probe's whole job is to outlast a slow start — migrations run
	// before the listener binds, and a second replica waits on the migration
	// advisory lock for as long as the first one takes. A presence check alone
	// would pass for a probe that gives up in five seconds, so what is asserted
	// here is the budget.
	startup := container["startupProbe"].(map[string]any)
	period, periodOK := startup["periodSeconds"].(int)
	threshold, thresholdOK := startup["failureThreshold"].(int)
	if !periodOK || !thresholdOK {
		t.Fatalf("startupProbe needs a numeric periodSeconds and failureThreshold: %v", startup)
	}
	if budget := period * threshold; budget < 90 {
		t.Fatalf("startupProbe budget is %ds, want at least 90s so a slow migration is not killed mid-flight",
			budget)
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

// TestKubernetesBaselinePinsItsImageAndNamesItsTLSSecret: a baseline is a claim about
// what a deployment needs, and two things in it are easy to leave dangling.
//
// The image. `latest` is a floating reference: a redeploy silently picks up whatever
// was pushed last, which is the opposite of what pinning a release means. The file
// says "pin a released tag or, better, a digest" in a comment; this makes it a check.
//
// The TLS secret. The Ingress terminates TLS with a secret the base does not create,
// so a fresh cluster applies an Ingress that can never serve. That prerequisite is
// allowed to be the deployment's job — shipping a Certificate would make cert-manager
// a hard requirement — but it has to be named where an operator will read it.
func TestKubernetesBaselinePinsItsImageAndNamesItsTLSSecret(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, "deploy", "k8s", "base")

	raw, err := os.ReadFile(filepath.Join(base, "kustomization.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var kustomization struct {
		Images []struct {
			Name   string `yaml:"name"`
			NewTag string `yaml:"newTag"`
			Digest string `yaml:"digest"`
		} `yaml:"images"`
	}
	if err := yaml.Unmarshal(raw, &kustomization); err != nil {
		t.Fatal(err)
	}
	if len(kustomization.Images) == 0 {
		t.Fatal("the base images nothing, so it deploys whatever the Deployment names")
	}
	for _, img := range kustomization.Images {
		if img.Digest != "" {
			continue
		}
		if img.NewTag == "" || img.NewTag == "latest" {
			t.Errorf("%s is not pinned (newTag=%q digest=%q); pin a released tag or a digest",
				img.Name, img.NewTag, img.Digest)
		}
	}

	ingressRaw, err := os.ReadFile(filepath.Join(base, "ingress.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var ingress struct {
		Spec struct {
			TLS []struct {
				SecretName string `yaml:"secretName"`
			} `yaml:"tls"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(ingressRaw, &ingress); err != nil {
		t.Fatal(err)
	}
	if len(ingress.Spec.TLS) == 0 {
		t.Fatal("the Ingress terminates no TLS, and the base is expected to")
	}
	operations, err := os.ReadFile(filepath.Join(root, "docs", "operations.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range ingress.Spec.TLS {
		if entry.SecretName == "" {
			continue
		}
		if !strings.Contains(string(operations), entry.SecretName) {
			t.Errorf("the Ingress needs the TLS secret %q and docs/operations.md never names it; "+
				"a prerequisite an operator cannot find is a dangling one", entry.SecretName)
		}
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

// TestBackupWorkloadIsSafeToLeaveRunning guards deploy/k8s/backup, the scheduled
// logical backup. It is a workload nobody looks at until the day they need it, and
// every one of its failure modes is silent: an image that changed under them, dumps
// that overlap and starve the service's connection budget, an unbounded dump
// directory that fills the volume and stops the backups, or a container running as
// root against a volume it also writes. Each of those is asserted rather than
// described.
func TestBackupWorkloadIsSafeToLeaveRunning(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	docs := readYAMLDocs(t, filepath.Join(root, "deploy", "k8s", "backup"))

	// The kustomization has to list both manifests: a file that exists but is not
	// referenced is applied by nobody, and the failure looks like "the backup never
	// ran" rather than like a missing line.
	var kustomization struct {
		Namespace string   `yaml:"namespace"`
		Resources []string `yaml:"resources"`
	}
	raw, err := os.ReadFile(filepath.Join(root, "deploy", "k8s", "backup", "kustomization.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &kustomization); err != nil {
		t.Fatalf("backup kustomization does not parse: %v", err)
	}
	for _, want := range []string{"pvc.yaml", "cronjob.yaml"} {
		if !slices.Contains(kustomization.Resources, want) {
			t.Fatalf("the backup kustomization does not list %s: %v", want, kustomization.Resources)
		}
	}
	if kustomization.Namespace != "re0auth" {
		t.Fatalf("backup kustomization namespace = %q, want re0auth (the base's namespace)", kustomization.Namespace)
	}

	var cron map[string]any
	kinds := map[string]bool{}
	for _, doc := range docs {
		kind, _ := doc["kind"].(string)
		kinds[kind] = true
		if kind == "CronJob" {
			cron = doc
		}
	}
	for _, want := range []string{"CronJob", "PersistentVolumeClaim"} {
		if !kinds[want] {
			t.Fatalf("deploy/k8s/backup has no %s", want)
		}
	}
	if cron == nil {
		t.Fatal("no CronJob document parsed")
	}

	jobSpec := nestedMap(t, cron, "spec")
	if schedule, _ := jobSpec["schedule"].(string); strings.TrimSpace(schedule) == "" {
		t.Fatal("the backup CronJob has no schedule")
	}
	// Forbid is the one setting that keeps a slow dump from racing the next one.
	if policy, _ := jobSpec["concurrencyPolicy"].(string); policy != "Forbid" {
		t.Fatalf("concurrencyPolicy = %q, want Forbid: overlapping dumps compete for the service's connection budget",
			policy)
	}

	podSpec := nestedMap(t, cron, "spec", "jobTemplate", "spec", "template", "spec")
	if podSecurity, ok := podSpec["securityContext"].(map[string]any); !ok || podSecurity["runAsNonRoot"] != true {
		t.Fatalf("backup pod is not runAsNonRoot: %v", podSpec["securityContext"])
	}
	containers, _ := podSpec["containers"].([]any)
	if len(containers) == 0 {
		t.Fatal("the backup CronJob has no containers")
	}
	container, _ := containers[0].(map[string]any)
	image, _ := container["image"].(string)
	if !strings.Contains(image, "@sha256:") {
		t.Fatalf("backup image %q is not pinned by digest", image)
	}
	resources, ok := container["resources"].(map[string]any)
	if !ok {
		t.Fatal("the backup container has no resources block")
	}
	for _, field := range []string{"requests", "limits"} {
		if _, ok := resources[field].(map[string]any); !ok {
			t.Fatalf("backup resources have no %s", field)
		}
	}
	security, ok := container["securityContext"].(map[string]any)
	if !ok {
		t.Fatal("the backup container has no securityContext")
	}
	if security["allowPrivilegeEscalation"] != false || security["readOnlyRootFilesystem"] != true {
		t.Fatalf("backup container securityContext = %v", security)
	}

	mounts, _ := container["volumeMounts"].([]any)
	mounted := false
	for _, m := range mounts {
		if mm, ok := m.(map[string]any); ok && mm["mountPath"] == "/backups" {
			mounted = true
		}
	}
	if !mounted {
		t.Fatal("nothing is mounted at /backups; the dump would be written into the container and lost")
	}

	// The script's own load-bearing lines: a dump with no retention fills the volume
	// and every later run fails, and a dump with no checksum cannot be told apart
	// from a truncated one.
	args, _ := container["args"].([]any)
	script := ""
	for _, a := range args {
		if s, ok := a.(string); ok {
			script += s
		}
	}
	for _, want := range []struct{ needle, why string }{
		{"pg_dump", "the workload must dump the database"},
		{"sha256sum", "each dump needs its checksum beside it"},
		{"-mtime", "an unbounded dump directory fills the volume and stops the backups"},
	} {
		if !strings.Contains(script, want.needle) {
			t.Fatalf("the backup script does not contain %q: %s", want.needle, want.why)
		}
	}
}
