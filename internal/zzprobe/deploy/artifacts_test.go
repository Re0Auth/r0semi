//go:build audit5

// Package deploy holds adversarial probes for the shipping/ops surface of this
// repository: the Dockerfile, the k8s manifests, the workflows and the release
// chain. It exists because internal/archtest asserts that a Deployment *has* a
// NetworkPolicy and a PDB, but nothing asserts that either one actually selects
// the pods it is supposed to govern.
//
// These are probe tests, not product tests: they read the artifacts as text and
// cross-check them against each other and against the code. Each one says which
// invariant it pins and which change would make it fail.
package deploy

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// repoRoot is the module root: this package's test binary runs from its own dir.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", "..", ".."))
}

func readFile(t *testing.T, parts ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(parts...), err)
	}
	return string(raw)
}

// yamlDocs decodes every document in a multi-document YAML file.
func yamlDocs(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	var out []map[string]any
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			break
		}
		if doc != nil {
			out = append(out, doc)
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s parsed to no documents", path)
	}
	return out
}

func dig(t *testing.T, doc map[string]any, path ...string) map[string]any {
	t.Helper()
	cur := doc
	for _, key := range path {
		next, ok := cur[key].(map[string]any)
		if !ok {
			t.Fatalf("missing %q in %v (got %T)", key, path, cur[key])
		}
		cur = next
	}
	return cur
}

// podLabels returns a workload's pod-template labels as a "k=v" set. path points
// at the pod *template* (the object whose metadata carries the labels).
func podLabels(t *testing.T, doc map[string]any, path ...string) map[string]bool {
	t.Helper()
	tmpl := dig(t, doc, path...)
	meta, _ := tmpl["metadata"].(map[string]any)
	labels, _ := meta["labels"].(map[string]any)
	out := map[string]bool{}
	for k, v := range labels {
		out[k+"="+toString(v)] = true
	}
	return out
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func baseDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "deploy", "k8s", "base")
}

// TestBaseNetworkPolicySelectsTheDeploymentItProtects cross-checks the four
// selectors in deploy/k8s/base against each other.
//
// The gap this closes: `internal/archtest` proves a NetworkPolicy document
// exists. A NetworkPolicy whose podSelector matches nothing is a policy that
// protects nothing, and it looks identical in a green job (and in
// `kubectl apply`) to one that works — which matters here because the
// ConfigMap's own comment makes the NetworkPolicy the entire safety argument for
// `expose_internal = true`.
func TestBaseNetworkPolicySelectsTheDeploymentItProtects(t *testing.T) {
	base := baseDir(t)

	var deployment, netpol, svcDoc, pdb map[string]any
	for _, doc := range yamlDocs(t, filepath.Join(base, "deployment.yaml")) {
		if doc["kind"] == "Deployment" {
			deployment = doc
		}
	}
	for _, doc := range yamlDocs(t, filepath.Join(base, "networkpolicy.yaml")) {
		if doc["kind"] == "NetworkPolicy" {
			netpol = doc
		}
	}
	for _, doc := range yamlDocs(t, filepath.Join(base, "pdb.yaml")) {
		if doc["kind"] == "PodDisruptionBudget" {
			pdb = doc
		}
	}
	services := yamlDocs(t, filepath.Join(base, "service.yaml"))
	if len(services) < 2 {
		t.Fatalf("expected the public and internal Services, got %d", len(services))
	}
	svcDoc = services[0]
	for _, doc := range services {
		if doc["kind"] == "Service" && doc["metadata"].(map[string]any)["name"] == "re0auth" {
			svcDoc = doc
		}
	}
	if deployment == nil || netpol == nil || pdb == nil || svcDoc == nil {
		t.Fatal("could not find all four documents")
	}

	pods := podLabels(t, deployment, "spec", "template")
	if len(pods) == 0 {
		t.Fatal("the Deployment's pod template carries no labels")
	}
	spec := deployment["spec"].(map[string]any)
	selector := spec["selector"].(map[string]any)["matchLabels"].(map[string]any)
	for k, v := range selector {
		if !pods[k+"="+toString(v)] {
			t.Errorf("the Deployment selector %s=%v does not match its own pod labels %v: "+
				"the Deployment would create pods it does not own", k, v, pods)
		}
	}

	// The anti-vacuous direction: the policy's selector must match the pods.
	npSpec := netpol["spec"].(map[string]any)
	npSelector := npSpec["podSelector"].(map[string]any)["matchLabels"].(map[string]any)
	if len(npSelector) == 0 {
		t.Error("the NetworkPolicy selects every pod in the namespace (empty podSelector)")
	}
	for k, v := range npSelector {
		if !pods[k+"="+toString(v)] {
			t.Errorf("the NetworkPolicy podSelector %s=%v matches none of the Deployment's pod labels %v: "+
				"the app would be unregulated while `kubectl apply` reports success", k, v, pods)
		}
	}

	// The Service must select the same pods, or the Ingress has no backend.
	svcSelector := svcDoc["spec"].(map[string]any)["selector"].(map[string]any)
	for k, v := range svcSelector {
		if !pods[k+"="+toString(v)] {
			t.Errorf("Service selector %s=%v matches no pod label %v", k, v, pods)
		}
	}
	// And the PDB.
	pdbSelector := pdb["spec"].(map[string]any)["selector"].(map[string]any)["matchLabels"].(map[string]any)
	for k, v := range pdbSelector {
		if !pods[k+"="+toString(v)] {
			t.Errorf("PDB selector %s=%v matches no pod label %v", k, v, pods)
		}
	}

	// The ingress rules themselves: 8080 only from the controller, 9090 only from
	// monitoring, and no rule that opens either port to every namespace.
	policyTypes, _ := npSpec["policyTypes"].([]any)
	hasIngress, hasEgress := false, false
	for _, p := range policyTypes {
		switch p {
		case "Ingress":
			hasIngress = true
		case "Egress":
			hasEgress = true
		}
	}
	if !hasIngress || !hasEgress {
		t.Errorf("policyTypes = %v; both directions must be declared, or the omitted one is allow-all "+
			"(the process talks to Postgres and to upstreams, and both must be enumerable)", policyTypes)
	}

	type rule struct {
		ns    string
		ports []int
	}
	var rules []rule
	for _, raw := range npSpec["ingress"].([]any) {
		r := raw.(map[string]any)
		var got rule
		for _, from := range r["from"].([]any) {
			f := from.(map[string]any)
			if sel, ok := f["namespaceSelector"].(map[string]any); ok {
				labels, _ := sel["matchLabels"].(map[string]any)
				if name, ok := labels["kubernetes.io/metadata.name"].(string); ok {
					got.ns = name
				}
				if sel["matchLabels"] == nil && sel["matchExpressions"] == nil {
					got.ns = "*"
				}
			}
			if _, ok := f["ipBlock"].(map[string]any); ok {
				got.ns = "ipBlock"
			}
		}
		for _, p := range r["ports"].([]any) {
			pm := p.(map[string]any)
			port, _ := pm["port"].(int)
			got.ports = append(got.ports, port)
		}
		rules = append(rules, got)
	}
	if len(rules) == 0 {
		t.Fatal("the NetworkPolicy allows no ingress at all")
	}
	seenPublic, seenInternal := false, false
	for _, r := range rules {
		for _, port := range r.ports {
			switch port {
			case 8080:
				seenPublic = true
				if r.ns != "ingress-nginx" {
					t.Errorf("port 8080 is open to %q (want ingress-nginx): the public listener would be "+
						"reachable from every pod in the cluster", r.ns)
				}
			case 9090:
				seenInternal = true
				if r.ns != "monitoring" {
					t.Errorf("port 9090 (/metrics, /debug/pprof/) is open to %q (want monitoring only): "+
						"a heap profile is one unreviewed rule away from every pod", r.ns)
				}
			default:
				t.Errorf("the NetworkPolicy opens port %d, which no listener in the Deployment publishes", port)
			}
		}
	}
	if !seenPublic || !seenInternal {
		t.Errorf("ingress rules cover public=%v internal=%v; both listeners need a rule or the policy "+
			"silently denies the platform (public) or the scrapers (internal)", seenPublic, seenInternal)
	}
}

// TestExposeInternalAcknowledgementIsBackedByAPolicy pins the ConfigMap's own
// claim: "What makes it safe is the NetworkPolicy beside this file". The claim is
// only true while the acknowledgement and the policy travel together, and the
// acknowledgement alone is one line in a file whose default is the opposite.
func TestExposeInternalAcknowledgementIsBackedByAPolicy(t *testing.T) {
	base := baseDir(t)
	cm := yamlDocs(t, filepath.Join(base, "configmap.yaml"))[0]
	data := cm["data"].(map[string]any)["re0auth.toml"].(string)

	if !regexp.MustCompile(`(?m)^\s*expose_internal\s*=\s*true`).MatchString(data) {
		t.Skip("the base no longer binds a non-loopback internal address; nothing to back")
	}
	if !regexp.MustCompile(`(?m)^\s*internal_addr\s*=\s*"?(0\.0\.0\.0|\[::\]|):`).MatchString(data) {
		t.Error("expose_internal = true without a non-loopback internal_addr: the acknowledgement is " +
			"no longer describing what the process does")
	}
	// And the policy that is offered as the reason must still exist and still
	// restrict 9090 — see TestBaseNetworkPolicySelectsTheDeploymentItProtects.
	raw := readFile(t, filepath.Join(base, "networkpolicy.yaml"))
	if !strings.Contains(raw, "monitoring") || !strings.Contains(raw, "9090") {
		t.Fatal("the ConfigMap justifies expose_internal with a NetworkPolicy that no longer restricts 9090")
	}

	// The other half of the same claim, on the app's side: the profiling endpoints
	// are registered by the internal listener's handler and never by the public
	// router.
	root := repoRoot(t)
	obs := filepath.Join(root, "internal", "observability")
	entries, err := os.ReadDir(obs)
	if err != nil {
		t.Fatal(err)
	}
	foundPprof := false
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		if strings.Contains(readFile(t, obs, e.Name()), "debug/pprof") {
			foundPprof = true
		}
	}
	if !foundPprof {
		t.Error("nothing in internal/observability registers /debug/pprof: either the claim in the " +
			"ConfigMap's comment is about a surface that no longer exists, or it moved")
	}
	api := filepath.Join(root, "internal", "httpapi")
	apiEntries, err := os.ReadDir(api)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range apiEntries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		if strings.Contains(readFile(t, api, e.Name()), "debug/pprof") {
			t.Errorf("internal/httpapi/%s registers /debug/pprof: the public router must not be able to "+
				"answer a heap or goroutine dump", e.Name())
		}
	}
}

// TestGracefulShutdownWindowsAgree is the "three numbers in three files" check.
//
// The app drains for shutdownTimeout after SIGTERM, the pod is given
// terminationGracePeriodSeconds before SIGKILL, and the Ingress must outwait both
// or it reports a 502 for a request the server was still answering. Any of the
// three can be edited alone, and archtest only asserts the k8s one is *present*.
func TestGracefulShutdownWindowsAgree(t *testing.T) {
	root := repoRoot(t)

	main := readFile(t, root, "cmd", "re0auth", "main.go")
	m := regexp.MustCompile(`shutdownTimeout\s*=\s*(\d+)\s*\*\s*time\.Second`).FindStringSubmatch(main)
	if m == nil {
		t.Fatal("could not find shutdownTimeout in cmd/re0auth/main.go; the probe is stale")
	}
	drain, _ := strconv.Atoi(m[1])

	var grace int
	for _, doc := range yamlDocs(t, filepath.Join(root, "deploy", "k8s", "base", "deployment.yaml")) {
		if doc["kind"] != "Deployment" {
			continue
		}
		spec := dig(t, doc, "spec", "template", "spec")
		if v, ok := spec["terminationGracePeriodSeconds"].(int); ok {
			grace = v
		}
	}
	if grace == 0 {
		t.Fatal("the Deployment has no terminationGracePeriodSeconds: a 30s drain would be SIGKILLed")
	}
	// The margin is the point: kubelet sends SIGTERM, the process drains, and the
	// pod also has to be removed from the Service endpoints and have its
	// connections closed. Grace equal to the drain leaves no room for any of that.
	if grace < drain+5 {
		t.Errorf("terminationGracePeriodSeconds = %ds against a %ds drain: in-flight requests are killed "+
			"mid-drain (want at least %ds)", grace, drain, drain+5)
	}

	// The proxy in front must also outwait the drain, or a request the server
	// answers cleanly is reported to the client as a gateway error.
	ingress := readFile(t, root, "deploy", "k8s", "base", "ingress.yaml")
	pm := regexp.MustCompile(`proxy-read-timeout:\s*"(\d+)"`).FindStringSubmatch(ingress)
	if pm == nil {
		t.Error("the Ingress sets no proxy-read-timeout; nginx's default (60s) happens to cover the drain, " +
			"but nothing states or checks it")
	} else if v, _ := strconv.Atoi(pm[1]); v < drain {
		t.Errorf("Ingress proxy-read-timeout = %ss is shorter than the %ds drain", pm[1], drain)
	}
}

// TestIngressHasNoAnnotationThatWouldWeakenTLSOrTrustHeaders: the Ingress is the
// only place in the repository where a single annotation can (a) turn off
// upstream TLS verification, (b) let a client choose the address the service
// believes it came from, or (c) run arbitrary nginx configuration. The app's
// client-address logic (server.trusted_proxies) depends on that header, so this
// is a security boundary rather than a tuning knob.
func TestIngressHasNoAnnotationThatWouldWeakenTLSOrTrustHeaders(t *testing.T) {
	ingress := readFile(t, repoRoot(t), "deploy", "k8s", "base", "ingress.yaml")
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(ingress), &doc); err != nil {
		t.Fatal(err)
	}
	meta, _ := doc["metadata"].(map[string]any)
	annotations, _ := meta["annotations"].(map[string]any)

	dangerous := []string{
		"ssl-verify",            // backend TLS verification off
		"proxy-ssl-verify",      //
		"use-forwarded-headers", // changes what X-Forwarded-For means
		"forwarded-for-header",  //
		"configuration-snippet", // arbitrary nginx config: the whole file as code
		"server-snippet",
		"location-snippet",
		"auth-snippet",
		"allowlist-source-range", // an allowlist is not a control if it is not here
		"auth-url",
		"backend-protocol",
	}
	for key := range annotations {
		for _, needle := range dangerous {
			if strings.Contains(key, needle) {
				t.Errorf("Ingress annotation %q changes TLS verification, header trust or runs nginx code; "+
					"if it is intended, it needs a test that says which property it is preserving", key)
			}
		}
	}
	// The body limit is a denial-of-service knob pointing the other way: a value
	// large enough to buffer in memory on every node.
	if v, ok := annotations["nginx.ingress.kubernetes.io/proxy-body-size"].(string); ok {
		if !strings.HasSuffix(v, "m") {
			t.Errorf("proxy-body-size = %q; only an explicit MiB value is reviewable", v)
		} else if n, err := strconv.Atoi(strings.TrimSuffix(v, "m")); err == nil && n > 8 {
			t.Errorf("proxy-body-size = %q is larger than the 4 MiB the data plane itself bounds a body to", v)
		}
	}
}

// TestBackupWorkloadIsUnselectedAndKeepsItsServiceAccountToken documents the two
// gaps in deploy/k8s/backup that no assertion covers yet.
//
// It is written to pass on the current artifacts because it is *describing* them:
// each assertion is the inverted form of the guard that should exist. Flipping
// either one is the fix.
func TestBackupWorkloadIsUnselectedAndKeepsItsServiceAccountToken(t *testing.T) {
	root := repoRoot(t)
	backup := filepath.Join(root, "deploy", "k8s", "backup")

	var cron map[string]any
	for _, doc := range yamlDocs(t, filepath.Join(backup, "cronjob.yaml")) {
		if doc["kind"] == "CronJob" {
			cron = doc
		}
	}
	if cron == nil {
		t.Fatal("no CronJob")
	}
	podSpec := dig(t, cron, "spec", "jobTemplate", "spec", "template", "spec")

	// 1. The dump pod carries no labels, so no NetworkPolicy in the repository
	//    selects it. On a cluster with a default-deny egress policy (the thing the
	//    base's own policy is a piece of), every run fails to reach Postgres — and
	//    a CronJob that fails is silent: nothing about a missing dump reaches the
	//    service's metrics, and there is no alert on backup staleness.
	tmpl := dig(t, cron, "spec", "jobTemplate", "spec", "template")
	tmplMeta, _ := tmpl["metadata"].(map[string]any)
	labels, hasLabels := tmplMeta["labels"]
	if hasLabels {
		t.Errorf("the backup pod now carries labels (%v); if they include the app's selector it is "+
			"covered by the app's NetworkPolicy, which allows no egress for it — re-read that policy "+
			"before keeping this", labels)
	} else {
		t.Log("GAP: the backup pod has no labels, so deploy/k8s/base/networkpolicy.yaml does not select it " +
			"and no policy grants it egress to Postgres; a default-deny cluster makes every dump fail silently")
	}

	// 2. It runs as the namespace's default ServiceAccount with a mounted token
	//    that it never uses — the base hardens this for the app and archtest does
	//    not check it for the CronJob.
	if v, ok := podSpec["automountServiceAccountToken"].(bool); ok && !v {
		t.Log("the backup pod already disables the ServiceAccount token mount")
	} else {
		t.Log("GAP: the backup pod mounts a ServiceAccount token (default true for the namespace's " +
			"default SA) inside the container that holds the database DSN; one line " +
			"(automountServiceAccountToken: false) removes a credential nothing reads")
	}
}

// TestReleasedArchivesCarryThePreReleaseWarning: README says the warning travels
// with the artifacts rather than staying in the repository. The archives are the
// half that is checkable without a tag run.
func TestReleasedArchivesCarryThePreReleaseWarning(t *testing.T) {
	root := repoRoot(t)
	makefile := readFile(t, root, "Makefile")

	// The `dist` target is what assembles an archive.
	distRecipe := recipeOf(makefile, "dist")
	if distRecipe == "" {
		t.Fatal("could not find the dist target in the Makefile")
	}
	for _, file := range []string{"README.md", "SECURITY.md"} {
		if !strings.Contains(distRecipe, file) {
			t.Errorf("the dist target no longer copies %s into the archive; the pre-release warning "+
				"lives there and would stop travelling with the release", file)
		}
	}
	readme := readFile(t, root, "README.md")
	if !strings.Contains(readme, "未达到生产可用") {
		t.Error("README.md no longer carries the pre-release warning the archives are supposed to ship")
	}
	security := readFile(t, root, "SECURITY.md")
	if !strings.Contains(security, "not production-ready") {
		t.Error("SECURITY.md no longer carries the pre-release warning")
	}

	// The other half of the same promise: the version in the archive must be the
	// tag, not `git describe` — and the image is built by a different job, so its
	// stamping has to be checked where it is set.
	release := readFile(t, root, ".github", "workflows", "release.yml")
	if !strings.Contains(release, `VERSION: ${{ github.ref_name }}`) {
		t.Error("release.yml no longer passes the tag as VERSION; the archives would report a describe string")
	}
	dockerfile := readFile(t, root, "Dockerfile")
	if !strings.Contains(dockerfile, "ARG VERSION=dev") {
		t.Log("the Dockerfile no longer defaults VERSION to dev; re-read how the image is stamped")
	}
}

// TestImageVersionStampingIsPresentInCIAndAbsentAtRelease describes, as a test,
// the difference between the two places the image is built: ci.yml passes
// VERSION=ci, and the release job — the one whose image is the one people pull —
// passes nothing at all, so the released binary answers "dev".
//
// The guard this should become is the direct statement of the invariant:
// release.yml's build-push-action must carry `VERSION=${{ github.ref_name }}`.
func TestImageVersionStampingIsPresentInCIAndAbsentAtRelease(t *testing.T) {
	root := repoRoot(t)
	ci := readFile(t, root, ".github", "workflows", "ci.yml")
	release := readFile(t, root, ".github", "workflows", "release.yml")

	if !strings.Contains(ci, "VERSION=ci") {
		t.Error("ci.yml no longer stamps the image (VERSION=ci); the mechanism this probe compares against is gone")
	}

	// The image job of release.yml is the block between `image:` and the next
	// top-level job. Look for a build-args VERSION there.
	imageJob := section(release, "  image:", "  release:")
	if imageJob == "" {
		t.Fatal("could not isolate the image job in release.yml")
	}
	if !regexp.MustCompile(`(?m)^\s*build-args:`).MatchString(imageJob) ||
		!strings.Contains(imageJob, "VERSION=") {
		t.Log("GAP: the release image job passes no VERSION build-arg, so ARG VERSION=dev (Dockerfile:48) " +
			"is what the published image was built with: `re0auth -version`, the startup log's version= field " +
			"and its provenance all say dev, in the one image a deployment actually pulls")
	}
	// The Dockerfile must keep offering the seam.
	if !strings.Contains(readFile(t, root, "Dockerfile"), "-X main.version=${VERSION}") {
		t.Error("the Dockerfile no longer feeds VERSION into main.version; the stamp cannot be set at all")
	}
}

// TestRuntimeStageShipsTheBinaryAndTheCABundleOnly is the "no config, no secrets
// in the image" claim, as a check on the one stage that ships.
func TestRuntimeStageShipsTheBinaryAndTheCABundleOnly(t *testing.T) {
	root := repoRoot(t)
	dockerfile := readFile(t, root, "Dockerfile")

	idx := strings.LastIndex(dockerfile, "FROM scratch")
	if idx < 0 {
		t.Fatal("the runtime stage is not FROM scratch")
	}
	runtime := dockerfile[idx:]
	// The licence and the attribution are the third thing the runtime stage is
	// allowed to carry (added with the P2-21 fix): NOTICE is what tells a
	// redistributor which third-party code is in the binary, so shipping the image
	// without it is the same gap as shipping an archive without it.
	allowed := []string{"/etc/ssl/certs/ca-certificates.crt", "/out/re0auth", "LICENSE", "NOTICE"}
	for _, line := range strings.Split(runtime, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "COPY ") && !strings.HasPrefix(trimmed, "ADD ") {
			continue
		}
		ok := false
		for _, src := range allowed {
			if strings.Contains(trimmed, src) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("the runtime stage copies something else: %q\n"+
				"Anything beyond the binary and the CA bundle is either a file that should be injected at "+
				"run time or a layer that can leak (the release ships no config and no key by design)", trimmed)
		}
	}
	if !strings.Contains(runtime, "USER 65532") {
		t.Error("the runtime stage lost its numeric non-root USER; scratch has no passwd, so a named user " +
			"could not be resolved even if one were written")
	}
	// CGO_ENABLED=0 is what makes scratch viable at all: a cgo binary needs a libc
	// that this stage does not have.
	if !strings.Contains(dockerfile, "CGO_ENABLED=0 go build") {
		t.Error("the build stage no longer sets CGO_ENABLED=0: the binary would depend on the build stage's libc")
	}
	// And the frontend assertion, which is what keeps a placeholder build from
	// being shipped.
	if strings.Count(dockerfile, "test -f internal/webui/dist/index.html") < 2 {
		t.Error("the Dockerfile no longer asserts the built frontend reached the embed directory in both stages " +
			"(the placeholder has no index.html, so that file is the evidence a real build happened)")
	}
}

// TestNoWorkflowRunsUntrustedCodeWithWritePermissions: every job that could run
// pull-request content must hold contents: read and nothing else, and no workflow
// may use pull_request_target (which hands a fork a token with the base repo's
// permissions).
func TestNoWorkflowRunsUntrustedCodeWithWritePermissions(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		raw := readFile(t, dir, e.Name())
		if strings.Contains(raw, "pull_request_target") {
			t.Errorf("%s uses pull_request_target: a fork's code would run with this repository's token", e.Name())
		}
		// The triggers this workflow answers to.
		onPR := regexp.MustCompile(`(?m)^\s*pull_request:?\s*$`).MatchString(raw) ||
			strings.Contains(raw, "pull_request:")
		if !onPR {
			continue
		}
		checked++
		// scan: it decides the permissions for the whole workflow; a job may narrow
		// them but not widen them.
		for _, perm := range []string{"contents: write", "packages: write", "id-token: write", "actions: write"} {
			if strings.Contains(raw, perm) {
				// release.yml does not answer pull_request; if one starts to, this
				// fires, which is the point.
				t.Errorf("%s answers pull_request and asks for %q somewhere in the file: "+
					"re-read which job holds it before a fork can reach it", e.Name(), perm)
			}
		}
	}
	if checked < 1 {
		t.Error("no workflow was found to answer pull_request; the probe is stale (ci.yml and codeql.yml both do)")
	}
}

// recipeOf returns the recipe (the indented lines) of a Makefile target.
func recipeOf(makefile, target string) string {
	var out []string
	in := false
	for _, line := range strings.Split(strings.ReplaceAll(makefile, "\r\n", "\n"), "\n") {
		if !in {
			if strings.HasPrefix(line, target+":") {
				in = true
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] != '\t' {
			break
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// section returns the text between two markers.
func section(text, start, end string) string {
	i := strings.Index(text, start)
	if i < 0 {
		return ""
	}
	rest := text[i:]
	if j := strings.Index(rest, end); j > 0 {
		return rest[:j]
	}
	return rest
}
