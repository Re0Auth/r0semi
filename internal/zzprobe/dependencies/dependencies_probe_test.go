//go:build audit5

// Package dependencies holds read-only probes for the dependency-graph and
// build/release supply-chain audit. Nothing here modifies the tree: every probe
// reads a file that already exists (workflows, Makefile, the built frontend) and
// fails when the property it names stops holding.
//
// The files are read from disk rather than through `go list`/`make`, so these
// probes run on any platform with no DB, no Docker and no toolchain installs.
package dependencies

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoRoot walks up from internal/zzprobe/dependencies to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found at %s: %v", root, err)
	}
	return root
}

func readFile(t *testing.T, root string, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{root}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var (
	usesLine = regexp.MustCompile(`(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)`)
	shaPin   = regexp.MustCompile(`@[0-9a-f]{40}$`)
)

// TestProbeWorkflowActionsArePinnedToASHA is the guard docs/dependencies.md §7
// claims exists ("固定本身由 internal/archtest … 守住") and which, at the time of
// the audit, did not: internal/archtest/workflows_test.go only checks pnpm cache
// wiring, and internal/archtest/dockerfile_test.go only reads the Dockerfile.
//
// A floating `@v4` is somebody else's code running with this repository's token.
// The only legitimate exception is a local reusable workflow (`uses: ./…`), which
// has no SHA to pin.
//
// The floor at the end is the anti-vacuous half: a reworded workflow or a moved
// directory must fail here rather than pass by finding nothing.
func TestProbeWorkflowActionsArePinnedToASHA(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	checked, local := 0, 0
	for _, e := range entries {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yml") && !strings.HasSuffix(e.Name(), ".yaml")) {
			continue
		}
		body := readFile(t, dir, e.Name())
		for _, m := range usesLine.FindAllStringSubmatch(body, -1) {
			ref := m[1]
			if strings.HasPrefix(ref, "./") {
				local++
				continue
			}
			checked++
			if !shaPin.MatchString(ref) {
				t.Errorf("%s: `uses: %s` is not pinned to a full commit SHA; a tag can move "+
					"and this action runs inside a job holding a repository token", e.Name(), ref)
			}
		}
	}

	if checked < 10 {
		t.Fatalf("only %d remote `uses:` refs were parsed; the parser is no longer reading the "+
			"workflows (local reusable workflows seen: %d)", checked, local)
	}
	if local == 0 {
		t.Fatalf("no local reusable workflow (`uses: ./…`) was seen; the exemption above is " +
			"now unchecked, which is exactly the hole it exists to avoid")
	}
}

// TestProbeDockerfileRuntimeCarriesLicenceAndNotice: the archives ship LICENSE and
// NOTICE (Makefile:167) but the runtime image ships only the binary and a CA bundle
// (Dockerfile:59-64), so the image — the artifact deploy/k8s actually runs, and the
// one published to GHCR — carries neither the MPL-2.0 text nor the Apache-2.0 §4(d)
// attributions that NOTICE reproduces.
func TestProbeDockerfileRuntimeCarriesLicenceAndNotice(t *testing.T) {
	root := repoRoot(t)
	df := readFile(t, root, "Dockerfile")

	// The runtime stage is the one after the last FROM.
	idx := strings.LastIndex(df, "FROM ")
	if idx < 0 {
		t.Fatal("no FROM line in the Dockerfile; the parse below would be meaningless")
	}
	runtime := df[idx:]

	for _, want := range []string{"LICENSE", "NOTICE"} {
		if !strings.Contains(runtime, want) {
			t.Errorf("the runtime image stage never copies %s; the archive does (Makefile:167), "+
				"so the two artifacts of the same tag are not equally redistributable", want)
		}
	}
	if !strings.Contains(df, "FROM scratch") {
		t.Fatalf("the runtime stage is no longer FROM scratch; re-read what this probe assumes")
	}
}

var distCopy = regexp.MustCompile(`(?m)^\t.*\bcp\s+[^\n]*$`)

// TestProbeDistRecipeCopiesAreFatal: `make dist` assembles the release archives.
// `go build` and `tar`/`zip` carry `|| exit 1`, but the `cp` that puts LICENSE,
// NOTICE, README.md and SECURITY.md into each archive does not — and the loop body
// runs under a single `sh -c` with no `set -e`. A rename of any of those files
// therefore yields six valid archives that are each missing a file, while every
// checksum, the SBOM and the release all still succeed.
//
// internal/zzprobe/deploy/artifacts_test.go:475 guards two of the five names, but it
// reads the recipe text, so it passes on exactly this failure.
func TestProbeDistRecipeCopiesAreFatal(t *testing.T) {
	root := repoRoot(t)
	mk := readFile(t, root, "Makefile")

	recipe := recipeOf(mk, "dist")
	if recipe == "" {
		t.Fatal("could not find the dist target in the Makefile")
	}

	copies := distCopy.FindAllString(recipe, -1)
	if len(copies) == 0 {
		t.Fatalf("the dist recipe now copies nothing; the probe cannot distinguish "+
			"\"guarded\" from \"absent\"\nrecipe:\n%s", recipe)
	}
	for _, c := range copies {
		if !strings.Contains(c, "|| exit 1") && !strings.Contains(c, "|| { ") && !strings.Contains(c, "&& exit") {
			t.Errorf("this copy in the dist recipe cannot fail the recipe, so a missing source file "+
				"ships an archive without it:\n  %s", strings.TrimSpace(c))
		}
	}
}

// recipeOf returns the indented (tab-continued) lines of a Makefile target.
func recipeOf(makefile, target string) string {
	var b strings.Builder
	inTarget := false
	for _, line := range strings.Split(strings.ReplaceAll(makefile, "\r\n", "\n"), "\n") {
		if !inTarget {
			if strings.HasPrefix(line, target+":") {
				inTarget = true
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] != '\t' && line[0] != ' ' {
			break
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// TestProbeShippedFrontendCarriesThirdPartyAttribution: internal/webui embeds the
// built SPA (webui.go `//go:embed all:dist`), so the Svelte/SvelteKit runtime code
// ships inside every binary, archive and image. MIT/ISC require the copyright and
// permission notice to travel with all copies.
//
// The mechanism is the `make npm-attribution` target, which writes
// dist/re0auth_<ver>_npm-attribution.json (a pnpm licence listing) and is a
// prerequisite of `checksums`/`release`, so the file ships in SHA256SUMS and the
// archives. It is NOT inlined licence text in the bundle: Svelte/SvelteKit do not
// emit MIT banners into built JS, so asserting in-bundle markers tested the wrong
// object. This probe asserts the wiring that actually carries the attribution, and
// (when a frontend has been built) that in-bundle markers, if present, are not the
// whole story.
func TestProbeShippedFrontendCarriesThirdPartyAttribution(t *testing.T) {
	root := repoRoot(t)

	// 1. The Makefile defines the target and makes it ship.
	mk := readFile(t, root, "Makefile")
	if !strings.Contains(mk, "npm-attribution:") {
		t.Error("the Makefile has no npm-attribution target: the SPA's npm dependencies ship without " +
			"the licence listing that satisfies their MIT/ISC notice requirement")
	}
	for _, need := range []string{
		"pnpm licenses list --json",
		"re0auth_$${VERSION}_npm-attribution.json",
	} {
		if !strings.Contains(mk, need) {
			t.Errorf("the npm-attribution target does not contain %q; it must produce a non-empty licence listing", need)
		}
	}
	// The output must be a prerequisite of checksums (so it is in SHA256SUMS) and of
	// release (so it is built).
	if !strings.Contains(mk, "checksums: sbom npm-attribution") {
		t.Error("checksums does not depend on npm-attribution: the licence listing would not be " +
			"covered by SHA256SUMS")
	}
	if !strings.Contains(mk, "release: dist sbom npm-attribution checksums") {
		t.Error("release does not depend on npm-attribution: the listing would not be built into a release")
	}
	if !strings.Contains(mk, `test -s "dist/re0auth_$${VERSION}_npm-attribution.json"`) {
		t.Error("the target does not refuse an empty listing; an empty file satisfies nothing")
	}

	// 2. NOTICE covers the Go graph only — this is the documented split, so the npm
	//    half is the JSON, not NOTICE.
	notice := readFile(t, root, "NOTICE")
	if strings.Contains(notice, "svelte") {
		t.Log("NOTICE already mentions an npm package; the split may have changed")
	}

	// 3. When a real frontend build exists, confirm the bundle really is third-party
	//    code (so the claim above is about something that ships). Skipped when only
	//    the embed placeholder is present.
	dist := filepath.Join(root, "internal", "webui", "dist")
	if _, err := os.Stat(filepath.Join(dist, "index.html")); err != nil {
		t.Skip("internal/webui/dist holds the placeholder; run `pnpm run build` in web/")
	}
	var files, svelteRuntime int
	err := filepath.Walk(dist, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || (filepath.Ext(path) != ".js" && filepath.Ext(path) != ".css" && filepath.Ext(path) != ".mjs") {
			return nil
		}
		files++
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "__svelte") {
			svelteRuntime++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 5 {
		t.Fatalf("only %d built asset(s) under %s; the walk found nothing to read", files, dist)
	}
	if svelteRuntime == 0 {
		t.Fatalf("no built asset mentions the Svelte runtime; the bundle is not what the attribution covers")
	}
	t.Logf("%d built assets ship inside the binary (%d mention the Svelte runtime); their npm "+
		"attribution travels in the release's npm-attribution JSON, generated by make npm-attribution", files, svelteRuntime)
}
