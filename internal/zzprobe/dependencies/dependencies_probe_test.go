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
// permission notice to travel with all copies; NOTICE is generated for the Go module
// graph only and contains no npm package at all.
//
// The probe skips when only the embed placeholder is present, so it is honest about
// not having a built frontend to read.
func TestProbeShippedFrontendCarriesThirdPartyAttribution(t *testing.T) {
	root := repoRoot(t)
	dist := filepath.Join(root, "internal", "webui", "dist")
	if _, err := os.Stat(filepath.Join(dist, "index.html")); err != nil {
		t.Skip("internal/webui/dist holds the placeholder; run `pnpm run build` in web/")
	}

	markers := regexp.MustCompile(`(?i)copyright|@license|SPDX-License-Identifier|Licensed under`)
	var files, hits, svelteRuntime int
	err := filepath.Walk(dist, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		switch filepath.Ext(path) {
		case ".js", ".css", ".mjs":
		default:
			return nil
		}
		files++
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		body := string(b)
		if markers.MatchString(body) {
			hits++
		}
		if strings.Contains(body, "__svelte") {
			svelteRuntime++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The floor: these files exist, so "no licence text found" cannot be an artefact
	// of walking nothing. This is also what proves the bundle really is third-party
	// code and not an empty shell.
	if files < 5 {
		t.Fatalf("only %d built asset(s) under %s; the walk found nothing to read", files, dist)
	}
	if svelteRuntime == 0 {
		t.Fatalf("no built asset mentions the Svelte runtime; either the framework changed its "+
			"marker or this is not a real build, so the licencing claim below is unchecked "+
			"(%d files scanned)", files)
	}
	if hits == 0 {
		t.Errorf("%d built assets ship inside the binary but none carries a copyright or licence "+
			"notice: the Svelte/SvelteKit runtime (%d files mention it) is redistributed without "+
			"attribution, and NOTICE lists Go modules only", files, svelteRuntime)
	}
}
