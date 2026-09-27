//go:build audit5

// Package verifydependencies holds the adversarial verifier's probes for
// docs/audit-5/findings/dependencies.md (findings SUP-1 … SUP-8).
//
// Nothing here modifies the tree: every probe reads files that already exist. The
// point of this package is not to re-run the audited report's probe (that one is
// internal/zzprobe/dependencies) but to test the *claims about the claims*:
//
//   - SUP-1's "no copyright/licence text at all" — with a positive control, because a
//     scan that finds nothing and a scan that is broken look identical.
//   - SUP-1's remedy 2 ("turn on legal-comment preservation") — whether there is
//     anything in the upstream runtime to preserve.
//   - SUP-3's count of 43 `uses:` sites and the doc's claim that a guard exists.
//   - SUP-4's consequence ("a rename ships silently") — which of the five files a
//     rename is actually loud for.
package verifydependencies

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

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

func mustRead(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// licenceMarkers is deliberately WIDER than the audited probe's
// (`copyright|@license|SPDX-License-Identifier|Licensed under`): it also matches the
// two shapes a minifier keeps without being asked to — the `/*!` bang comment and a
// bare "MIT License" banner. A narrower pattern that produces 0 is not evidence of
// anything until the wider one has been shown to work.
var licenceMarkers = regexp.MustCompile(`(?i)copyright|@license|SPDX|/\*!|Licensed under|Permission is hereby granted|MIT License`)

// scanLicenceMarkers returns, per file, the licence markers found under dir.
func scanLicenceMarkers(t *testing.T, dir string, exts ...string) (map[string][]string, int) {
	t.Helper()
	want := map[string]bool{}
	for _, e := range exts {
		want[e] = true
	}
	found := map[string][]string{}
	scanned := 0
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !want[filepath.Ext(path)] {
			return nil
		}
		scanned++
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range licenceMarkers.FindAllString(string(b), -1) {
			found[filepath.Base(path)] = append(found[filepath.Base(path)], m)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found, scanned
}

// TestVerifyLicenceScanHasAPositiveControl re-does SUP-1's negative with the control
// the audited report's marker set lacked, and then checks the substance: the bundle
// does contain third-party runtime code (Svelte/SvelteKit markers) while NOTICE names
// no npm package at all.
func TestVerifyLicenceScanHasAPositiveControl(t *testing.T) {
	root := repoRoot(t)
	dist := filepath.Join(root, "internal", "webui", "dist")
	if _, err := os.Stat(filepath.Join(dist, "index.html")); err != nil {
		t.Skip("internal/webui/dist holds the placeholder; no built frontend to scan")
	}

	// --- positive control: the same scanner, on a tree with a planted notice. ---
	ctl := t.TempDir()
	planted := filepath.Join(ctl, "planted.js")
	if err := os.WriteFile(planted, []byte("/*! Copyright (c) 2026 Positive Control @license MIT */\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hits, scanned := scanLicenceMarkers(t, ctl, ".js")
	if scanned != 1 || len(hits) == 0 {
		t.Fatalf("the scanner found nothing in a tree that contains a planted copyright notice "+
			"(scanned=%d files, hits=%v); every 0 below would be meaningless", scanned, hits)
	}
	t.Logf("positive control: scanner found %v in the planted tree", hits)

	// --- the real tree: every text file the build ships, not just .js/.css. ---
	real, scannedFiles := scanLicenceMarkers(t, dist, ".js", ".css", ".html", ".json", ".svg", ".txt")
	if scannedFiles < 21 {
		t.Fatalf("only %d deliverable files were scanned; the tree is smaller than the audit found, "+
			"so \"no notice found\" cannot be told apart from \"nothing was read\"", scannedFiles)
	}
	t.Logf("dist: %d text files scanned; files carrying any licence marker: %d", scannedFiles, len(real))
	for f, ms := range real {
		t.Logf("  %s: %v", f, ms)
	}

	// The correction to SUP-1: the bundle is NOT free of licence text. Tailwind's
	// compiler emits `/*! tailwindcss v4.3.3 | MIT License | https://tailwindcss.com */`
	// and it survives the build, so the audited probe's `hits == 0` was an artefact of
	// its marker set (none of its four patterns match that banner).
	banner := false
	for f, ms := range real {
		if filepath.Ext(f) == ".css" && len(ms) > 0 {
			banner = true
		}
	}
	if !banner {
		t.Errorf("the CSS bundle no longer carries the tailwindcss banner; SUP-1's \"no licence text \" " +
			"claim would then be literally true and this verifier's correction is stale")
	}
	for f, ms := range real {
		for _, m := range ms {
			if strings.EqualFold(m, "copyright") || strings.EqualFold(m, "@license") {
				t.Errorf("%s carries %q, which contradicts SUP-1's \"no copyright notice at all\"", f, m)
			}
		}
	}

	// --- the substance: third-party runtime is in the bytes; NOTICE names no npm. ---
	var svelteFiles, kitFiles int
	err := filepath.Walk(dist, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".js" {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		body := string(b)
		if strings.Contains(body, "__svelte") {
			svelteFiles++
		}
		if strings.Contains(body, "__sveltekit") {
			kitFiles++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if svelteFiles == 0 && kitFiles == 0 {
		t.Fatalf("no Svelte/SvelteKit runtime marker in the bundle; the redistribution claim below "+
			"would be unchecked (scanned %d files)", scannedFiles)
	}
	notice := strings.ToLower(mustRead(t, root, "NOTICE"))
	for _, pkg := range []string{"svelte", "@sveltejs", "devalue", "tailwind"} {
		if strings.Contains(notice, pkg) {
			t.Errorf("NOTICE now mentions %q; SUP-1's \"NOTICE lists Go modules only\" is stale", pkg)
		}
	}
	t.Logf("bundle ships Svelte markers in %d file(s), SvelteKit markers in %d file(s); "+
		"NOTICE mentions none of svelte/@sveltejs/devalue/tailwind", svelteFiles, kitFiles)
}

// TestVerifyNoUpstreamLegalCommentToPreserve tests SUP-1's remedy 2 on its own terms.
// The remedy is "turn on legal-comment preservation and add a non-vacuity assertion";
// if the third-party code the bundle is built from carries no legal comment at all,
// that build option preserves nothing and the assertion it is paired with can never
// fire — a silent no-op of exactly the kind the remedy was meant to prevent.
func TestVerifyNoUpstreamLegalCommentToPreserve(t *testing.T) {
	root := repoRoot(t)
	legal := regexp.MustCompile(`@license|@preserve|SPDX-License-Identifier|(?i)copyright|/\*!`)
	var files, withComment int
	for _, pkg := range []string{"svelte", "@sveltejs/kit", "devalue"} {
		dir := filepath.Join(root, "web", "node_modules", filepath.FromSlash(pkg))
		if _, err := os.Stat(dir); err != nil {
			t.Skipf("web/node_modules/%s is not installed; run `pnpm install` in web/", pkg)
		}
		// pnpm installs packages as symlinks into node_modules/.pnpm, and
		// filepath.Walk does not follow a symlinked root — resolving it first is what
		// makes this walk read the package instead of one symlink entry.
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			dir = resolved
		}
		// pnpm installs packages as symlinks into node_modules/.pnpm, and
		// filepath.Walk does not follow them (it lstats), so this walk has to resolve
		// symlinks itself — otherwise it reads one symlink entry and reports "nothing to
		// preserve" from a directory it never entered.
		err := walkJS(dir, func(path string, b []byte) {
			files++
			if legal.Match(b) {
				withComment++
				t.Logf("  carries a legal comment: %s", strings.TrimPrefix(path, root))
			}
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if files < 300 {
		t.Fatalf("only %d JS files were read out of the three runtime packages; that is too few for "+
			"\"there is nothing to preserve\" to be a finding rather than a broken walk", files)
	}
	if withComment > 0 {
		t.Errorf("%d of %d upstream JS files carry a legal comment, so legal-comment preservation in "+
			"the bundler WOULD have something to preserve — SUP-1's remedy 2 is not a no-op after all",
			withComment, files)
	}
	t.Logf("%d JS files read from svelte, @sveltejs/kit and devalue; 0 carry a licence comment, so no "+
		"bundler option can put attribution into the bundle: it has to be shipped alongside it", files)
}

// TestVerifyUsesSitesArePinnedButUnguarded re-derives SUP-3 from scratch: the real
// number of `uses:` keys (the audited report says 43), whether every remote ref is a
// full SHA, and whether anything in the repository would fail if one of them were not.
func TestVerifyUsesSitesArePinnedButUnguarded(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Anchored at line start and comment-free: `uses:` inside a `#` comment is text,
	// not a step, and counting it would inflate the audit's evidence table.
	key := regexp.MustCompile(`(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)`)
	sha := regexp.MustCompile(`@[0-9a-f]{40}$`)

	remote, local, unpinned := 0, 0, []string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		for _, m := range key.FindAllStringSubmatch(string(mustRead(t, dir, e.Name())), -1) {
			ref := m[1]
			if strings.HasPrefix(ref, "./") {
				local++
				continue
			}
			remote++
			if !sha.MatchString(ref) {
				unpinned = append(unpinned, e.Name()+": "+ref)
			}
		}
	}
	t.Logf("real `uses:` keys: %d remote + %d local = %d (the audited report's evidence says 43)",
		remote, local, remote+local)
	if remote < 40 {
		t.Fatalf("only %d remote refs parsed; the floor is what makes the pinning claim below "+
			"non-vacuous", remote)
	}
	if len(unpinned) > 0 {
		t.Errorf("a live supply-chain finding the audit did not have: %v", unpinned)
	}
	if remote == 43 {
		t.Errorf("the audited report's count of 43 is confirmed exactly; this note is stale")
	}

	// Is there a guard? The doc claims `internal/archtest` holds every pin. It holds
	// the base-image half and nothing else.
	dockerfileTest := mustRead(t, root, "internal", "archtest", "dockerfile_test.go")
	if !strings.Contains(dockerfileTest, "digestPinnedFROM") {
		t.Errorf("internal/archtest no longer guards base-image digests; re-read what the doc's " +
			"`internal/archtest` sentence still covers")
	}
	arch, err := os.ReadDir(filepath.Join(root, "internal", "archtest"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range arch {
		if !strings.HasSuffix(f.Name(), ".go") {
			continue
		}
		body := mustRead(t, root, "internal", "archtest", f.Name())
		if regexp.MustCompile(`uses:\s*\(|shaPin|pinnedToASHA|usesRef`).MatchString(body) {
			t.Errorf("internal/archtest/%s now parses `uses:` refs; SUP-3's \"no guard exists\" "+
				"is refuted", f.Name())
		}
	}
}

// TestVerifyWhichRenamesShipSilently is SUP-4's consequence, tested rather than
// argued: the recipe gap is real (the compiled-in reproduction of the loop exits 0
// with the archive missing every file), but which of the five names can be renamed
// without a tracked test noticing is a separate question, and the audited report
// picked the one name that cannot.
func TestVerifyWhichRenamesShipSilently(t *testing.T) {
	root := repoRoot(t)
	files := []string{"LICENSE", "NOTICE", "README.md", "SECURITY.md", "re0auth.example.toml"}

	// Every tracked Go file (tests included) is a potential guard, because a rename
	// trips the one that reads the file.
	var readers map[string][]string
	readers = map[string][]string{}
	for _, rel := range []string{filepath.Join("internal", "archtest"), filepath.Join("cmd", "re0auth")} {
		dir := filepath.Join(root, rel)
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			body := mustRead(t, path)
			for _, f := range files {
				// Only a quoted literal in a test counts. The filename also appears in
				// prose ("licensed by LICENSE", "see README.md"), and a comment cannot
				// fail when the file is renamed.
				if strings.Contains(body, `"`+f+`"`) {
					short, _ := filepath.Rel(root, path)
					readers[f] = append(readers[f], short)
				}
			}
			return nil
		})
	}
	silent := []string{}
	for _, f := range files {
		// A tracked test is what makes a rename loud in CI; an audit probe under
		// internal/zzprobe is deleted after the audit and guards nothing.
		tracked := []string{}
		for _, r := range readers[f] {
			if !strings.Contains(r, "zzprobe") {
				tracked = append(tracked, r)
			}
		}
		if len(tracked) == 0 {
			silent = append(silent, f)
		}
		t.Logf("%-22s read by tracked code: %v (audit-only readers: %d)",
			f, tracked, len(readers[f])-len(tracked))
	}
	if len(silent) == 0 {
		t.Errorf("every one of the five files is read by tracked code, so SUP-4's silent-ship " +
			"consequence is unreachable and should be downgraded further")
	}
	t.Logf("renaming these ships an incomplete archive with a green pipeline: %v", silent)

	// And the structural half: nothing downstream lists archive contents.
	makefile := mustRead(t, root, "Makefile")
	recipe := makefileRecipe(makefile, "dist")
	if regexp.MustCompile(`(?m)set -e`).MatchString(recipe) {
		t.Errorf("the dist recipe now sets -e, so a failing cp does fail the recipe")
	}
	if !regexp.MustCompile(`cp [^\n]*"dist/\$\$name/";`).MatchString(recipe) {
		t.Log("the unguarded cp line has changed shape; re-read the recipe before trusting this test")
	}
	for _, f := range []string{"Makefile", filepath.Join(".github", "workflows", "release.yml")} {
		body := mustRead(t, append([]string{root}, strings.Split(f, string(filepath.Separator))...)...)
		if regexp.MustCompile(`tar -t|unzip -l|tar -tz|zipinfo`).MatchString(body) {
			t.Errorf("%s now inspects archive contents, so a missing file is no longer silent", f)
		}
	}
}

// walkJS reads every .js/.mjs/.cjs file under dir, following symlinked directories
// (pnpm's node_modules is made of them) and refusing to loop.
func walkJS(dir string, visit func(path string, body []byte)) error {
	var rec func(string, int) error
	rec = func(d string, depth int) error {
		if depth > 16 {
			return nil
		}
		entries, err := os.ReadDir(d)
		if err != nil {
			return nil
		}
		for _, e := range entries {
			path := filepath.Join(d, e.Name())
			info, err := os.Stat(path) // Stat, not Lstat: follow the symlink.
			if err != nil {
				continue
			}
			if info.IsDir() {
				if err := rec(path, depth+1); err != nil {
					return err
				}
				continue
			}
			switch filepath.Ext(path) {
			case ".js", ".mjs", ".cjs":
			default:
				continue
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			visit(path, b)
		}
		return nil
	}
	return rec(dir, 0)
}

func makefileRecipe(makefile, target string) string {
	var b strings.Builder
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
		if line[0] != '\t' && line[0] != ' ' {
			break
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// TestVerifySBOMFlagIsAbsentAndItsGuardIsCoarse checks SUP-7's substance: the flag
// that would put licences in the SBOM is not passed anywhere, and the only integrity
// check on the SBOM tolerates the loss of 31 of today's 42 components.
func TestVerifySBOMFlagIsAbsentAndItsGuardIsCoarse(t *testing.T) {
	root := repoRoot(t)
	for _, f := range []string{"Makefile", filepath.Join(".github", "workflows", "ci.yml")} {
		body := mustRead(t, append([]string{root}, strings.Split(f, string(filepath.Separator))...)...)
		if strings.Contains(body, "-licenses") || strings.Contains(body, "-assert-licenses") {
			t.Errorf("%s now passes the licence flags; SUP-7's \"SBOM carries no licences\" is refuted", f)
		}
		if strings.Contains(body, "cyclonedx-gomod mod") {
			for _, line := range strings.Split(body, "\n") {
				if strings.Contains(line, "cyclonedx-gomod mod") {
					t.Logf("%s: %s", filepath.Base(f), strings.TrimSpace(line))
				}
			}
		}
	}
	ci := mustRead(t, root, ".github", "workflows", "ci.yml")
	if !strings.Contains(ci, `test "$components" -gt 10`) {
		t.Errorf("the SBOM component floor is no longer `-gt 10`; re-read what it tolerates")
	} else {
		t.Log("the SBOM's only integrity check is `components > 10`; a 31-component loss passes it " +
			"silently, and it says nothing about licences")
	}
}
