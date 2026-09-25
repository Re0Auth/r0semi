package archtest

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// digestPinnedFROM matches a FROM line whose image reference carries a digest.
var digestPinnedFROM = regexp.MustCompile(`(?m)^FROM\s+\S+@sha256:[0-9a-f]{64}(?:\s+AS\s+\S+)?\s*$`)

// repoRoot is the module root: tests in this package run from internal/archtest.
func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Clean(filepath.Join(wd, "..", "..")), nil
}

// TestDockerfileBaseImagesArePinned: a tag can move under a build, so every base
// image except `scratch` must be referenced by digest. This is what makes "the
// same Dockerfile" mean the same toolchain, and it is cheap to enforce here rather
// than in a scanner that only runs on tags.
func TestDockerfileBaseImagesArePinned(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)

	var froms []string
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "FROM ") {
			froms = append(froms, strings.TrimSpace(line))
		}
	}
	if len(froms) < 3 {
		t.Fatalf("Dockerfile has %d FROM lines, want at least 3: %v", len(froms), froms)
	}
	for _, line := range froms {
		if strings.Contains(line, "scratch") {
			continue
		}
		if !digestPinnedFROM.MatchString(line) {
			t.Fatalf("base image is not digest-pinned: %s", line)
		}
	}
	// The runtime stage is scratch, which has no base to pin; anything else means
	// a base image came back without saying so.
	if !strings.Contains(text, "FROM scratch") {
		t.Fatal("the runtime stage is not FROM scratch")
	}
	if !strings.Contains(text, "USER 65532:65532") {
		t.Fatal("the runtime stage does not run as the nonroot uid")
	}
}
