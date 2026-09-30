package archtest

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestGolangciGosecHasNoIncludeAllowlist keeps the security linter default-on.
//
// `.golangci.yml` once curated gosec through `gosec.includes`. In golangci-lint
// v2 that key is applied as `rules.NewRuleFilter(false, includes...)` — an
// allowlist — so naming five rules switched every other gosec rule off, and
// G112/G114/G115 were installed, configured and inert. This untagged check is
// the cheap guard that keeps the allowlist from coming back silently; the probe
// in internal/zzprobe/audit7/z16guardtestquality carries the dynamic half
// (gosec's own findings against the config).
//
// The same family of failure is a gosec `linters.exclusions.rules` entry with no
// `text`: that suppresses every gosec rule on a path, which is an allowlist by
// another route, so it fails here too.
func TestGolangciGosecHasNoIncludeAllowlist(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, ".golangci.yml"))
	if err != nil {
		t.Fatalf("read .golangci.yml: %v", err)
	}
	var cfg struct {
		Linters struct {
			Enable   []string `yaml:"enable"`
			Settings struct {
				Gosec struct {
					Includes []string `yaml:"includes"`
				} `yaml:"gosec"`
			} `yaml:"settings"`
			Exclusions struct {
				Rules []struct {
					Path    string   `yaml:"path"`
					Linters []string `yaml:"linters"`
					Text    string   `yaml:"text"`
				} `yaml:"rules"`
			} `yaml:"exclusions"`
		} `yaml:"linters"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse .golangci.yml: %v", err)
	}
	// The positive control: the file must still say what this check is reading,
	// or a future reshuffle of `linters.enable` would make it pass vacuously.
	if !slices.Contains(cfg.Linters.Enable, "gosec") {
		t.Fatal(".golangci.yml no longer enables gosec; this check is not reading the gate it guards")
	}
	if includes := cfg.Linters.Settings.Gosec.Includes; len(includes) > 0 {
		t.Errorf("gosec.includes = %v is non-empty (Z16-2, docs/issues/P2-medium.md). In golangci-lint v2 "+
			"it is an allowlist — rules.NewRuleFilter(false, includes...) — so every rule not named never "+
			"runs. Decline a finding by naming it in gosec.excludes with a reason instead.", includes)
	}
	for _, rule := range cfg.Linters.Exclusions.Rules {
		if !slices.Contains(rule.Linters, "gosec") {
			continue
		}
		if strings.TrimSpace(rule.Text) == "" {
			t.Errorf("the gosec exclusion for path %q has no `text`: it hides every gosec rule on those "+
				"files rather than a named one. Name the rule in gosec.excludes, or give the entry a `text`.", rule.Path)
		}
	}
}
