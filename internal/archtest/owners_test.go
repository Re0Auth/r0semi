package archtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCodeownersRoutesEveryPath: GitHub does not fail on a CODEOWNERS typo. It
// stops requesting the review and says nothing, so the one mechanism that puts a
// change in front of the person who should see it disappears without a red mark
// anywhere — the same failure shape as a metric nobody declared, which is why the
// shape is checkable here.
func TestCodeownersRoutesEveryPath(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, ".github", "CODEOWNERS"))
	if err != nil {
		t.Fatalf("read .github/CODEOWNERS: %v", err)
	}

	var (
		rules    int
		catchAll bool
	)
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			t.Errorf("CODEOWNERS:%d has a pattern with no owner: %q", i+1, line)
			continue
		}
		rules++
		if fields[0] == "*" {
			catchAll = true
		}
		for _, owner := range fields[1:] {
			switch {
			case strings.HasPrefix(owner, "@") && len(owner) > 1:
				// A user, or an org/team.
			case strings.Contains(owner, "@") && !strings.HasPrefix(owner, "@"):
				// An email address owner.
			default:
				t.Errorf("CODEOWNERS:%d owner %q is neither @user, @org/team, nor an email: "+
					"GitHub would ignore the rule and request no review", i+1, owner)
			}
		}
	}
	if rules == 0 {
		t.Fatal("CODEOWNERS has no rules")
	}
	if !catchAll {
		t.Error("CODEOWNERS has no `*` rule, so a path added tomorrow is owned by nobody")
	}
}
