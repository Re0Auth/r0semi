package main

import (
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/vault"
)

// A rotation run's counts cannot express the one thing that matters before the
// retired key is deleted: whether anything was left behind. Two ways it can be:
// a record the run refused to re-wrap (its row changed under it), and a record
// written afterwards by a process still configured with the retired key — which no
// run can see. The second is why the re-run instruction is unconditional.
func TestRotationReport(t *testing.T) {
	t.Run("a clean run still tells the operator the re-run gate", func(t *testing.T) {
		lines, incomplete := rotationReport(vault.Rotation{Scanned: 3, Rewrapped: 2, AlreadyCurrent: 1})
		if incomplete {
			t.Fatalf("a run that re-wrapped or verified everything is not incomplete: %v", lines)
		}
		joined := strings.Join(lines, "\n")
		if !strings.Contains(joined, "rewrapped=0 skipped=0") {
			t.Errorf("the report does not name the gate the operator must pass before removing the key:\n%s", joined)
		}
		if !strings.Contains(joined, "still configured with the retired key") {
			t.Errorf("the report does not explain what a rotation cannot see:\n%s", joined)
		}
	})

	t.Run("a run that left a record behind is not a success", func(t *testing.T) {
		lines, incomplete := rotationReport(vault.Rotation{Scanned: 3, Rewrapped: 1, AlreadyCurrent: 1, Skipped: 1})
		if !incomplete {
			t.Fatal("a run with a skipped record was reported as complete")
		}
		last := lines[len(lines)-1]
		if !strings.Contains(last, "Do NOT remove the retired key") {
			t.Errorf("the failure line does not say what not to do: %q", last)
		}
		if !strings.Contains(last, "1 of 3") {
			t.Errorf("the failure line does not name the counts: %q", last)
		}
		if !strings.Contains(last, "rewrapped=0 skipped=0") {
			t.Errorf("the failure line does not name the gate: %q", last)
		}
	})

	t.Run("nothing to rotate is called out", func(t *testing.T) {
		lines, incomplete := rotationReport(vault.Rotation{})
		if incomplete {
			t.Fatal("an empty vault is not an incomplete rotation")
		}
		if !strings.Contains(strings.Join(lines, "\n"), "nothing to rotate") {
			t.Errorf("an empty run does not warn that the storage may be the wrong one: %v", lines)
		}
	})
}
