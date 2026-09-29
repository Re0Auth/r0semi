//go:build audit7

// Re-check of Z10-4, Z10-5 and the audit-detail gap this round found: every claim
// here is read out of the source text, so a wrong claim fails a test.
package z10verify

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestZ10VerifyKillSwitchReportHasNoSessionUnavailableMarker confirms Z10-4's
// mechanism and its asymmetry: bindings carry an "unavailable" marker, sessions
// do not.
func TestZ10VerifyKillSwitchReportHasNoSessionUnavailableMarker(t *testing.T) {
	const file = "internal/admin/admin.go"
	raw := repoFile(t, file)

	if !regexp.MustCompile(`(?m)\bBindingsUnavailable\s+bool`).MatchString(raw) {
		t.Fatalf("admin.Report no longer declares BindingsUnavailable; the asymmetry Z10-4 rests on is gone")
	}
	if regexp.MustCompile(`\bSessionsUnavailable\b`).MatchString(raw) {
		t.Errorf("admin.Report now has a SessionsUnavailable marker: Z10-4 is fixed and its verdict must change")
	}
	if strings.Contains(raw, "sessions_unavailable") {
		t.Errorf("the kill switch now emits sessions_unavailable: Z10-4 is fixed")
	}

	// The sessions half is skipped entirely when the port is absent, with no
	// else-branch that records the absence.
	kill := scrubLiterals(t, file, funcBody(t, file, "KillSwitch"))
	if !strings.Contains(kill, "s.sessions != nil &&") {
		t.Fatalf("KillSwitch no longer guards the session sweep on a non-nil port; Z10-4's premise changed")
	}
	if !strings.Contains(kill, "rep.SessionsRevoked = n") {
		t.Errorf("KillSwitch no longer assigns rep.SessionsRevoked; the marker question changed")
	}
	if strings.Contains(kill, "SessionsUnavailable = true") {
		t.Errorf("KillSwitch now sets a sessions-unavailable marker: Z10-4 is fixed")
	}

	// The bindings half says so explicitly, in the same function, which is the
	// control: the report format can express the distinction.
	if !strings.Contains(kill, "rep.BindingsUnavailable = true") {
		t.Errorf("KillSwitch no longer marks bindings as unavailable; the control for Z10-4's asymmetry is gone")
	}

	// And killDetail does not carry the marker either.
	detailRaw := funcBodyRaw(t, file, "killDetail")
	if !strings.Contains(detailRaw, `"sessions_revoked"`) {
		t.Errorf("killDetail no longer records sessions_revoked; re-derive Z10-4")
	}
	if strings.Contains(detailRaw, "sessions_unavailable") {
		t.Errorf("killDetail now records sessions_unavailable: Z10-4 is fixed")
	}
}

// TestZ10VerifyKillSwitchDropsThePartialSummaryInTheHTTPLayer re-derives Z10-5
// from both ends: admin.KillSwitch returns (report, err) with the counts it
// already cut, and the HTTP handler writes only a problem body on the error
// branch.
func TestZ10VerifyKillSwitchDropsThePartialSummaryInTheHTTPLayer(t *testing.T) {
	// Service end: every error return hands back `rep` alongside the error.
	kill := scrubLiterals(t, "internal/admin/admin.go", funcBody(t, "internal/admin/admin.go", "KillSwitch"))
	if n := strings.Count(kill, "return rep, err"); n < 3 {
		t.Fatalf("admin.KillSwitch returns (rep, err) on only %d paths; the promise Z10-5 tests is gone", n)
	}
	for _, frag := range []string{"return rep, ErrInvalidTarget", "return rep, ErrBindingsUnavailable"} {
		if !strings.Contains(kill, frag) {
			t.Errorf("admin.KillSwitch no longer has %q; its error contract changed", frag)
		}
	}
	if !strings.Contains(kill, "rep.TokensRevoked = removed") {
		t.Errorf("the report no longer carries tokens_revoked; Z10-5's premise changed")
	}
	if !strings.Contains(kill, "rep.SessionsRevoked = n") {
		t.Errorf("the report no longer carries sessions_revoked; Z10-5's premise changed")
	}

	// HTTP end: the error branch discards the report.
	const routes = "internal/httpapi/admin_routes.go"
	handler := scrubLiterals(t, routes, funcBody(t, routes, "handleAdminKillSwitch"))
	if !strings.Contains(handler, "report, err := s.adminSvc.KillSwitch(") {
		t.Fatalf("the handler no longer receives the report; re-derive Z10-5")
	}
	errBranch := regexp.MustCompile(`(?s)case err != nil:(.*?)writeProblem`).FindStringSubmatch(handler)
	if errBranch == nil {
		t.Fatalf("the handler's generic error branch changed shape; re-derive Z10-5")
	}
	if strings.Contains(errBranch[1], "report") {
		t.Errorf("the handler's error branch now uses the report — Z10-5 may be fixed and its verdict must change")
	}
	if !strings.Contains(handler, "writeJSON(w, http.StatusOK, report)") {
		t.Errorf("the success branch no longer writes the report; the asymmetry Z10-5 rests on is gone")
	}
}

// TestZ10VerifyKillSwitchAuditDetailCarriesNoSessionsCount is the new finding of
// this re-check, stated as a probe that goes red if it is ever fixed: no
// kill-switch failure path records how many sessions were already cut, while the
// success path's killDetail does. The zone-10 report asserts the opposite — that
// the audit row carries `sessions_revoked` — and its own probe only ever
// asserted `tokens_revoked`.
func TestZ10VerifyKillSwitchAuditDetailCarriesNoSessionsCount(t *testing.T) {
	const file = "internal/admin/admin.go"
	raw := repoFile(t, file)

	re := regexp.MustCompile(`(?s)map\[string\]string\{([^}]*)\}\)`)
	var calls [][2]string
	for _, m := range re.FindAllStringSubmatchIndex(raw, -1) {
		before := raw[:m[0]]
		idx := strings.LastIndex(before, "s.record(")
		if idx < 0 {
			continue
		}
		callHead := before[idx:]
		if !strings.Contains(callHead, `"admin.`+"kill_switch"+`"`) {
			continue
		}
		calls = append(calls, [2]string{callHead, raw[m[2]:m[3]]})
	}
	if len(calls) != 3 {
		t.Fatalf("found %d kill-switch record call sites with an inline Detail literal, want 3 "+
			"(the failure paths of KillSwitch): the probe is reading the wrong source", len(calls))
	}

	// The success path goes through killDetail, which does carry it.
	detailRaw := funcBodyRaw(t, file, "killDetail")
	if !strings.Contains(detailRaw, `"sessions_revoked"`) {
		t.Fatalf("killDetail no longer carries sessions_revoked; the asymmetry this finding rests on is gone")
	}

	// None of the inline Detail literals on the failure paths carry it.
	for _, c := range calls {
		head, body := c[0], c[1]
		if strings.Contains(head, "killDetail") {
			continue // the success path, already checked
		}
		if strings.Contains(body, "sessions_revoked") {
			t.Errorf("a kill-switch failure path now records sessions_revoked in Detail: the finding is fixed. Detail: %s",
				strings.Join(strings.Fields(body), " "))
		}
		if !strings.Contains(body, "tokens_revoked") {
			t.Errorf("a kill-switch failure path no longer records tokens_revoked at all; re-derive the finding. Detail: %s",
				strings.Join(strings.Fields(body), " "))
		}
	}
}

// TestZ10VerifyShutdownStackStillExceedsThePodGracePeriod independently parses
// the four real numbers and agrees with the zone-10 report's arithmetic — while
// also showing that round 6's finding G-12 named exactly this stack, so the
// report's "rebuttal of a fix" framing is wrong.
func TestZ10VerifyShutdownStackStillExceedsThePodGracePeriod(t *testing.T) {
	removal := secondsNamed(t, "cmd/re0auth/main.go", "endpointRemovalWait")
	shutdown := secondsNamed(t, "cmd/re0auth/main.go", "shutdownTimeout")
	drain := secondsNamed(t, "internal/store/postgres/auditbatch.go", "auditDrainTimeout")

	deploy := repoFile(t, "deploy/k8s/base/deployment.yaml")
	m := regexp.MustCompile(`(?m)^\s*terminationGracePeriodSeconds:\s*(\d+)\s*$`).FindStringSubmatch(deploy)
	if m == nil {
		t.Fatalf("no terminationGracePeriodSeconds in the manifest")
	}
	grace, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	total := removal + shutdown + drain
	t.Logf("independently parsed: %d + %d + %d = %d vs grace %d", removal, shutdown, drain, total, grace)
	if total <= grace {
		t.Errorf("the stack now fits (%ds <= %ds): the finding is fixed and its verdict must change", total, grace)
	}

	// The manifest comment still counts only the first two terms, and the
	// CHANGELOG still advises a grace that only covers them.
	if !strings.Contains(deploy, "35s") {
		t.Errorf("the manifest no longer claims a 35s budget; the comment half of the finding changed")
	}
	cl := repoFile(t, "CHANGELOG.md")
	if !strings.Contains(cl, "terminationGracePeriodSeconds ≥ 35s") {
		t.Errorf("the CHANGELOG no longer advises a 35s grace; the doc half of the finding changed")
	}

	// G-12 of round 6 recorded the same numbers, so this is a re-report.
	round6 := repoFile(t, "scratchpad/audit6/findings/00-LAUNCH-READINESS-CONSOLIDATED.md")
	if !strings.Contains(round6, "5s + 30s + 30s = 65s") || !strings.Contains(round6, "G-12") {
		t.Errorf("round 6 does not contain the G-12 entry this probe found; the re-report judgement must be re-checked")
	}
}

// secondsNamed extracts `name = <N> * time.Second` from a repository file.
func secondsNamed(t *testing.T, rel, name string) int {
	t.Helper()
	re := regexp.MustCompile(`(?m)\b` + regexp.QuoteMeta(name) + `\s*=\s*(\d+)\s*\*\s*time\.Second`)
	m := re.FindStringSubmatch(repoFile(t, rel))
	if m == nil {
		t.Fatalf("%s no longer declares %s = <N> * time.Second; this probe would be vacuous", rel, name)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	return n
}
