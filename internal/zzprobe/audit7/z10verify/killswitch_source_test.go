//go:build audit7

// Regression guards for Z10-4, Z10-5, Z10V-1, Z10-3/G-12 and Z10V-2.
//
// These probes were written while the findings were open and asserted the
// pre-fix shape. The fixes have since landed, so each guard now asserts the
// fixed behaviour: reverting the fix turns it red. Every guard carries a
// negative control that feeds the pre-fix source shape to the same predicate —
// "the fixed text is present" is only worth something if the predicate can also
// say "the old shape is absent".
package z10verify

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestZ10VerifyKillSwitchReportCarriesTheSessionUnavailableMarker is the flipped
// form of Z10-4. The pre-fix asymmetry was: bindings carried an "unavailable"
// marker, sessions did not, so `sessions_revoked: 0` could not be told apart
// from "this deployment cannot sign anyone out". The guard pins the fixed
// symmetry.
func TestZ10VerifyKillSwitchReportCarriesTheSessionUnavailableMarker(t *testing.T) {
	const file = "internal/admin/admin.go"
	raw := repoFile(t, file)

	if !sessionUnavailableMarkerPresent(raw) {
		t.Fatalf("admin no longer carries both the SessionsUnavailable field and the sessions_unavailable " +
			"wire key: Z10-4's fix has been reverted")
	}
	if !regexp.MustCompile(`(?m)\bSessionsUnavailable\s+bool`).MatchString(raw) {
		t.Errorf("admin.Report no longer declares SessionsUnavailable bool; the marker Z10-4 added is gone")
	}
	if !strings.Contains(raw, `json:"sessions_unavailable,omitempty"`) {
		t.Errorf("SessionsUnavailable no longer serialises as sessions_unavailable; the responder-visible " +
			"marker Z10-4 added is gone")
	}
	if !regexp.MustCompile(`(?m)\bBindingsUnavailable\s+bool`).MatchString(raw) {
		t.Errorf("admin.Report no longer declares BindingsUnavailable bool; the control the symmetry rests on is gone")
	}

	// The marker is set when the target has a session dimension and there is no
	// revoker, and only then: a wired deployment must still report the number.
	kill := funcBody(t, file, "KillSwitch")
	if !strings.Contains(kill, "rep.SessionsUnavailable = true") {
		t.Errorf("KillSwitch no longer sets rep.SessionsUnavailable on the no-revoker branch; Z10-4's fix is gone")
	}
	if !strings.Contains(kill, "s.sessions != nil &&") {
		t.Fatalf("KillSwitch no longer guards the session sweep on a non-nil port; the probe reads the wrong branch")
	}
	if !strings.Contains(kill, "rep.SessionsRevoked = n") {
		t.Errorf("KillSwitch no longer assigns rep.SessionsRevoked on the wired branch; the marker's control is gone")
	}
	// And the durable row says so too, next to the count.
	detail := funcBodyRaw(t, file, "killDetail")
	if !strings.Contains(detail, `"sessions_revoked"`) {
		t.Errorf("killDetail no longer records sessions_revoked; re-derive Z10-4")
	}
	if !strings.Contains(detail, `"sessions_unavailable"`) {
		t.Errorf("killDetail no longer records sessions_unavailable; the audit row is silent again about a " +
			"deployment that cannot cut sessions")
	}

	// Anti-vacuity: the predicate above must reject the pre-fix Report, or a
	// revert would leave this test green.
	preFix := `type Report struct {
	BindingsUnavailable bool ` + "`json:\"bindings_unavailable,omitempty\"`" + `
}`
	if sessionUnavailableMarkerPresent(preFix) {
		t.Fatal("the predicate cannot see the pre-fix shape (no SessionsUnavailable / sessions_unavailable); " +
			"this guard would not fail on a revert and is vacuous")
	}
}

func sessionUnavailableMarkerPresent(src string) bool {
	return strings.Contains(src, "SessionsUnavailable") && strings.Contains(src, "sessions_unavailable")
}

// TestZ10VerifyKillSwitchAuditDetailCarriesEveryCountOnEveryPath is the flipped
// form of Z10V-1. The finding was that the failure rows carried only
// `tokens_revoked` in an inline Detail map while the success row went through
// killDetail, which carries `sessions_revoked` as well — so a failed sweep that
// had already cut sessions left a durable row that did not say so.
//
// The fix routes every path through recordKill → killDetail. The guard pins
// that: no inline Detail map in KillSwitch, and one shared Detail builder that
// carries every count and every "unavailable" marker.
func TestZ10VerifyKillSwitchAuditDetailCarriesEveryCountOnEveryPath(t *testing.T) {
	const file = "internal/admin/admin.go"

	kill := funcBody(t, file, "KillSwitch")
	if !killSwitchRecordsThroughKillDetail(kill) {
		t.Fatalf("KillSwitch no longer routes its audit rows through recordKill/killDetail: the partial-detail " +
			"failure Z10V-1 fixed can be reintroduced")
	}
	if n := strings.Count(kill, "s.recordKill("); n < 5 {
		t.Errorf("KillSwitch records through recordKill on only %d paths; want the success path and at least "+
			"four exit paths", n)
	}

	recordKill := funcBody(t, file, "recordKill")
	if !strings.Contains(recordKill, "killDetail(rep, target)") {
		t.Fatalf("recordKill no longer derives the Detail from killDetail; re-derive Z10V-1")
	}

	detail := funcBodyRaw(t, file, "killDetail")
	for _, key := range []string{
		`"tokens_revoked"`,
		`"sessions_revoked"`,
		`"client_id"`,
		`"bindings_unavailable"`,
		`"sessions_unavailable"`,
	} {
		if !strings.Contains(detail, key) {
			t.Errorf("killDetail no longer records %s; a durable kill-switch row is missing that fact again", key)
		}
	}

	// Anti-vacuity: the pre-fix KillSwitch built its failure Detail inline with
	// only tokens_revoked. The predicate must call that "not routed through
	// killDetail".
	preFix := `s.record(ctx, actor, "admin.kill_switch", "all", audit.OutcomeError,
		map[string]string{"tokens_revoked": strconv.Itoa(rep.TokensRevoked)})`
	if killSwitchRecordsThroughKillDetail(preFix) {
		t.Fatal("the predicate accepts an inline partial Detail map as if it went through killDetail; " +
			"this guard would not fail on a revert and is vacuous")
	}
}

// killSwitchRecordsThroughKillDetail reports whether a KillSwitch body derives
// its audit Detail from killDetail rather than building a partial map inline.
func killSwitchRecordsThroughKillDetail(killBody string) bool {
	return strings.Contains(killBody, "s.recordKill(") && !strings.Contains(killBody, "map[string]string{")
}

// TestZ10VerifyKillSwitchDropsThePartialSummaryInTheHTTPLayer is Z10-5, kept as
// it was: the finding is still open, and the source shape it reads is unchanged.
// It re-derives Z10-5 from both ends: admin.KillSwitch returns (report, err) with
// the counts it already cut, and the HTTP handler writes only a problem body on
// the error branch.
func TestZ10VerifyKillSwitchDropsThePartialSummaryInTheHTTPLayer(t *testing.T) {
	// Service end: every error return hands back `rep` alongside the error.
	kill := funcBody(t, "internal/admin/admin.go", "KillSwitch")
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
	handler := funcBody(t, routes, "handleAdminKillSwitch")
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

// TestZ10VerifyShutdownStackFitsThePodGracePeriod is the flipped form of Z10-3
// (a re-report of round 6's G-12). The stack was `5 + 30 + 30 = 65s` against a
// 45s grace period, with the manifest and the CHANGELOG counting only the first
// two terms. The fix cut auditDrainTimeout to 10s and taught the documentation
// the whole stack; the guard pins arithmetic and documentation together, so a
// partial revert fails here.
func TestZ10VerifyShutdownStackFitsThePodGracePeriod(t *testing.T) {
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
	if removal == 0 || shutdown == 0 || drain == 0 || grace == 0 {
		t.Fatalf("a parsed value is zero (%d/%d/%d/%d): the probe is not reading what it thinks",
			removal, shutdown, drain, grace)
	}
	total := removal + shutdown + drain
	t.Logf("independently parsed: %d + %d + %d = %d vs grace %d", removal, shutdown, drain, total, grace)

	if total > grace {
		t.Errorf("the shutdown stack needs %ds but the pod is SIGKILLed after %ds: the audit drain runs only "+
			"after the HTTP drain and is killed with rows still queued", total, grace)
	}

	// The documentation moved with the code, and this half is not optional: the
	// old comment's "35s total" was what made G-12 keep getting re-reported.
	if !strings.Contains(deploy, "5 + 30 + 10 = 45s") {
		t.Errorf("the manifest comment no longer counts the whole stack (5 + 30 + 10 = 45s); the budget it " +
			"documents and the budget the process spends have drifted apart again")
	}
	cl := repoFile(t, "CHANGELOG.md")
	if !strings.Contains(cl, "terminationGracePeriodSeconds ≥ 45s") {
		t.Errorf("the CHANGELOG no longer advises terminationGracePeriodSeconds ≥ 45s; the documented budget " +
			"no longer covers the whole stack")
	}
}

// TestZ10VerifyTheOperationalListenerIsClosedNotDrained is the flipped form of
// Z10V-2. The finding was that every endpoint shared one 30s drainCtx, so
// whichever listener went first could spend the whole budget and leave the
// other with an already-expired context. The fix marks the operational listener
// noDrain and closes it outright. The guard pins that the bypass exists, that it
// is the internal surface that gets it, and that it happens before Shutdown.
func TestZ10VerifyTheOperationalListenerIsClosedNotDrained(t *testing.T) {
	const file = "cmd/re0auth/main.go"
	raw := repoFile(t, file)

	if !regexp.MustCompile(`(?m)\bnoDrain\s+bool`).MatchString(raw) {
		t.Fatalf("the endpoint type no longer has a noDrain field; Z10V-2's fix has been reverted")
	}
	serve := funcBody(t, file, "serveUntilSignal")
	if !operationalListenerBypassesTheSharedDrain(serve) {
		t.Fatalf("serveUntilSignal no longer closes the noDrain endpoint instead of draining it from the " +
			"shared budget: Z10V-2's fix has been reverted")
	}

	// The endpoint that gets the bypass is the operational surface.
	internalAt := strings.Index(raw, "metrics.InternalHandler()")
	noDrainAt := strings.Index(raw, "noDrain: true")
	if internalAt < 0 || noDrainAt < 0 {
		t.Fatalf("the internal listener or its noDrain mark is gone (InternalHandler %d, noDrain %d); re-derive Z10V-2",
			internalAt, noDrainAt)
	}
	if noDrainAt < internalAt || noDrainAt > internalAt+400 {
		t.Errorf("noDrain is no longer set on the internal-listener endpoint (found at %d, InternalHandler at %d); "+
			"some other listener may now be closed without draining", noDrainAt, internalAt)
	}

	// Anti-vacuity: the pre-fix loop drained every endpoint from the shared
	// context. The predicate must reject it.
	preFix := `for _, ep := range endpoints {
		if e := ep.server.Shutdown(drainCtx); e != nil {
			_ = ep.server.Close()
		}
	}`
	if operationalListenerBypassesTheSharedDrain(preFix) {
		t.Fatal("the predicate accepts the pre-fix shared drain as if it bypassed it; this guard would not " +
			"fail on a revert and is vacuous")
	}
}

// operationalListenerBypassesTheSharedDrain reports whether a serveUntilSignal
// body closes the noDrain endpoint instead of handing it the shared deadline,
// and does so before the first Shutdown call.
func operationalListenerBypassesTheSharedDrain(serveBody string) bool {
	bypass := strings.Index(serveBody, "if ep.noDrain {")
	if bypass < 0 || !strings.Contains(serveBody[bypass:], "ep.server.Close()") {
		return false
	}
	shutdown := strings.Index(serveBody, "ep.server.Shutdown(drainCtx)")
	return shutdown < 0 || bypass < shutdown
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
