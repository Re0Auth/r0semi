//go:build audit6

package z05memstore

// Falsification probe for finding 05-3 (the Postgres device-decision audit
// events record an empty client_id, while the memory backend records the
// client). The Postgres runtime half is unreachable here (no database), so
// this attacks the shipped source with controls on both sides of the claimed
// drift. Red today = the finding stands at the source level.

import (
	"regexp"
	"strings"
	"testing"
)

// rev3RecordCall extracts the s.record(...)/s.recordConsent(...) call for a
// device decision from a method body and returns the audit action and its
// client-id argument.
func rev3RecordCall(t *testing.T, body, method string) (action, clientArg string) {
	t.Helper()
	re := regexp.MustCompile(`s\.record(?:Consent)?\(\s*ctx,\s*"(oidc\.device\.[a-z]+)"\s*,\s*([^,]*?)\s*,\s*([^,]*?)\s*,`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("%s: no device-decision audit record call found; the probe is not reading the method", method)
	}
	return m[1], m[3]
}

func TestRev3PostgresDeviceDecisionsCarryTheirClientID(t *testing.T) {
	code := revStripComments(revRead(t, "internal/store/postgres/oidc.go"))

	// Z20V-2 de-exported the approval implementation (ApproveDevice ->
	// approveDevice); DenyDevice stays exported but now takes the denying subject.
	for _, method := range []string{"approveDevice", "DenyDevice"} {
		action, clientArg := rev3RecordCall(t, revMethodBody(t, code, method), method)
		if clientArg == `""` || clientArg == "" {
			t.Errorf("finding 05-3 stands: the Postgres %s records audit event %q with an empty client_id — the "+
				"production audit chain cannot attribute a device decision to the client it authorised", method, action)
		}
	}

	// Controls, so a missing string cannot pass vacuously:
	// (a) the memory twin records the client on the same two events — the
	// direction of the drift.
	mem := revStripComments(revRead(t, "internal/store/memory/oidc.go"))
	for _, method := range []string{"approveDevice", "DenyDevice"} {
		_, clientArg := rev3RecordCall(t, revMethodBody(t, mem, method), method)
		if !strings.Contains(clientArg, "clientID") {
			t.Fatalf("control broken: the memory %s no longer records a client id (%q); the drift claim has no reference",
				method, clientArg)
		}
	}
	// (b) the same Postgres file already attributes clients elsewhere
	// (clientIDOfRequest, used by CompleteLogin's consent event), so the
	// empty string is an omission, not a policy.
	if !strings.Contains(code, "clientIDOfRequest") {
		t.Fatal("control broken: the Postgres adapter no longer contains the clientIDOfRequest attribution pattern")
	}
}
