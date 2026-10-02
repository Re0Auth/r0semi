package postgres

// device_deny_subject_guard_test.go is the database-free half of Z20V-1=A.
//
// Z20V-1: the Postgres denial recorded `subject: ""`, so the production audit
// chain could not answer "who refused" (the memory backend had the same gap).
// DenyDevice must take the denying account from its caller and record it. The live
// rows are asserted by the CI integration test; this guard pins the signature and
// the record call so a regression fails without a database.

import (
	"strings"
	"testing"
)

func TestDenyDeviceTakesAndRecordsTheSubject(t *testing.T) {
	body := sourceOf(t, "oidc.go")
	deny := oidcStoreMethod(t, body, "DenyDevice")

	if !strings.Contains(deny, "subject string") {
		t.Error("DenyDevice does not take the denying subject; the event can only record an empty one (Z20V-1)")
	}
	if strings.Contains(deny, `s.record(ctx, "oidc.device.deny", "",`) {
		t.Error("DenyDevice still records an empty subject (Z20V-1)")
	}
	if !strings.Contains(deny, `s.record(ctx, "oidc.device.deny", subject,`) {
		t.Error("DenyDevice does not pass the subject into the denial event")
	}
	if !strings.Contains(deny, "RETURNING client_id") {
		t.Error("DenyDevice lost the client_id out of the write (G-17 regression)")
	}

	// The entrance must forward its authenticated subject into the denial, not a
	// literal: the interactive route is the only caller that holds it.
	decide := oidcStoreMethod(t, body, "DecideDeviceAuthorization")
	if !strings.Contains(decide, "s.DenyDevice(ctx, userCode, subject)") {
		t.Error("DecideDeviceAuthorization does not forward the subject into DenyDevice; the denial " +
			"would record an empty account again (Z20V-1)")
	}
}
