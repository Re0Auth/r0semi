//go:build audit7

// Zone-10 probe: can the audit records the round-5 fix added silently become
// no-ops?
package z10adminauditprivacy

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/oauth"
)

// stubIntrospector, stubGrants and stubDevices are the three required OP seams,
// none of which this probe reaches.
type stubIntrospector struct{}

func (stubIntrospector) Introspect(context.Context, string) (oauth.TokenInfo, error) {
	return oauth.TokenInfo{}, nil
}

type stubGrants struct{}

func (stubGrants) Grants(context.Context, string) ([]oauth.Grant, error) { return nil, nil }
func (stubGrants) RevokeGrant(context.Context, string, string) error     { return nil }

type stubDevices struct{}

func (stubDevices) DescribeDeviceAuthorization(context.Context, string) (oauth.DeviceAuthorization, error) {
	return oauth.DeviceAuthorization{}, nil
}

func (stubDevices) DecideDeviceAuthorization(context.Context, string, string, bool, []oauth.Scope, []oauth.Scope) error {
	return nil
}

// TestZ10TheAuditReadRecordsAreAcceptedWithNoSinkToWriteThem was the Z10-7
// finding, and is now its regression guard (the name is kept for the audit
// coverage matrix).
//
// The P2-22 fix has two halves: `admin.audit.read` in handleAdminAudit and
// `account.export` in handleExportAccount, both written through `s.auditLog` —
// an OPTIONAL field whose doc says "a nil logger records nothing", which the
// read-API validation did not require. httpapi.New enforced
// `Config.Audit requires Config.Sessions` and `requires a non-empty Config.Admins`
// out of the same worry (reading the log means reading about every account), but
// used to accept a read API with no write side: the records then never happened,
// in a configuration that looked correctly wired. The constructor now refuses
// that combination (Z10-7), and this probe asserts the refusal is caused by the
// missing sink.
func TestZ10TheAuditReadRecordsAreAcceptedWithNoSinkToWriteThem(t *testing.T) {
	base := func() httpapi.Config {
		manager := auth.NewManager(auth.Options{Secure: false})
		return httpapi.Config{
			Issuer:            probeIssuer,
			OIDC:              http.NotFoundHandler(),
			TokenIntrospector: stubIntrospector{},
			GrantStore:        stubGrants{},
			DeviceStore:       stubDevices{},
			Sessions:          manager,
			Accounts:          account.NewMemoryStore(),
			Admins:            []account.UserID{"usr_admin0000000000000000"},
			Audit:             &probeAuditReader{page: audit.Page{Limit: 10}},
			AuditLog:          nil,
		}
	}

	_, err := httpapi.New(base())
	if err == nil {
		t.Fatalf("httpapi.New accepted Config.Audit (the operator read API) with a nil Config.AuditLog. " +
			"recordAuditOutcome returns early on a nil logger, so GET /v1/admin/audit, /verify, /head and " +
			"GET /v1/account/export leave no record at all while the configuration looks complete — the exact " +
			"gap the P2-22 fix was added to close (Z10-7 regressed).")
	}
	if !strings.Contains(err.Error(), "Config.AuditLog") {
		t.Fatalf("httpapi.New refused the configuration for an unrelated reason (%v); this probe no longer "+
			"isolates Z10-7", err)
	}

	// Positive control: the same configuration WITH a sink is accepted, so the
	// refusal above is caused by the missing sink and not by the stubs.
	withSink := base()
	withSink.AuditLog = audit.NewMemoryLogger()
	if _, err := httpapi.New(withSink); err != nil {
		t.Fatalf("httpapi.New refused the same read API with an AuditLog: %v", err)
	}
}
