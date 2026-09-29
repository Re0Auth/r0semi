//go:build audit7

// Zone-10 probe: can the audit records the round-5 fix added silently become
// no-ops?
package z10adminauditprivacy

import (
	"context"
	"net/http"
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

// TestZ10TheAuditReadRecordsAreAcceptedWithNoSinkToWriteThem.
//
// The P2-22 fix has two halves: `admin.audit.read` in handleAdminAudit and
// `account.export` in handleExportAccount, both written through `s.auditLog` —
// an OPTIONAL field whose doc says "a nil logger records nothing", and which the
// read-API validation does not require. httpapi.New enforces
// `Config.Audit requires Config.Sessions` and `requires a non-empty Config.Admins`
// out of the same worry (reading the log means reading about every account), but
// accepts a read API with no write side: the two records then never happen, in a
// configuration that looks correctly wired.
func TestZ10TheAuditReadRecordsAreAcceptedWithNoSinkToWriteThem(t *testing.T) {
	manager := auth.NewManager(auth.Options{Secure: false})
	_, err := httpapi.New(httpapi.Config{
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
	})
	if err == nil {
		t.Errorf("httpapi.New accepted Config.Audit (the operator read API) with a nil Config.AuditLog. " +
			"recordAudit returns early on a nil logger, so GET /v1/admin/audit and GET /v1/account/export " +
			"leave no record at all while the configuration looks complete — the exact gap the P2-22 fix " +
			"was added to close. The composition root wires both, so this is a library-level fail-open.")
	}
}
