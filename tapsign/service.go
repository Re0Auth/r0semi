package tapsign

import (
	"context"
	"errors"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/httpclient"
)

// ErrInvalidCredential reports that upstream rejected the credential with 401
// or 403. It is the passive death signal: the stored session token is no longer
// valid anywhere (the user changed their password, logged out server-side, or
// the token was rotated elsewhere).
var ErrInvalidCredential = errors.New("tapsign: credential rejected by upstream")

// ErrRotationAuditFailed reports that Rotate SUCCEEDED but could not write its
// audit record. The returned replacement credential is live and is the only
// credential that works: the old token was invalidated upstream before the audit
// write was attempted.
//
// It exists so a caller can tell "the rotation failed" (the old token may still
// be the live one) from "the rotation happened, only its audit entry is missing"
// (the replacement must be persisted, and the audit failure is an operator
// alert). Callers that treat every non-nil error as a failed rotation would
// discard the one live credential and lock the user out, so Rotate reports this
// case as errors.Is(err, ErrRotationAuditFailed) and the Service interface
// documents it.
var ErrRotationAuditFailed = errors.New("tapsign: rotation succeeded but the audit record could not be written")

// TapTapToken is the result of a TapTap OAuth device-authorization flow. It is
// exchanged for a built-in-account Credential via Service.Redeem.
type TapTapToken struct {
	Kid     string
	MacKey  string
	OpenID  string
	UnionID string
}

// Service is the upstream/tapsign capability: the lifecycle of a TapTap
// built-in-account session token.
//
// It never sees the vault and never stores anything; callers obtain a decrypted
// Credential from the vault and hand it here.
type Service interface {
	// Verify reports whether cred is still accepted by upstream.
	Verify(ctx context.Context, cred Credential) error

	// Rotate exchanges cred for a fresh session token. The old token is invalid
	// from the moment Rotate succeeds.
	//
	// A non-nil error normally means the rotation did not complete and the
	// returned credential is not usable. The one exception is
	// errors.Is(err, ErrRotationAuditFailed): there the rotation DID happen, the
	// returned replacement is the only live credential, and the caller must
	// persist it while treating the error as an audit alert (S07-10).
	Rotate(ctx context.Context, cred Credential) (Credential, error)

	// Revoke invalidates cred everywhere and discards the replacement token.
	//
	// It is idempotent in its goal -- "the old token is invalid" -- so an
	// ErrInvalidCredential from upstream is reported as success.
	Revoke(ctx context.Context, cred Credential) error

	// Redeem exchanges a TapTap OAuth token for a built-in-account Credential,
	// registering the linked account on first login.
	Redeem(ctx context.Context, tok TapTapToken) (Credential, error)
}

// NewService wires the TapTap built-in-account client directly, without the
// component runtime. It is what a standalone source (or a component) uses.
func NewService(cfg Config, doer httpclient.Doer, logger audit.Logger) (Service, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if doer == nil {
		return nil, errors.New("tapsign: a Doer is required")
	}
	if logger == nil {
		return nil, errors.New("tapsign: an audit.Logger is required")
	}
	return newClient(cfg, doer, logger), nil
}
