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
