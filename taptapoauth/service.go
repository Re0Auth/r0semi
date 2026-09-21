package taptapoauth

import (
	"context"
	"errors"
	"time"

	"github.com/Re0Auth/r0semi/httpclient"
	"github.com/Re0Auth/r0semi/tapsign"
)

// ErrAuthorizationPending reports that the user has not approved the device
// authorization yet. The caller should wait DeviceAuth.Interval and poll again.
var ErrAuthorizationPending = errors.New("taptapoauth: authorization pending")

// DeviceAuth is a pending device authorization.
type DeviceAuth struct {
	DeviceID        string
	DeviceCode      string
	UserCode        string
	VerificationURL string        // to display, and to encode into a QR code
	QRCodeURL       string        // upstream-provided QR target, if any
	Interval        time.Duration // recommended poll interval
	ExpiresAt       time.Time
}

// Enroller is the upstream/taptap.oauth capability: the RFC 8628-style device
// authorization flow leading to a TapTap token.
//
// The result is not yet a Credential; call tapsign.Service.Redeem to exchange
// it for a built-in-account session token.
type Enroller interface {
	// Start requests a device code and returns the authorization the user must
	// approve out of band.
	Start(ctx context.Context) (DeviceAuth, error)

	// Poll exchanges an approved authorization for a TapTap token. It returns
	// ErrAuthorizationPending while the user has not approved yet.
	Poll(ctx context.Context, auth DeviceAuth) (tapsign.TapTapToken, error)
}

// NewService wires the TapTap device-authorization client directly, without the
// component runtime. It is what a standalone source (or a component) uses.
func NewService(cfg Config, doer httpclient.Doer) (Enroller, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if doer == nil {
		return nil, errors.New("taptapoauth: a Doer is required")
	}
	return newClient(cfg, doer), nil
}
