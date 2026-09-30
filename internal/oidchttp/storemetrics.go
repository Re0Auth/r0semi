package oidchttp

import (
	"context"
	"errors"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/internal/observability"
	"github.com/Re0Auth/r0semi/oauth"
)

// meteredStorage wraps the op.Storage so a refresh-store outage is observable.
//
// The library maps every error from the refresh lookup to invalid_grant
// (zitadel/oidc pkg/op/token_refresh.go), so a failover and a genuinely dead
// token are indistinguishable on the wire. The store still classifies them
// (oauth.ErrTokenNotFound for "never handed out", a wrapped cause for an
// infrastructure failure); this decorator is where the second class becomes a
// metric instead of a log line an operator has to find (N-02,
// docs/issues/P2-medium.md).
//
// Only TokenRequestByRefreshToken is overridden; every other method is promoted
// from the embedded interface. The library reaches some capabilities by type
// asserting the storage, not by calling through op.Storage — the device grant
// (pkg/op/device.go assertDeviceStorage), the request-derived id_token claims
// (pkg/op/token.go CanSetUserinfoFromRequest) and the advertised grant types
// (pkg/op/op.go). A wrapper that embedded only op.Storage would answer those
// assertions "no" and silently disable the capability, so withStoreMetrics
// rebuilds whichever of them the wrapped store implemented.
type meteredStorage struct {
	op.Storage
	metrics *observability.Metrics
}

// meteredUserinfoStorage keeps op.CanSetUserinfoFromRequest visible through the
// wrapper.
type meteredUserinfoStorage struct {
	*meteredStorage
	op.CanSetUserinfoFromRequest
}

// meteredDeviceStorage keeps op.DeviceAuthorizationStorage visible through the
// wrapper.
type meteredDeviceStorage struct {
	*meteredStorage
	op.DeviceAuthorizationStorage
}

// meteredDeviceUserinfoStorage carries both optional interfaces at once.
type meteredDeviceUserinfoStorage struct {
	*meteredUserinfoStorage
	op.DeviceAuthorizationStorage
}

// withStoreMetrics returns s unchanged when there is no metrics set: the
// *observability.Metrics methods are nil-safe, but skipping the wrapper keeps
// the no-metrics path allocation-free and leaves the storage's concrete type
// intact.
func withStoreMetrics(s op.Storage, m *observability.Metrics) op.Storage {
	if m == nil {
		return s
	}
	base := &meteredStorage{Storage: s, metrics: m}
	userinfo, hasUserinfo := s.(op.CanSetUserinfoFromRequest)
	devices, hasDevice := s.(op.DeviceAuthorizationStorage)
	switch {
	case hasUserinfo && hasDevice:
		return &meteredDeviceUserinfoStorage{
			meteredUserinfoStorage: &meteredUserinfoStorage{
				meteredStorage:            base,
				CanSetUserinfoFromRequest: userinfo,
			},
			DeviceAuthorizationStorage: devices,
		}
	case hasUserinfo:
		return &meteredUserinfoStorage{meteredStorage: base, CanSetUserinfoFromRequest: userinfo}
	case hasDevice:
		return &meteredDeviceStorage{meteredStorage: base, DeviceAuthorizationStorage: devices}
	default:
		return base
	}
}

// TokenRequestByRefreshToken counts only infrastructure failures. A refusal the
// store produced on purpose — the unknown-token sentinel, or an *oidc.Error the
// store already typed as invalid_grant (the replay/spent case) — is an answer,
// not an outage.
func (s meteredStorage) TokenRequestByRefreshToken(ctx context.Context, value string) (op.RefreshTokenRequest, error) {
	req, err := s.Storage.TokenRequestByRefreshToken(ctx, value)
	if err == nil || errors.Is(err, oauth.ErrTokenNotFound) {
		return req, err
	}
	var oe *oidc.Error
	if errors.As(err, &oe) && oe.ErrorType == oidc.InvalidGrant {
		return req, err
	}
	s.metrics.ObserveStoreUnavailable("refresh_token_read")
	return req, err
}
