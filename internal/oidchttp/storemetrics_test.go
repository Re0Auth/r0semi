package oidchttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/internal/observability"
	"github.com/Re0Auth/r0semi/oauth"
)

// erroringStorage answers the refresh lookup with a fixed error. Embedding the
// op.Storage interface leaves every other method nil; the test calls only this
// one.
type erroringStorage struct {
	op.Storage
	err error
}

func (s erroringStorage) TokenRequestByRefreshToken(context.Context, string) (op.RefreshTokenRequest, error) {
	return nil, s.err
}

// storeUnavailableLine returns the exposition line for the N-02 counter, or "".
func storeUnavailableLine(t *testing.T, m *observability.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", rec.Code)
	}
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if strings.HasPrefix(line, "re0auth_store_unavailable_total") {
			return line
		}
	}
	return ""
}

// TestStoreUnavailableIsCountedOnlyForInfrastructureFailures is the N-02
// boundary guard: the library maps every refresh-store error to invalid_grant,
// so the store outage has to be told apart here. A refusal the store produced on
// purpose must not inflate the counter.
func TestStoreUnavailableIsCountedOnlyForInfrastructureFailures(t *testing.T) {
	m := observability.New()
	ctx := context.Background()

	// A database that could not answer: counted.
	if _, err := withStoreMetrics(erroringStorage{err: errors.New("connection refused")}, m).
		TokenRequestByRefreshToken(ctx, "v"); err == nil {
		t.Fatal("the fake store returned no error")
	}
	if got := storeUnavailableLine(t, m); !strings.Contains(got, `operation="refresh_token_read"`) ||
		!strings.HasSuffix(got, " 1") {
		t.Errorf("an infrastructure failure was not counted: %q", got)
	}

	// A value this issuer never handed out: an answer, not an outage.
	if _, err := withStoreMetrics(erroringStorage{err: oauth.ErrTokenNotFound}, m).
		TokenRequestByRefreshToken(ctx, "v"); !errors.Is(err, oauth.ErrTokenNotFound) {
		t.Fatalf("the sentinel was not returned: %v", err)
	}
	// The replay/spent refusal is a typed invalid_grant: also an answer.
	spent := oidc.ErrInvalidGrant().WithDescription("refresh token was already used")
	if _, err := withStoreMetrics(erroringStorage{err: spent}, m).
		TokenRequestByRefreshToken(ctx, "v"); err == nil {
		t.Fatal("the typed refusal was not returned")
	}
	if got := storeUnavailableLine(t, m); !strings.HasSuffix(got, " 1") {
		t.Errorf("a refusal was counted as an outage: %q", got)
	}

	// A nil metrics set skips the wrapper entirely and still propagates the error.
	raw := withStoreMetrics(erroringStorage{err: errors.New("x")}, nil)
	if _, ok := raw.(meteredStorage); ok {
		t.Error("the decorator was installed despite a nil metrics set")
	}
	if _, err := raw.TokenRequestByRefreshToken(ctx, "v"); err == nil {
		t.Error("the unwrapped storage stopped returning its error")
	}
	t.Logf("counter: %s", strings.TrimSpace(storeUnavailableLine(t, m)))
}

// fullStorage satisfies op.Storage plus the two optional interfaces this
// project's stores implement, so the wrapper's preservation is observable.
type fullStorage struct {
	op.Storage
	op.DeviceAuthorizationStorage
	op.CanSetUserinfoFromRequest
}

// TestStoreMetricsPreservesOptionalStorageInterfaces guards the capability the
// library reaches by type assertion rather than by an op.Storage call. A wrapper
// that embedded only op.Storage still compiles and still forwards the refresh
// lookup, but it answers every optional assertion "no": the device grant is then
// reported unsupported (pkg/op/device.go assertDeviceStorage) and request-derived
// id_token claims stop being set (pkg/op/token.go CanSetUserinfoFromRequest).
func TestStoreMetricsPreservesOptionalStorageInterfaces(t *testing.T) {
	wrapped := withStoreMetrics(fullStorage{}, observability.New())
	if _, ok := wrapped.(op.DeviceAuthorizationStorage); !ok {
		t.Error("the decorator hides op.DeviceAuthorizationStorage: the device grant is reported unsupported " +
			"even though the wrapped store implements it (N-02 regression)")
	}
	if _, ok := wrapped.(op.CanSetUserinfoFromRequest); !ok {
		t.Error("the decorator hides op.CanSetUserinfoFromRequest: request-derived id_token claims silently " +
			"stop being set (N-02 regression)")
	}
}
