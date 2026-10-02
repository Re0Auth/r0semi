// S02-8 probe (regulation: one probe per "red before / green after" claim).
//
// Handler.Introspect used to fold every SetIntrospectionFromToken error into
// oauth.TokenInfo{Active:false}: a store outage and a revoked token were the
// same answer, so internal/httpapi's withBearer answered 401 invalid_token for
// a database failure and no 5xx or outage metric ever appeared.
//
// The contract this pins:
//
//	store answers "no live record" (oauth.ErrTokenNotFound) -> Active=false, nil
//	store itself fails (anything else)                      -> non-nil error
//
// The second branch is what withBearer (internal/httpapi/middleware.go:711-714)
// turns into a 500 problem+json; zz_probe_s02_8_test.go in internal/httpapi
// drives that end to end.
//
// Before the fix the first subtest is RED: the infrastructure error came back as
// a nil-error inactive answer.
package oidchttp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/internal/observability"
	"github.com/Re0Auth/r0semi/oauth"
)

// s028IntrospectStorage is an op.Storage whose introspection lookup fails with a
// fixed error. Embedding op.Storage leaves every other method nil; Introspect
// reaches only this one, and op.NewProvider calls none at construction.
type s028IntrospectStorage struct {
	op.Storage
	err error
}

func (s s028IntrospectStorage) SetIntrospectionFromToken(context.Context, *oidc.IntrospectionResponse, string, string, string) error {
	return s.err
}

// s028HandlerWithIntrospectError builds a protocol plane whose store answers the
// introspection with err, using the same token key as newFixture so an access
// token issued by the real plane decrypts here.
func s028HandlerWithIntrospectError(t *testing.T, err error, m *observability.Metrics) *Handler {
	t.Helper()
	var cryptoKey [32]byte
	copy(cryptoKey[:], []byte("0123456789abcdef0123456789abcdef"))
	h, newErr := New(Config{
		Storage:       s028IntrospectStorage{err: err},
		CryptoKey:     cryptoKey,
		CryptoKeyID:   "test",
		AllowInsecure: true,
		Clients:       oauth.NewMemoryClientRegistry(),
		Registry:      oauth.DefaultRegistry(),
		Metrics:       m,
	})
	if newErr != nil {
		t.Fatal(newErr)
	}
	return h
}

func TestProbeIntrospectStoreFaultIsNotAnInactiveAnswer(t *testing.T) {
	f := newFixture(t)
	tokens := codeFlow(t, f, []string{oauth.ScopeAccountID.String()})
	access, _ := tokens["access_token"].(string)
	if access == "" {
		t.Fatal("the code flow returned no access token")
	}

	m := observability.New()
	h := s028HandlerWithIntrospectError(t, errors.New("connection refused"), m)

	info, err := h.Introspect(context.Background(), access)
	if err == nil {
		t.Fatalf("a store outage was reported as an answer about the token: info=%+v err=nil; "+
			"want a non-nil error so withBearer answers 500 problem+json instead of 401 invalid_token", info)
	}
	if info.Active {
		t.Errorf("a store outage reported Active=true: %+v", info)
	}
	if got := storeUnavailableLine(t, m); !strings.Contains(got, `operation="introspection"`) ||
		!strings.HasSuffix(got, " 1") {
		t.Errorf("the introspection outage was not counted: %q", got)
	}

	t.Logf("store fault -> err=%v; counter=%s", err, strings.TrimSpace(storeUnavailableLine(t, m)))
}

func TestProbeIntrospectUnknownTokenStaysInactive(t *testing.T) {
	f := newFixture(t)
	tokens := codeFlow(t, f, []string{oauth.ScopeAccountID.String()})
	access, _ := tokens["access_token"].(string)
	if access == "" {
		t.Fatal("the code flow returned no access token")
	}

	m := observability.New()
	h := s028HandlerWithIntrospectError(t, oauth.ErrTokenNotFound, m)

	info, err := h.Introspect(context.Background(), access)
	if err != nil {
		t.Fatalf("the store's not-found answer was propagated as a fault: %v; want Active=false with a nil error", err)
	}
	if info.Active {
		t.Errorf("an unknown token = %+v; want Active=false", info)
	}
	if got := storeUnavailableLine(t, m); got != "" {
		t.Errorf("a routine not-found answer was counted as an outage: %q", got)
	}
}
