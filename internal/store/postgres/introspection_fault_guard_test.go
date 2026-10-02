package postgres

// introspection_fault_guard_test.go is the database-free half of S02-8=A,
// requested by w1-oidchttp.
//
// SetIntrospectionFromToken used to collapse every failure into
// errors.New("postgres: token not found"): a pool exhaustion or a connection loss
// looked exactly like an unknown token, so the introspection handler answered
// Active:false for a broken store instead of 500 (and, once the handler separates
// the classes, a revoked token would have 500'd). The fix returns the typed
// oauth.ErrTokenNotFound for "unknown/expired" and preserves the cause for an
// infrastructure failure.

import (
	"strings"
	"testing"
)

func TestIntrospectionClassifiesNotFoundAndLeavesInfraDistinct(t *testing.T) {
	body := sourceOf(t, "oidc.go")
	method := receiverMethod(t, body, "oidc.go", "SetIntrospectionFromToken")

	if strings.Contains(method, `errors.New("postgres: token not found")`) {
		t.Error("SetIntrospectionFromToken still returns an untyped not-found error; the handler cannot " +
			"distinguish a revoked/expired token from a store fault (S02-8)")
	}
	if strings.Contains(method, `errors.New("postgres: token expired")`) {
		t.Error("an expired token is still a bespoke untyped error, not oauth.ErrTokenNotFound")
	}
	if !strings.Contains(method, "oauth.ErrTokenNotFound") {
		t.Error("SetIntrospectionFromToken does not return oauth.ErrTokenNotFound for an unknown or " +
			"expired token (S02-8)")
	}
	if !strings.Contains(method, "pgx.ErrNoRows") || !strings.Contains(method, "errors.Is") {
		t.Error("the no-rows case is not separated from the query/scan error, so an infrastructure " +
			"failure can still be folded into not-found (S02-8)")
	}
	if !strings.Contains(method, "introspect token: %w") {
		t.Error("an infrastructure failure does not preserve its cause; a 500 without the underlying " +
			"error is undiagnosable (S02-8)")
	}
}
