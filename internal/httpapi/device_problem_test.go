package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// deviceProblem is the single place a device-engine error becomes a wire answer.
// The property that matters: a known not-found stays a 404, a protocol error this
// service wrote is shown, and an internal fault never carries its text to the
// caller.
func TestDeviceProblemNeverLeaksInternalText(t *testing.T) {
	const secret = `pq: relation "sessions" does not exist`
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"unknown or expired", oauth.ErrDeviceNotFound, http.StatusNotFound, "not_found"},
		{"client removed", oauth.ErrClientNotFound, http.StatusNotFound, "not_found"},
		{
			"protocol error",
			&oauth.Error{Code: "invalid_scope", Description: "the decision cannot widen the requested scope"},
			http.StatusBadRequest, "invalid_request",
		},
		{"internal fault", errors.New(secret), http.StatusInternalServerError, "internal_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, code, detail := deviceProblem(tc.err)
			if status != tc.wantStatus || code != tc.wantCode {
				t.Fatalf("deviceProblem = (%d, %q), want (%d, %q)", status, code, tc.wantStatus, tc.wantCode)
			}
			if status == http.StatusInternalServerError {
				if detail != "could not complete the request" {
					t.Errorf("internal detail = %q, want the generic message", detail)
				}
				if strings.Contains(detail, "pq:") || strings.Contains(detail, "sessions") {
					t.Errorf("internal error text leaked into the response: %q", detail)
				}
			}
		})
	}
}

// A protocol error wrapped for context must still classify: it keeps its
// description and its 400, not a 500.
func TestDeviceProblemSeesThroughWrapping(t *testing.T) {
	err := fmt.Errorf("device: %w",
		&oauth.Error{Code: "access_denied", Description: "explicit consent is required for phigros.score.read"})
	status, code, detail := deviceProblem(err)
	if status != http.StatusBadRequest || code != "invalid_request" {
		t.Fatalf("deviceProblem = (%d, %q), want (400, invalid_request)", status, code)
	}
	if !strings.Contains(detail, "explicit consent") {
		t.Errorf("detail = %q, want the safe protocol description", detail)
	}
}
