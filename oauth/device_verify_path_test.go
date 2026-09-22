package oauth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
)

// RFC 8628 hands verification_uri to the user's browser, so it has to name a page
// a person can use. A deployment with a frontend points it there; the default
// exists for one without. Either way the path is the deployment's to choose, and
// this asserts that the choice is actually honoured rather than ignored in favour
// of a hardcoded one.
func TestVerificationPathIsConfigurable(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{"default", "", "https://auth.test/device"},
		{"frontend page", "/app/device", "https://auth.test/app/device"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
			clients := NewMemoryClientRegistry()
			svc, err := NewService(clients, NewMemoryStore(), audit.NewMemoryLogger(), Config{
				Issuer:           "https://auth.test",
				Scopes:           testRegistry(t),
				Now:              clock.now,
				VerificationPath: tc.path,
			})
			if err != nil {
				t.Fatal(err)
			}
			registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})

			start, err := svc.BeginDeviceAuthorization(context.Background(), DeviceAuthorizationRequest{
				ClientID: "app", Scopes: []Scope{ScopeAccountID},
			})
			if err != nil {
				t.Fatal(err)
			}
			if start.VerificationURI != tc.want {
				t.Errorf("verification_uri = %q, want %q", start.VerificationURI, tc.want)
			}
			wantComplete := tc.want + "?user_code=" + start.UserCode
			if start.VerificationURIComplete != wantComplete {
				t.Errorf("verification_uri_complete = %q, want %q", start.VerificationURIComplete, wantComplete)
			}
			// The complete URI embeds the code, so a code containing characters
			// that mean something in a query string must arrive escaped.
			if strings.ContainsAny(start.UserCode, "&=?#") {
				if !strings.Contains(start.VerificationURIComplete, "user_code=") {
					t.Errorf("complete URI lost its query parameter: %q", start.VerificationURIComplete)
				}
			}
		})
	}
}
