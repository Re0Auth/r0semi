package postgres

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R10-59's durable half cannot be exercised without a live Postgres, so this is
// the shipped guard that the ordering is actually wired: every revocation bumps
// its scope before deleting, every resolve step captures the generation, and the
// mint re-checks it under FOR SHARE.
func TestR1059RevocationEpochsAreWiredIntoEverySeam(t *testing.T) {
	oidcSrc := stripSourceComments(sourceOf(t, "oidc.go"))
	for _, tc := range []struct{ fn, want string }{
		{"func (s *OIDCStore) RevokeTokens(", "bumpRevocationEpochs"},
		{"func (s *OIDCStore) RevokeGrant(", "bumpRevocationEpochs"},
		{"func (s *OIDCStore) CreateAccessAndRefreshTokens(", "checkRevocationEpochs"},
		{"func (s *OIDCStore) AuthRequestByCode(", "captureRevocationEpochs"},
		{"func (s *OIDCStore) TokenRequestByRefreshToken(", "captureRevocationEpochs"},
		{"func (s *OIDCStore) GetDeviceAuthorizatonState(", "captureRevocationEpochs"},
	} {
		if body := functionBody(t, oidcSrc, tc.fn); !strings.Contains(body, tc.want) {
			t.Errorf("R10-59: %s does not call %s", tc.fn, tc.want)
		}
	}

	helper := stripSourceComments(sourceOf(t, "revocation_epochs.go"))
	if !strings.Contains(helper, "FOR SHARE") {
		t.Fatal("R10-59: the mint's epoch read is not FOR SHARE, so a concurrent revocation is not ordered")
	}

	matches, err := filepath.Glob(filepath.Join("migrations", "*oidc_revocation_epochs*.sql"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("R10-59: no migration creates oidc_revocation_epochs (glob err=%v)", err)
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	up := string(raw)
	for _, want := range []string{"CREATE TABLE IF NOT EXISTS oidc_revocation_epochs", "VALUES ('*'", "DROP TABLE IF EXISTS oidc_revocation_epochs"} {
		if !strings.Contains(up, want) {
			t.Errorf("R10-59: the epoch migration lacks %q", want)
		}
	}
}
