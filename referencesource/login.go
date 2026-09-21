package referencesource

import (
	"context"
	"errors"
)

// Principal is the end user as the source knows them, plus the native
// credential the source must keep to act on their behalf.
type Principal struct {
	// Subject is the source's own, stable account id (e.g. a TapTap openid).
	Subject string
	// Display is an optional human-readable name.
	Display string
	// Credential is opaque to Re0Auth. It goes straight into the vault and is
	// never returned downstream.
	Credential []byte
	// Meta is non-secret metadata (unionid, platform, ...).
	Meta map[string]string
}

// Authenticator establishes the end user at the source.
//
// A real source reads its own session here, which its /login page (QR or
// device-code) populated. The Kit calls it from the authorize endpoint via the
// Consent hook. Returning an error means "no authenticated user", which the Kit
// turns into access_denied -- never a fabricated identity.
type Authenticator interface {
	Authenticate(ctx context.Context) (Principal, error)
}

// StaticAuthenticator is a fixed-Principal Authenticator for tests and demos.
// Slice 2 replaces it with the real TapTap login.
type StaticAuthenticator struct {
	Principal Principal
	Err       error
}

// Authenticate implements Authenticator.
func (a StaticAuthenticator) Authenticate(context.Context) (Principal, error) {
	if a.Err != nil {
		return Principal{}, a.Err
	}
	if a.Principal.Subject == "" {
		return Principal{}, errors.New("referencesource: no authenticated user at the source")
	}
	return a.Principal, nil
}
