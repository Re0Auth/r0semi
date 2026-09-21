package tapsign

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Credential is a TapTap built-in-account credential -- the "stoken" of the
// community. It is the payload the vault stores opaquely; tapsign owns its
// codec, so the vault never learns the shape.
type Credential struct {
	// SessionToken is the long-lived session token (X-LC-Session). It is the
	// secret.
	SessionToken string `json:"session_token"`
	// ObjectID locates the LeanCloud user and is required to rotate the token.
	ObjectID string `json:"object_id"`
}

// Valid reports whether the credential is structurally complete.
func (c Credential) Valid() error {
	if c.SessionToken == "" {
		return errors.New("tapsign: empty session token")
	}
	if c.ObjectID == "" {
		return errors.New("tapsign: empty object id")
	}
	return nil
}

// Encode serializes the credential for storage in the vault.
func (c Credential) Encode() ([]byte, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("tapsign: encode credential: %w", err)
	}
	return b, nil
}

// DecodeCredential parses a payload previously produced by Credential.Encode.
func DecodeCredential(b []byte) (Credential, error) {
	var c Credential
	if err := json.Unmarshal(b, &c); err != nil {
		return Credential{}, fmt.Errorf("tapsign: decode credential: %w", err)
	}
	return c, nil
}
