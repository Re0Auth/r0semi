package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func TestOIDCTokenKeyFailClosed(t *testing.T) {
	t.Setenv("RE0AUTH_OIDC_TOKEN_KEY", "")
	if _, err := oidcTokenKey(); err == nil {
		t.Fatal("missing token key was accepted")
	}

	t.Setenv("RE0AUTH_OIDC_TOKEN_KEY", base64.StdEncoding.EncodeToString(make([]byte, 16)))
	if _, err := oidcTokenKey(); err == nil {
		t.Fatal("16-byte token key was accepted")
	}

	good := base64.StdEncoding.EncodeToString(make([]byte, 32))
	t.Setenv("RE0AUTH_OIDC_TOKEN_KEY", good)
	key, err := oidcTokenKey()
	if err != nil || len(key) != 32 {
		t.Fatalf("valid token key rejected: %v", err)
	}
}

func TestOIDCSigningKeyFailClosed(t *testing.T) {
	t.Setenv("RE0AUTH_OIDC_SIGNING_KEY", "")
	if _, err := oidcSigningKey(); err == nil {
		t.Fatal("missing signing key was accepted")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RE0AUTH_OIDC_SIGNING_KEY", base64.StdEncoding.EncodeToString(der))
	if _, err := oidcSigningKey(); err != nil {
		t.Fatalf("valid signing key rejected: %v", err)
	}
}

func TestOIDCRetiredKeysParsing(t *testing.T) {
	t.Setenv("RE0AUTH_OIDC_RETIRED_TOKEN_KEYS", "old:"+base64.StdEncoding.EncodeToString(make([]byte, 32)))
	tokens, err := oidcRetiredTokenKeys()
	if err != nil || len(tokens) != 1 || tokens[0].ID != "old" {
		t.Fatalf("retired token keys = %v (%v)", tokens, err)
	}
	t.Setenv("RE0AUTH_OIDC_RETIRED_TOKEN_KEYS", "malformed")
	if _, err := oidcRetiredTokenKeys(); err == nil {
		t.Fatal("malformed retired token key accepted")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RE0AUTH_OIDC_RETIRED_SIGNING_KEYS", "old:"+base64.StdEncoding.EncodeToString(pubDER))
	signing, err := oidcRetiredSigningKeys()
	if err != nil || len(signing) != 1 || signing[0].ID != "old" {
		t.Fatalf("retired signing keys = %v (%v)", signing, err)
	}
	t.Setenv("RE0AUTH_OIDC_RETIRED_SIGNING_KEYS", "malformed")
	if _, err := oidcRetiredSigningKeys(); err == nil {
		t.Fatal("malformed retired signing key accepted")
	}
}
