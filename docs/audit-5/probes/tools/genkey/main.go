//go:build ignore

// Command genkey prints the audit smoke-test secret set, one KEY=VALUE per line,
// in the form cmd/re0auth reads from the environment. It exists only because the
// audit machine has no openssl; it is not part of any shipped artifact.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
)

func rand32() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	out := ""
	for _, kv := range [][2]string{
		{"RE0AUTH_KEK", rand32()},
		{"RE0AUTH_OIDC_TOKEN_KEY", rand32()},
		{"RE0AUTH_OIDC_SIGNING_KEY", base64.StdEncoding.EncodeToString(der)},
		{"RE0AUTH_AUDIT_KEY", rand32()},
	} {
		out += kv[0] + "=" + kv[1] + "\n"
	}
	if err := os.WriteFile("docs/audit-5/runtime/secrets.env", []byte(out), 0o600); err != nil {
		panic(err)
	}
	fmt.Println("wrote docs/audit-5/runtime/secrets.env")
}
