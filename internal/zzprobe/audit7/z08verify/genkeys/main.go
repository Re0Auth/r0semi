//go:build audit7

// Command genkeys prints the three environment values cmd/re0auth needs to
// start in memory mode, so the zone-08 re-verification can drive a real process
// without a config file. It exists because the local PowerShell is Windows
// PowerShell 5.1, whose .NET Framework types lack ExportPkcs8PrivateKey.
//
//	go run -tags audit7 ./internal/zzprobe/audit7/z08verify/genkeys
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	kek := make([]byte, 32)
	token := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := rand.Read(token); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("RE0AUTH_KEK=%s\n", base64.StdEncoding.EncodeToString(kek))
	fmt.Printf("RE0AUTH_OIDC_TOKEN_KEY=%s\n", base64.StdEncoding.EncodeToString(token))
	fmt.Printf("RE0AUTH_OIDC_SIGNING_KEY=%s\n", base64.StdEncoding.EncodeToString(der))
}
