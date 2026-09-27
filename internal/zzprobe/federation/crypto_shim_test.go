//go:build audit5

package zzprobe_federation

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

func base64URLSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
