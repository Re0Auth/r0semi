//go:build !conformance

package main

import (
	"context"
	"errors"
	"os"
)

const conformanceAutoLoginEnv = "RE0AUTH_CONFORMANCE_AUTOLOGIN"

// conformanceLoginStartupCheck fails closed. An operator who set the opt-in on a
// binary built without the tag is told the truth at startup, instead of silently
// getting no bypass and believing otherwise.
func conformanceLoginStartupCheck() error {
	if os.Getenv(conformanceAutoLoginEnv) != "" {
		return errors.New(conformanceAutoLoginEnv + " is set, but this binary was built without the " +
			"`conformance` build tag, so it cannot auto-authenticate anything; " +
			"rebuild with `go build -tags conformance` or unset it")
	}
	return nil
}

// conformanceAutoLogin is compiled out of every production build: this binary has no
// path that skips authentication or consent, so it always reports "not handled".
func conformanceAutoLogin(context.Context, oidcBackend, string) (string, bool, error) {
	return "", false, nil
}
