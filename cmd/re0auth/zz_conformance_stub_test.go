//go:build !conformance

package main

import (
	"context"
	"testing"
)

// The production binary must not be able to bypass authentication or consent, and an
// operator who sets the opt-in on it must be told at startup rather than left
// believing a bypass is active. This is the non-tagged side of the guard; the tagged
// behaviour is asserted in zz_conformance_autologin_test.go.
func TestConformanceAutoLoginIsAbsentOnAProductionBuild(t *testing.T) {
	t.Setenv(conformanceAutoLoginEnv, "1")
	if err := conformanceLoginStartupCheck(); err == nil {
		t.Fatal("the startup check accepted the auto-login opt-in on a binary built without the conformance tag")
	}

	t.Setenv(conformanceAutoLoginEnv, "")
	if err := conformanceLoginStartupCheck(); err != nil {
		t.Fatalf("the startup check refused an unset opt-in: %v", err)
	}
	if target, handled, err := conformanceAutoLogin(context.Background(), nil, "ar_1"); err != nil || handled || target != "" {
		t.Fatalf("the production build auto-handled a request: target=%q handled=%v err=%v", target, handled, err)
	}
}
