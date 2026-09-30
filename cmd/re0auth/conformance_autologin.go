//go:build conformance

package main

import (
	"context"
	"log/slog"
	"net/url"
	"os"
	"time"
)

// This file exists only under the `conformance` build tag, which no release target
// passes (Makefile:169 builds with `go build -trimpath` and no tags). It lets the
// OpenID Foundation conformance suite drive an authorization-code flow unattended:
// the suite cannot log in at an external IdP, and this OP answers every
// authorization with an interactive consent screen by design (S02-2, S02-1).
//
// The build tag is the first gate, not the only one. The bypass also requires
// RE0AUTH_CONFORMANCE_AUTOLOGIN=1, logs a warning at startup and on every request it
// approves, and the non-tagged build refuses to start when that variable is set
// (conformance_stub.go). A production binary cannot contain this code at all.

const conformanceAutoLoginEnv = "RE0AUTH_CONFORMANCE_AUTOLOGIN"

// conformanceSubject is the fixed subject every auto-authenticated request carries.
// It is a plain string: the OP's consent record does not require an account row.
const conformanceSubject = "usr_conformance"

// conformanceLoginStartupCheck says, at startup, that this binary is the dangerous
// one. Silence would let a conformance build serve unnoticed.
func conformanceLoginStartupCheck() error {
	if os.Getenv(conformanceAutoLoginEnv) != "1" {
		return nil
	}
	slog.Warn("CONFORMANCE BUILD: authorization requests will be auto-authenticated and auto-approved; "+
		"this binary must never be deployed", "env", conformanceAutoLoginEnv)
	return nil
}

// conformanceAutoLogin completes a pending authorization request with no user in the
// loop: it stamps a real authentication time and completes the login as
// conformanceSubject, then hands back the OP's own callback URL so the code is
// issued. It reports handled=false unless both the tag and the opt-in are present.
//
// The authentication is "now", and it is recorded BEFORE CompleteLogin. That keeps
// the S02-1 boundary honest even here: a prompt=login or elapsed max_age request is
// completable because a fresh authentication exists, not because the freshness rule
// was skipped for the test.
func conformanceAutoLogin(ctx context.Context, store oidcBackend, id string) (string, bool, error) {
	if os.Getenv(conformanceAutoLoginEnv) != "1" {
		return "", false, nil
	}
	ar, err := store.AuthRequestByID(ctx, id)
	if err != nil {
		return "", false, err
	}
	now := time.Now()
	if err := store.SetAuthTime(ctx, id, now); err != nil {
		return "", false, err
	}
	if err := store.CompleteLogin(ctx, id, conformanceSubject, ar.GetScopes()); err != nil {
		return "", false, err
	}
	slog.Warn("conformance auto-login: completed an authorization with no authentication and no consent",
		"auth_request", id, "subject", conformanceSubject)
	return "/oauth/authorize/callback?id=" + url.QueryEscape(id), true, nil
}
