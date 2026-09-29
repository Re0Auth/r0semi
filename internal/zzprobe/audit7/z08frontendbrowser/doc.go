//go:build !audit7

// Package z08frontendbrowser holds the round-7 frontend / browser-plane audit
// probes (scratchpad/audit7/findings/Z08-frontend-browser.md).
//
// This file keeps the package present when the audit7 build tag is not set, so
// the default suite and the probes never see each other.
package z08frontendbrowser
