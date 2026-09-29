//go:build audit6

// Guards for the two-backend drift findings whose Postgres half cannot run in
// this environment (no local database). Each guard pins the memory backend's
// SAFE half, so the direction of the drift stays observable and a future fix
// to the Postgres side has something to agree with.
//
// 05-1: postgres/oidc.go TokenRequestByRefreshToken has no expires_at
//
//	predicate (SELECT ... WHERE token_hash = $1) and neither does the
//	DELETE in CreateAccessAndRefreshTokens; the zitadel/oidc refresh
//	grant checks no expiry of its own (pkg/op/token_refresh.go). The
//	memory backend refuses at the deadline. In Postgres the refresh TTL
//	is enforced only by the 15-minute sweep.
//
// 05-3: postgres/oidc.go ApproveDevice/DenyDevice record their audit events
//
//	with an EMPTY client_id (oidc.go:898,919), while the memory backend
//	records the client the decision belongs to. In the production backend
//	the audit trail cannot answer "which client did this device decision
//	authorise" — a narrower record than the development backend keeps.
package z05memstore

import (
	"context"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
)

// 05-1, memory half (green): a refresh token past its deadline is refused by
// the store the refresh grant consults.
func TestMemoryRefusesAnExpiredRefreshToken(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	req := &oidcstore.AuthRequest{ClientID: probeClientID, Subject: "usr_1", Scopes: []string{"account.id"}}

	_, refresh, _, err := e.store.CreateAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatal(err)
	}
	// Control: within the TTL it works.
	if _, err := e.store.TokenRequestByRefreshToken(ctx, refresh); err != nil {
		t.Fatalf("control failed: the fresh refresh token was refused: %v", err)
	}

	// Past the 30-day refresh TTL.
	e.clock.Advance(31 * 24 * time.Hour)
	if _, err := e.store.TokenRequestByRefreshToken(ctx, refresh); err == nil {
		t.Fatal("the memory backend redeemed a refresh token past its expiry; the guard half of " +
			"the drift finding is broken (this is the direction Postgres currently has)")
	}
}

// 05-3, memory half (green): the device decision audit events carry the
// client the decision is about.
func TestDeviceDecisionsAreAuditedWithClientAttribution(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()

	if err := e.store.StoreDeviceAuthorization(ctx, probeClientID, "dc-audit", "AUDT-0001",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := e.store.ApproveDevice(ctx, "AUDT-0001", "usr_1", nil); err != nil {
		t.Fatal(err)
	}
	if err := e.store.StoreDeviceAuthorization(ctx, probeClientID, "dc-audit-2", "AUDT-0002",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := e.store.DenyDevice(ctx, "AUDT-0002"); err != nil {
		t.Fatal(err)
	}

	var approve, deny *audit.Event
	events := e.logger.Events()
	for i := range events {
		switch events[i].Action {
		case "oidc.device.approve":
			approve = &events[i]
		case "oidc.device.deny":
			deny = &events[i]
		}
	}
	if approve == nil {
		t.Fatal("no oidc.device.approve event was recorded")
	}
	if got := approve.Detail["client_id"]; got != probeClientID {
		t.Errorf("approve event client_id = %q, want %q (Postgres records \"\" here: the drift finding)", got, probeClientID)
	}
	if deny == nil {
		t.Fatal("no oidc.device.deny event was recorded")
	}
	if got := deny.Detail["client_id"]; got != probeClientID {
		t.Errorf("deny event client_id = %q, want %q (Postgres records \"\" here: the drift finding)", got, probeClientID)
	}
}

// P0-2's store half, memory backend (green regression): SetUserinfoFromToken
// decides liveness from the stored row — an empty token id, an unknown one, an
// expired one and a subject that does not match the record are all refused,
// and only the record's subject is published.
func TestSetUserinfoFromTokenChecksTheStoredRow(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	req := &oidcstore.AuthRequest{ClientID: probeClientID, Subject: "usr_1", Scopes: []string{"account.id"}}

	accessID, _, err := e.store.CreateAccessToken(ctx, req)
	if err != nil {
		t.Fatal(err)
	}

	var ui oidc.UserInfo
	if err := e.store.SetUserinfoFromToken(ctx, &ui, "", "usr_1", ""); err == nil {
		t.Error("an empty token id was accepted at userinfo (JWT fallback)")
	}
	if err := e.store.SetUserinfoFromToken(ctx, &ui, "no-such-token", "usr_1", ""); err == nil {
		t.Error("an unknown token id was accepted at userinfo")
	}
	if err := e.store.SetUserinfoFromToken(ctx, &ui, accessID, "usr_someone_else", ""); err == nil {
		t.Error("a subject that does not match the token's record was accepted")
	}
	ui = oidc.UserInfo{}
	if err := e.store.SetUserinfoFromToken(ctx, &ui, accessID, "usr_1", ""); err != nil {
		t.Fatalf("a live token with its own subject was refused: %v", err)
	}
	if ui.Subject != "usr_1" {
		t.Errorf("published subject = %q, want the record's subject", ui.Subject)
	}

	// Past the one-hour access TTL the same token is refused.
	e.clock.Advance(2 * time.Hour)
	if err := e.store.SetUserinfoFromToken(ctx, &ui, accessID, "usr_1", ""); err == nil {
		t.Error("an expired access token was accepted at userinfo")
	}
}
