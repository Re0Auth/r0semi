package memory

// Z20-3 / Z20-4: the device face of the consent decision.
//
// Z20-3: the approval event must name the granted scope set, exactly like the
// interactive face — the device decision is where narrowing happens, so "which
// client with which scopes" is the only question the log has to answer.
//
// Z20-4: the device entrance DOES run the explicit-consent gate. That was
// recorded as missing (P-02) because the shipped catalogue carries no
// ExplicitConsent descriptor, so the gate could not be exercised; these probes
// build one and pin the behaviour. `internal/zzprobe/...` has similar probes, but
// they are behind audit build tags and do not run in the normal suite.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/oauth"
)

// deviceCriticalScope is a catalogue scope the shipped descriptor set does not
// have. It exists so a probe can put an ExplicitConsent descriptor in play.
const deviceCriticalScope = oauth.Scope("phigros.secret.read")

func registryWithDeviceCritical(t *testing.T) *oauth.Registry {
	t.Helper()
	reg, err := oauth.NewRegistry(append(oauth.DefaultDescriptors(), oauth.Descriptor{
		Scope: deviceCriticalScope, Title: "读取 Phigros 机密", Description: "probe descriptor",
		Risk: oauth.RiskCritical, ExplicitConsent: true,
	})...)
	if err != nil {
		t.Fatalf("oauth.NewRegistry: %v", err)
	}
	return reg
}

// deviceStore builds a store with an injectable catalogue, audit sink and client
// scope set.
func deviceStore(t *testing.T, registry *oauth.Registry, logger audit.Logger, clientScopes ...oauth.Scope) *OIDCStore {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	c, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, clientScopes)
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	store, err := NewOIDCStore(OIDCOptions{
		Clients:  clients,
		Registry: registry,
		Signer:   signerForTests(t),
		Audit:    logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func deviceApprovalEvent(t *testing.T, logger *audit.MemoryLogger) *audit.Event {
	t.Helper()
	for i := range logger.Events() {
		if logger.Events()[i].Action == "oidc.device.approve" {
			return &logger.Events()[i]
		}
	}
	return nil
}

func TestDeviceApprovalAuditRecordsTheGrantedScopes(t *testing.T) {
	logger := audit.NewMemoryLogger()
	store := deviceStore(t, oauth.DefaultRegistry(), logger,
		oauth.ScopeAccountID, oauth.ScopePhigrosProfile, oauth.ScopePhigrosScore)
	ctx := context.Background()

	if err := store.StoreDeviceAuthorization(ctx, "cli", "dc-scopes", "SCPE-0001",
		time.Now().Add(10*time.Minute),
		[]string{"account.id", "phigros.profile.read", "phigros.score.read"}); err != nil {
		t.Fatal(err)
	}
	// The user approves one of the two catalogue scopes: the narrowing is the
	// half the audit event used to lose (Z20-3).
	if err := store.DecideDeviceAuthorization(ctx, "SCPE-0001", "usr_1", true,
		[]oauth.Scope{oauth.ScopePhigrosProfile}, nil); err != nil {
		t.Fatal(err)
	}

	event := deviceApprovalEvent(t, logger)
	if event == nil {
		t.Fatal("the device approval recorded no audit event")
	}
	scopes, ok := event.Detail["scopes"]
	if !ok {
		t.Fatalf("the device approval records no scopes: detail=%v (Z20-3)", event.Detail)
	}
	if !strings.Contains(scopes, "phigros.profile.read") {
		t.Errorf("granted scopes %q omit the scope the user approved", scopes)
	}
	if strings.Contains(scopes, "phigros.score.read") {
		t.Errorf("granted scopes %q include the scope the user did NOT approve", scopes)
	}
	if event.Subject != "usr_1" || event.Detail["client_id"] != "cli" {
		t.Errorf("the device approval names the wrong parties: subject=%q detail=%v", event.Subject, event.Detail)
	}
}

// The direct ApproveDevice(nil) branch keeps the requested set, and the event
// must describe that set rather than an empty one.
func TestDirectDeviceApprovalAuditRecordsTheRequestedScopes(t *testing.T) {
	logger := audit.NewMemoryLogger()
	store := deviceStore(t, oauth.DefaultRegistry(), logger, oauth.ScopeAccountID, oauth.ScopePhigrosScore)
	ctx := context.Background()

	if err := store.StoreDeviceAuthorization(ctx, "cli", "dc-keep", "SCPE-0002",
		time.Now().Add(10*time.Minute), []string{"account.id", "phigros.score.read"}); err != nil {
		t.Fatal(err)
	}
	if err := store.approveDevice(ctx, "SCPE-0002", "usr_1", nil); err != nil {
		t.Fatal(err)
	}
	event := deviceApprovalEvent(t, logger)
	if event == nil {
		t.Fatal("the device approval recorded no audit event")
	}
	scopes := event.Detail["scopes"]
	for _, want := range []string{"account.id", "phigros.score.read"} {
		if !strings.Contains(scopes, want) {
			t.Errorf("granted scopes %q omit the requested %q", scopes, want)
		}
	}
}

// TestDeviceApprovalRequiresExplicitConsent pins Z20-4: the device entrance
// honours an ExplicitConsent descriptor. The control proves the probe's fixture
// can approve the same scope when it is ticked, so a refusal below is the gate
// and not a broken catalogue.
func TestDeviceApprovalRequiresExplicitConsent(t *testing.T) {
	store := deviceStore(t, registryWithDeviceCritical(t), nil,
		oauth.ScopeAccountID, deviceCriticalScope)
	ctx := context.Background()

	request := func(code string) {
		t.Helper()
		if err := store.StoreDeviceAuthorization(ctx, "cli", "dc-"+code, code,
			time.Now().Add(10*time.Minute), []string{deviceCriticalScope.String()}); err != nil {
			t.Fatal(err)
		}
	}

	// Control: with the individual tick the approval succeeds.
	request("EXPL-0001")
	if err := store.DecideDeviceAuthorization(ctx, "EXPL-0001", "usr_1", true, nil,
		[]oauth.Scope{deviceCriticalScope}); err != nil {
		t.Fatalf("control: an approval that ticked the critical scope was refused: %v", err)
	}

	// The finding P-02 predicted: the same approval with no tick is refused.
	request("EXPL-0002")
	err := store.DecideDeviceAuthorization(ctx, "EXPL-0002", "usr_1", true, nil, nil)
	if err == nil {
		t.Fatal("the device entrance approved an ExplicitConsent scope with no individual tick")
	}
	var oe *oauth.Error
	if !errors.As(err, &oe) || oe.Code != "access_denied" {
		t.Fatalf("refused for the wrong reason: %v (want access_denied)", err)
	}
	st, err := store.DeviceByUserCode(ctx, "EXPL-0002")
	if err != nil {
		t.Fatal(err)
	}
	if st.Done {
		t.Error("the refused approval was still written to the device record")
	}
}
