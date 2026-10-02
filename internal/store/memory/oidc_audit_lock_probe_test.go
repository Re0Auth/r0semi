package memory

// S13-4: the device approve/deny audit write used to run inside the store's
// single critical section. audit.Logger.Record is synchronous by contract (a
// durable deployment appends to Postgres), so holding the lock across it made
// every other store call wait behind the sink.
//
// These probes are expressed as "while the sink is blocked inside Record, can the
// store answer another call?". Before the fix the answer was no; after it, yes.
// The sink is blocked rather than delayed so the probe cannot pass on timing.

import (
	"context"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/oauth"
)

// blockingAudit blocks inside Record until the test releases it.
type blockingAudit struct {
	entered chan struct{}
	release chan struct{}
}

func newBlockingAudit() *blockingAudit {
	return &blockingAudit{entered: make(chan struct{}, 1), release: make(chan struct{})}
}

func (b *blockingAudit) Record(context.Context, audit.Event) error {
	b.entered <- struct{}{}
	<-b.release
	return nil
}

// storeWithAudit builds the usual test store with an injectable sink.
func storeWithAudit(t *testing.T, logger audit.Logger) *OIDCStore {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	c, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	store, err := NewOIDCStore(OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   signerForTests(t),
		Audit:    logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// assertLockFreeDuringAudit runs op, waits until its audit write is in flight,
// and then asks the store for something that needs its lock. The probe fails if
// that second call cannot complete while the sink is still blocked.
func assertLockFreeDuringAudit(t *testing.T, store *OIDCStore, log *blockingAudit, op func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- op() }()

	select {
	case <-log.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the audit sink was never reached; the probe measured nothing")
	}

	answered := make(chan struct{})
	go func() {
		_ = store.Counts()
		close(answered)
	}()
	select {
	case <-answered:
	case <-time.After(2 * time.Second):
		close(log.release)
		<-done
		t.Fatal("the store lock is held across the audit write: another store call could not proceed while the sink was blocked (S13-4)")
	}

	close(log.release)
	if err := <-done; err != nil {
		t.Fatalf("op: %v", err)
	}
}

func TestApproveDeviceAuditsOutsideTheStoreLock(t *testing.T) {
	log := newBlockingAudit()
	store := storeWithAudit(t, log)
	ctx := context.Background()
	if err := store.StoreDeviceAuthorization(ctx, "cli", "dc-lock-1", "LOCK-0001",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	assertLockFreeDuringAudit(t, store, log, func() error {
		return store.approveDevice(ctx, "LOCK-0001", "usr_1", nil)
	})
}

func TestDenyDeviceAuditsOutsideTheStoreLock(t *testing.T) {
	log := newBlockingAudit()
	store := storeWithAudit(t, log)
	ctx := context.Background()
	if err := store.StoreDeviceAuthorization(ctx, "cli", "dc-lock-2", "LOCK-0002",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	assertLockFreeDuringAudit(t, store, log, func() error {
		return store.DenyDevice(ctx, "LOCK-0002", "usr_1")
	})
}
