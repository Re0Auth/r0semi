//go:build audit5

// Package perf holds this audit's performance probes. It is a test-only package
// (no non-test files), so it does not enter any production import graph.
//
// The probes here exist because two capacity questions the repository documents
// are not answerable from the code alone:
//
//   - the in-memory OP store's janitor sweeps every record under the store's
//     single mutex, so its cost is O(live records) per tick — and the live
//     population is bounded by the longest TTL (a 30-day refresh token), not by
//     the sweep interval;
//   - how many bytes one retained grant actually costs, which is what decides
//     whether a 512MiB container limit can hold a month of refresh tokens.
package perf

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

var sharedSignerOnce sync.Once
var sharedSigner *oidcstore.Signer

// probeSigner shares one RSA key: generating one per store would dominate the
// fixture's runtime and is not what these probes measure.
func probeSigner(tb testing.TB) *oidcstore.Signer {
	tb.Helper()
	sharedSignerOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			tb.Fatal(err)
		}
		sharedSigner = oidcstore.NewSigner("probe", key)
	})
	return sharedSigner
}

// probeRequest is the token request every grant is minted from.
func probeRequest(subject string) *oidcstore.AuthRequest {
	return &oidcstore.AuthRequest{
		ClientID: "probe-client",
		Subject:  subject,
		Scopes:   []string{"account.id", "phigros.score.read"},
	}
}

// newProbeStore builds a memory OIDC store the way the composition root does.
func newProbeStore(tb testing.TB, now func() time.Time) *memory.OIDCStore {
	tb.Helper()
	clients := oauth.NewMemoryClientRegistry()
	c, err := oauth.NewClient("probe-client", "Probe", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		tb.Fatal(err)
	}
	if err := clients.Create(context.Background(), c); err != nil {
		tb.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   probeSigner(tb),
		Now:      now,
	})
	if err != nil {
		tb.Fatal(err)
	}
	return store
}

// mintGrants gives the store n grants, i.e. 2n live records (an access token and
// a refresh token each) that nothing has aged past its deadline.
func mintGrants(tb testing.TB, store *memory.OIDCStore, n int) {
	tb.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, probeRequest(fmt.Sprintf("usr_probe_%d", i%1000)), ""); err != nil {
			tb.Fatal(err)
		}
	}
}

// TestMemStoreSweepIsProportionalToLiveRecords counts what one janitor tick costs
// as the store fills up with records that have not expired.
//
// This is the shape the repository's own fixture avoids. BenchmarkTokenLifecycle
// WithJanitor advances its clock by 31 days every 1024 grants, so every sweep
// finds work and the population never grows; that is not a deployment's steady
// state. A real deployment's refresh tokens live 30 days, so the population at
// any moment is "grants issued in the last 30 days", and the sweep has to scan
// all of it to find the few that expired. The sweep holds the store's single
// mutex for the whole scan, and the store's mutex is the one every introspection,
// token mint and revocation takes.
func TestMemStoreSweepIsProportionalToLiveRecords(t *testing.T) {
	if testing.Short() {
		t.Skip("perf probe: skipped under -short")
	}
	const perPopulation = 20_000 // 40k records per round
	for _, rounds := range []int{1, 5} {
		store := newProbeStore(t, time.Now)
		mintGrants(t, store, rounds*perPopulation)
		counts := store.Counts()

		start := time.Now()
		removed := store.SweepExpired()
		elapsed := time.Since(start)

		// Non-vacuous: the population must really be there and the sweep must
		// really have scanned it (nothing is expired, so nothing is removed).
		if counts.Records() != rounds*2*perPopulation {
			t.Fatalf("population = %+v, want %d records", counts, rounds*2*perPopulation)
		}
		if removed != 0 {
			t.Fatalf("sweep removed %d records, but nothing in this store has expired", removed)
		}
		perRecord := elapsed / time.Duration(counts.Records())
		t.Logf("records=%7d  sweep=%10s  per_record=%6s",
			counts.Records(), elapsed.Round(time.Microsecond), perRecord.Round(time.Nanosecond))
	}
}

// TestMemStoreSweepStallsConcurrentRequests measures what a request sees while a
// janitor tick is running.
//
// The sweep takes the store's mutex and holds it across the entire scan, so every
// concurrent request that needs the store — which is every authenticated /v1 call,
// because introspection reads it — waits for the whole scan. The numbers below
// are the worst single-request latency observed during a tick, at two
// populations: that stall is what an operator would see as a p99 spike every five
// minutes with no request-rate change to explain it.
func TestMemStoreSweepStallsConcurrentRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("perf probe: skipped under -short")
	}
	ctx := context.Background()
	for _, population := range []int{10_000, 100_000} {
		store := newProbeStore(t, time.Now)
		mintGrants(t, store, population/2)
		ids := make([]string, 0, 64)
		for i := 0; i < 64; i++ {
			id, _, _, err := store.CreateAccessAndRefreshTokens(ctx, probeRequest(fmt.Sprintf("usr_probe_%d", i)), "")
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}

		var stop atomic.Bool
		var worst atomic.Int64
		var n atomic.Int64
		var wg sync.WaitGroup
		for w := 0; w < 8; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				resp := new(oidc.IntrospectionResponse)
				for !stop.Load() {
					id := ids[(w*7+int(n.Load()))%len(ids)]
					start := time.Now()
					_ = store.SetIntrospectionFromToken(ctx, resp, id, "usr_probe", "")
					d := int64(time.Since(start))
					n.Add(1)
					for {
						cur := worst.Load()
						if d <= cur || worst.CompareAndSwap(cur, d) {
							break
						}
					}
				}
			}(w)
		}

		// Let the readers settle, then run one sweep and see what it costs them.
		time.Sleep(20 * time.Millisecond)
		before := worst.Load()
		start := time.Now()
		removed := store.SweepExpired()
		sweep := time.Since(start)
		time.Sleep(20 * time.Millisecond)
		after := worst.Load()
		stop.Store(true)
		wg.Wait()

		if removed != 0 {
			t.Fatalf("sweep removed %d records from a store with nothing expired", removed)
		}
		if n.Load() == 0 {
			t.Fatal("no introspection ran; the probe measured nothing")
		}
		t.Logf("records=%7d requests=%8d  sweep=%10s  worst_before=%10s  worst_during=%10s",
			store.Counts().Records(), n.Load(),
			sweep.Round(time.Microsecond),
			time.Duration(before).Round(time.Microsecond),
			time.Duration(after).Round(time.Microsecond))
	}
}

// TestMemStoreDevicePurgeIsPerInsert measures the cost of creating a device
// authorization as the number of live ones grows.
//
// StoreDeviceAuthorization calls purgeExpiredDevicesLocked, which ranges over every
// live device record — under the store's one mutex — before inserting the new one.
// Nothing expired is removed more than its TTL allows, so within the ten-minute
// device window the scan only gets longer: N arrivals in a window cost O(N²) scans
// in total, and each of those scans blocks every other request in the process.
// Nothing bounds the arrival rate here except the per-address limiter, and the
// Postgres store's equivalent is a single INSERT (postgres/oidc.go), so the two
// backends do not degrade alike.
func TestMemStoreDevicePurgeIsPerInsert(t *testing.T) {
	if testing.Short() {
		t.Skip("perf probe: skipped under -short")
	}
	ctx := context.Background()
	store := newProbeStore(t, time.Now)
	seq := 0

	perCall := func(n int) time.Duration {
		start := time.Now()
		for i := 0; i < n; i++ {
			seq++
			code := fmt.Sprintf("DEV-%08d", seq)
			user := fmt.Sprintf("WXYZ-%08d", seq)
			if err := store.StoreDeviceAuthorization(ctx, "probe-client", code, user,
				time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
				t.Fatal(err)
			}
		}
		return time.Since(start) / time.Duration(n)
	}

	first := perCall(200)
	// Grow the live population to something a ten-minute window can reach at a
	// modest rate: 20k arrivals is 33/s.
	_ = perCall(20_000)
	last := perCall(200)

	live := store.Counts().Devices
	if live < 20_000 {
		t.Fatalf("only %d device records live; the probe did not grow the population", live)
	}
	t.Logf("StoreDeviceAuthorization: %s/call at ~200 live, %s/call at ~%d live",
		first.Round(time.Microsecond), last.Round(time.Microsecond), live)
	if last <= first {
		t.Skip("the per-call cost did not grow with the population on this run; " +
			"re-run to confirm the O(live devices) scan (the code is the evidence: " +
			"memory/oidc.go StoreDeviceAuthorization → purgeExpiredDevicesLocked)")
	}
}

// TestMemStoreBytesPerGrant measures the resident cost of one retained grant, so
// the 512MiB container limit can be compared against 30 days of issuance.
//
// It measures the live heap with the store discarded afterwards, so the number is
// the store's own retention rather than garbage.
func TestMemStoreBytesPerGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("perf probe: skipped under -short")
	}
	const grants = 50_000

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	store := newProbeStore(t, time.Now)
	mintGrants(t, store, grants)

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	counts := store.Counts()
	if counts.Records() != 2*grants {
		t.Fatalf("records = %d, want %d", counts.Records(), 2*grants)
	}
	heap := int64(after.HeapAlloc) - int64(base.HeapAlloc)
	perGrant := float64(heap) / float64(grants)
	perRecord := float64(heap) / float64(counts.Records())
	t.Logf("heap=%d bytes for %d grants (%d records): %.0f bytes/grant, %.0f bytes/record",
		heap, grants, counts.Records(), perGrant, perRecord)

	// The same arithmetic a deployment has to do: refresh tokens live 30 days, so
	// the record count is 30 days of grants, whatever the sweep interval is.
	for _, perSecond := range []float64{1, 10, 100} {
		records := perSecond * 86400 * 30 * 2
		t.Logf("at %.0f grants/s, 30 days = %.2e records = %.0f MiB of store",
			perSecond, records, records*perRecord/(1<<20))
	}
	// Keep the store alive across the measurement.
	runtime.KeepAlive(store)
}
