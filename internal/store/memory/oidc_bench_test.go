package memory

import (
	"context"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// BenchmarkIntrospect measures the store call behind every authenticated /v1
// request: once the OP handler has decrypted the bearer token, this is what
// decides whether it is still live. The parallel case is the one that matters,
// because every call serialises on the store's single lock.
func BenchmarkIntrospect(b *testing.B) {
	store := clockedStore(b, newTestClock())
	ctx := context.Background()
	accessID, _, err := store.CreateAccessToken(ctx, tokenRequest())
	if err != nil {
		b.Fatal(err)
	}

	b.Run("serial", func(b *testing.B) {
		resp := new(oidc.IntrospectionResponse)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := store.SetIntrospectionFromToken(ctx, resp, accessID, "usr_1", ""); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			resp := new(oidc.IntrospectionResponse)
			for pb.Next() {
				if err := store.SetIntrospectionFromToken(ctx, resp, accessID, "usr_1", ""); err != nil {
					b.Error(err)
					return
				}
			}
		})
	})
}

// BenchmarkTokenLifecycleWithJanitor runs what a live deployment does per grant
// — mint an access and refresh token, then introspect it — while the janitor
// sweeps every sweepEvery records. The reported peak_records is the point: the
// population stays bounded by the sweep interval, not by how long the process
// has been running.
func BenchmarkTokenLifecycleWithJanitor(b *testing.B) {
	clock := newTestClock()
	store := clockedStore(b, clock)
	ctx := context.Background()
	req := tokenRequest()

	const (
		sweepEvery = 1024
		// The refresh TTL is 30 days, so 31 expires both halves of a grant and
		// guarantees the sweep has work — which is what keeps the maps flat.
		ageBy = 31 * 24 * time.Hour
	)

	peak := 0
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		accessID, _, _, err := store.CreateAccessAndRefreshTokens(ctx, req, "")
		if err != nil {
			b.Fatal(err)
		}
		if err := store.SetIntrospectionFromToken(ctx, new(oidc.IntrospectionResponse), accessID, "usr_1", ""); err != nil {
			b.Fatal(err)
		}
		if i%sweepEvery == sweepEvery-1 {
			// Sample before the sweep: that is the high-water mark a deployment
			// actually holds.
			if n := store.Counts().Records(); n > peak {
				peak = n
			}
			clock.Advance(ageBy)
			if removed := store.SweepExpired(); removed == 0 {
				b.Fatal("the janitor found nothing to remove after every record was aged past its deadline")
			}
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(peak), "peak_records")
}
