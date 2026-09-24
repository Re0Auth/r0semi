package oidchttp

import (
	"context"
	"testing"
)

// BenchmarkIntrospectHandler measures the call the business plane makes for
// every authenticated request: decrypt the bearer token, then ask the store
// whether it is still live. It is deliberately not an HTTP round trip — Re0Auth
// is both the authorization server and the resource server, so /v1 calls this
// method directly and the network never enters the hot path.
func BenchmarkIntrospectHandler(b *testing.B) {
	f := newFixture(b)
	tokens := codeFlow(b, f, []string{"account.id", "phigros.score.read"})
	access, _ := tokens["access_token"].(string)
	if access == "" {
		b.Fatal("the code flow returned no access token")
	}
	ctx := context.Background()
	h := f.handler

	b.Run("serial", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			info, err := h.Introspect(ctx, access)
			if err != nil || !info.Active {
				b.Fatalf("introspect: err=%v active=%v", err, info.Active)
			}
		}
	})

	b.Run("parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				info, err := h.Introspect(ctx, access)
				if err != nil || !info.Active {
					b.Error("introspect failed")
					return
				}
			}
		})
	})
}
