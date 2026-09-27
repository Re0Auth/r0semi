package memory

import (
	"context"
	"fmt"
	"testing"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
)

// subjectRequest is tokenRequest() for a named subject.
func subjectRequest(subject string) *oidcstore.AuthRequest {
	return &oidcstore.AuthRequest{ClientID: "cli", Subject: subject, Scopes: []string{"account.id"}}
}

// BenchmarkGrantsAtScale measures the account page's query with a realistic
// population: one subject's grants among many other subjects' tokens.
//
// The two populations are the point. This used to be O(every token in the
// deployment) under the store's single lock, because the maps are keyed by token
// hash and the only way to find a subject's tokens was to walk all of them — so
// the two cases below differed by the ratio of their populations. With the subject
// index the cost is O(this subject's tokens) and the two numbers are flat, which
// is what keeps the grants view and the account export independent of how many
// accounts a deployment has.
func BenchmarkGrantsAtScale(b *testing.B) {
	for _, population := range []int{100, 10_000} {
		b.Run(fmt.Sprintf("subjects=%d", population), func(b *testing.B) {
			store := clockedStore(b, newTestClock())
			ctx := context.Background()

			const tokensEach = 4
			for i := 0; i < population; i++ {
				subject := fmt.Sprintf("usr_other_%05d", i)
				for j := 0; j < tokensEach; j++ {
					if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, subjectRequest(subject), ""); err != nil {
						b.Fatal(err)
					}
				}
			}
			for j := 0; j < tokensEach; j++ {
				if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, subjectRequest("usr_me"), ""); err != nil {
					b.Fatal(err)
				}
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				grants, err := store.Grants(ctx, "usr_me")
				if err != nil {
					b.Fatal(err)
				}
				if len(grants) != 1 {
					b.Fatalf("grants = %d, want the one client", len(grants))
				}
			}
		})
	}
}
