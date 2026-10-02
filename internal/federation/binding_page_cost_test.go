package federation

// The memory binding store's deployment-wide pager must be a bounded read. Its
// ordered index is what buys that: the cursor is located by binary search and only
// the page's own rows are copied. This probe pins the cost so a future ListAllPage
// that falls back to materialising (and re-sorting) the whole table -- the
// O(N^2 log N) shape -- fails instead of merely being slower.

import (
	"context"
	"fmt"
	"testing"

	"github.com/Re0Auth/r0semi/internal/account"
)

// TestMemoryBindingStoreListAllPageDoesNotRescanWholeTable walks a table several
// pages long and asserts the pager copied each row once. rowsCopied counts every row
// ListAll and ListAllPage materialise, so a pager that rescanned through ListAll
// would be charged for the whole table on every page and blow the budget by orders
// of magnitude.
func TestMemoryBindingStoreListAllPageDoesNotRescanWholeTable(t *testing.T) {
	store := NewMemoryBindingStore()
	ctx := context.Background()
	const (
		total = 1200
		limit = 25
	)
	for i := 0; i < total; i++ {
		// Users, games and sources vary independently so the cursor has to compare
		// all three fields, exactly as the Kill Switch sweep does.
		b := Binding{
			User:    account.UserID(fmt.Sprintf("usr_%04d", i%40)),
			Game:    fmt.Sprintf("game_%d", i%3),
			Source:  fmt.Sprintf("src_%d", i%7),
			Version: 1,
		}
		if err := store.Put(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	// A handful of keys collide above; the live rows are fewer than total.
	all, err := store.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := len(all)

	// Measure only the page walk, not the fixture load.
	store.rowsCopied.Store(0)

	var (
		seen        int
		afterUser   string
		afterGame   string
		afterSource string
	)
	for pages := 0; ; pages++ {
		page, err := store.ListAllPage(ctx, afterUser, afterGame, afterSource, limit)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		if len(page) > limit {
			t.Fatalf("page of %d bindings, want at most %d", len(page), limit)
		}
		seen += len(page)
		last := page[len(page)-1]
		afterUser, afterGame, afterSource = string(last.User), last.Game, last.Source
		if pages > total+2 {
			t.Fatal("paging did not terminate")
		}
	}
	if seen != want {
		t.Fatalf("pages yielded %d bindings, want %d", seen, want)
	}

	// One copy per row, total. A per-page full rescan would copy want*(want/limit)
	// rows here -- the N^2/log N shape this is guarding against.
	if copied := store.rowsCopied.Load(); copied != int64(want) {
		t.Fatalf("paging %d bindings in pages of %d copied %d rows, want %d: the pager is rescanning the whole table per page",
			want, limit, copied, want)
	}
}
