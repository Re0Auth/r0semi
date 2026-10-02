package vault

// The memory repo's pager must be a bounded read. Its ordered index is what buys
// that: the cursor is located by binary search and only the page's own rows are
// copied. This probe pins the cost so a future ListPage that falls back to
// materialising (and re-sorting) the whole table -- the O(N^2 log N) shape -- fails
// instead of merely being slower.

import (
	"context"
	"fmt"
	"testing"
)

// TestMemoryRepoListPageDoesNotRescanWholeTable walks a table several pages long and
// asserts the pager copied each row once. rowsCopied counts every row List and
// ListPage materialise, so a pager that rescanned through List would be charged for
// the whole table on every page and blow the budget by orders of magnitude.
func TestMemoryRepoListPageDoesNotRescanWholeTable(t *testing.T) {
	repo := NewMemoryRepo()
	ctx := context.Background()
	const (
		total = 1200
		limit = 25
	)
	for i := 0; i < total; i++ {
		// Subjects and providers vary independently so the cursor has to compare
		// both fields, exactly as the rotate walk does.
		id := Identity{Subject: fmt.Sprintf("usr_%04d", i), Provider: fmt.Sprintf("p%d", i%5)}
		if err := repo.Put(ctx, Record{Identity: id, Version: 1, KEKID: "kek-1"}); err != nil {
			t.Fatal(err)
		}
	}

	// Measure only the page walk, not the fixture load.
	repo.rowsCopied.Store(0)

	var (
		seen          int
		afterSubject  string
		afterProvider string
	)
	for pages := 0; ; pages++ {
		page, err := repo.ListPage(ctx, afterSubject, afterProvider, limit)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		if len(page) > limit {
			t.Fatalf("page of %d records, want at most %d", len(page), limit)
		}
		seen += len(page)
		last := page[len(page)-1]
		afterSubject, afterProvider = last.Identity.Subject, last.Identity.Provider
		if pages > total+2 {
			t.Fatal("paging did not terminate")
		}
	}
	if seen != total {
		t.Fatalf("pages yielded %d records, want %d", seen, total)
	}

	// One copy per row, total. A per-page full rescan would copy total*(total/limit)
	// = 57,600 rows here -- the N^2/log N shape this is guarding against.
	if copied := repo.rowsCopied.Load(); copied != total {
		t.Fatalf("paging %d records in pages of %d copied %d rows, want %d: the pager is rescanning the whole table per page",
			total, limit, copied, total)
	}
}
