package vault

// Rotation visits every credential in the deployment. It walks a repo that can page
// a page at a time instead of materialising the whole vault, and these tests pin
// both halves: the page walk covers everything exactly once, and a repo that only
// implements List still rotates.

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// pagingRepo counts how it was enumerated, so a test can tell the paging path from
// the List path.
type pagingRepo struct {
	Repo
	pages  int
	listed int
}

func (r *pagingRepo) List(ctx context.Context) ([]Record, error) {
	r.listed++
	return r.Repo.List(ctx)
}

func (r *pagingRepo) ListPage(ctx context.Context, afterSubject, afterProvider string, limit int) ([]Record, error) {
	r.pages++
	return r.Repo.(RecordPager).ListPage(ctx, afterSubject, afterProvider, limit)
}

// listOnlyRepo hides ListPage, so the caller must fall back to List.
type listOnlyRepo struct {
	Repo
	listed int
}

func (r *listOnlyRepo) List(ctx context.Context) ([]Record, error) {
	r.listed++
	return r.Repo.List(ctx)
}

func TestRotateWalksPagesAndCoversEveryRecord(t *testing.T) {
	repo := &pagingRepo{Repo: NewMemoryRepo()}
	logger := audit.NewMemoryLogger()
	old := keyFor(t, "kek-1", 0xA1)
	fresh := keyFor(t, "kek-2", 0xB2)
	ctx := context.Background()

	// More records than one page, and providers and subjects varying independently
	// so the cursor has to compare both fields.
	const total = rotatePageSize + 7
	before, err := NewService(repo, old, logger)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < total; i++ {
		id := Identity{Subject: fmt.Sprintf("usr_%03d", i), Provider: fmt.Sprintf("p%d", i%3)}
		if err := before.Enroll(ctx, id, []byte("secret"), nil); err != nil {
			t.Fatal(err)
		}
	}

	after, err := NewService(repo, fresh, logger, WithRetiredKeys(old))
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := after.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rotation.Scanned != total {
		t.Fatalf("scanned = %d, want %d", rotation.Scanned, total)
	}
	if rotation.Rewrapped != total {
		t.Fatalf("rewrapped = %d, want every record moved off the retired key", rotation.Rewrapped)
	}
	if repo.pages < 2 {
		t.Fatalf("pages read = %d, want the vault walked in pages", repo.pages)
	}
	if repo.listed != 0 {
		t.Fatalf("Rotate called List %d time(s) on a repo that can page", repo.listed)
	}

	// Nothing is left on the retired key, and every secret still opens.
	for i := 0; i < total; i++ {
		id := Identity{Subject: fmt.Sprintf("usr_%03d", i), Provider: fmt.Sprintf("p%d", i%3)}
		rec, err := repo.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if rec.KEKID == old.KeyID() {
			t.Fatalf("%s is still wrapped by the retired key", id)
		}
	}
	if got := readSecret(t, after, Identity{Subject: "usr_000", Provider: "p0"}); string(got) != "secret" {
		t.Fatalf("a rotated secret does not open: %q", got)
	}
}

// A repo that cannot page still rotates: the interface is an optimisation seam,
// not a requirement.
func TestRotateFallsBackToList(t *testing.T) {
	repo := &listOnlyRepo{Repo: NewMemoryRepo()}
	logger := audit.NewMemoryLogger()
	old := keyFor(t, "kek-1", 0xA1)
	fresh := keyFor(t, "kek-2", 0xB2)
	ctx := context.Background()

	before, err := NewService(repo, old, logger)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []Identity{{Subject: "usr_1", Provider: "phigros.taptap"}, {Subject: "usr_2", Provider: "taptap"}} {
		if err := before.Enroll(ctx, id, []byte("s"), nil); err != nil {
			t.Fatal(err)
		}
	}

	after, err := NewService(repo, fresh, logger, WithRetiredKeys(old))
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := after.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rotation.Scanned != 2 || rotation.Rewrapped != 2 {
		t.Fatalf("rotation = %+v, want both records re-wrapped", rotation)
	}
	if repo.listed != 1 {
		t.Fatalf("List called %d times, want once", repo.listed)
	}
}

// The memory repo's pager must agree with its List: same order, no skips, no
// repeats.
func TestMemoryRepoPagesMatchList(t *testing.T) {
	repo := NewMemoryRepo()
	ctx := context.Background()
	for _, id := range []Identity{
		{Subject: "usr_1", Provider: "b.provider"},
		{Subject: "usr_1", Provider: "a.provider"},
		{Subject: "usr_2", Provider: "a.provider"},
		{Subject: "usr_2", Provider: "c.provider"},
		{Subject: "usr_3", Provider: "a.provider"},
	} {
		if err := repo.Put(ctx, Record{Identity: id, Version: 1, KEKID: "kek-1"}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := repo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !sort.SliceIsSorted(all, func(i, j int) bool { return identityLess(all[i].Identity, all[j].Identity) }) {
		t.Fatalf("List is not ordered by (subject, provider): %+v", all)
	}

	var seen []Record
	var afterSubject, afterProvider string
	for pages := 0; ; pages++ {
		page, err := repo.ListPage(ctx, afterSubject, afterProvider, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		if len(page) > 2 {
			t.Fatalf("page of %d records, want at most 2", len(page))
		}
		seen = append(seen, page...)
		last := page[len(page)-1]
		afterSubject, afterProvider = last.Identity.Subject, last.Identity.Provider
		if pages > len(all)+1 {
			t.Fatal("paging did not terminate")
		}
	}
	if len(seen) != len(all) {
		t.Fatalf("pages yielded %d records, want %d", len(seen), len(all))
	}
	for i := range seen {
		if seen[i].Identity != all[i].Identity {
			t.Fatalf("page order differs from List at %d: %s vs %s", i, seen[i].Identity, all[i].Identity)
		}
	}
}
