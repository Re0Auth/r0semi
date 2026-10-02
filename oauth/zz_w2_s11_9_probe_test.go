package oauth

import (
	"context"
	"encoding/base64"
	"errors"
	"sort"
	"testing"
)

// W2 S11-9 probe: GET /v1/admin/clients must be genuinely pageable.
//
// Before the fix, ClientAdmin.List returned every row in one call, so a
// deployment with many clients answered an unbounded response and a caller had
// no way to ask for less. The memory registry's page arithmetic is pinned here;
// the HTTP layer's parameter handling and the Postgres statement are pinned by
// their own probes, and the cursor encoding is this file's first assertion
// because both stores share it.
func TestW2S119ListClientsPagesByCursor(t *testing.T) {
	ctx := context.Background()

	// The cursor is opaque but reversible by this package; a value round-trips,
	// and one this package did not write is refused rather than misread.
	if got, err := DecodeClientCursor(EncodeClientCursor("cli_x")); err != nil || got != "cli_x" {
		t.Fatalf("cursor round trip = %q (%v), want cli_x", got, err)
	}
	for _, bad := range []string{
		"!!!not-base64!!!",
		base64.RawURLEncoding.EncodeToString([]byte("other-endpoint:cli_x")),
		base64.RawURLEncoding.EncodeToString([]byte(clientCursorPrefix)), // prefix but no key
	} {
		if _, err := DecodeClientCursor(bad); !errors.Is(err, ErrInvalidClientCursor) {
			t.Errorf("DecodeClientCursor(%q) = %v, want ErrInvalidClientCursor", bad, err)
		}
	}

	reg := NewMemoryClientRegistry()
	// Inserted out of order on purpose: the listing must be ordered by id, not by
	// map iteration order.
	ids := []string{"cli_c", "cli_a", "cli_e", "cli_b", "cli_d"}
	for _, id := range ids {
		if err := reg.Create(ctx, testClient(t, id)); err != nil {
			t.Fatal(err)
		}
	}

	// The limit is honoured: the registry never returns more than it was asked
	// for, and a page smaller than the table still reports that there is more.
	page1, cursor1, err := reg.ListClients(ctx, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page1) != 2 {
		t.Fatalf("page 1 returned %d rows for limit 2: %+v", len(page1), page1)
	}
	if cursor1 == "" {
		t.Fatal("page 1 reported no next cursor although rows remain")
	}

	page2, cursor2, err := reg.ListClients(ctx, 2, cursor1)
	if err != nil {
		t.Fatal(err)
	}
	page3, cursor3, err := reg.ListClients(ctx, 2, cursor2)
	if err != nil {
		t.Fatal(err)
	}
	if cursor3 != "" {
		t.Errorf("the last page carried a next cursor: %q", cursor3)
	}

	// A round trip loses nothing, repeats nothing, and keeps the ascending order
	// the contract promises.
	var seen []string
	for _, page := range [][]Client{page1, page2, page3} {
		for _, c := range page {
			seen = append(seen, c.ID)
		}
	}
	want := append([]string(nil), ids...)
	sort.Strings(want)
	if len(seen) != len(want) {
		t.Fatalf("paging returned %d rows, want %d: %v", len(seen), len(want), seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("paging order = %v, want %v (sorted, no repeats, no gaps)", seen, want)
		}
	}

	// Resuming at the cursor of a deleted row still makes progress: the page
	// starts strictly after the named key, so no row is returned twice.
	if _, _, err := reg.ListClients(ctx, 2, EncodeClientCursor("cli_b")); err != nil {
		t.Fatal(err)
	}
	tail, _, err := reg.ListClients(ctx, 10, EncodeClientCursor("cli_b"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range tail {
		if c.ID <= "cli_b" {
			t.Errorf("a page after cli_b returned %s, which is not strictly later", c.ID)
		}
	}
	if len(tail) != 3 {
		t.Errorf("the tail after cli_b has %d rows, want 3", len(tail))
	}

	// 0 means "the caller did not ask": the default page, not an error. Anything
	// outside the documented range is refused, never silently clamped — a caller
	// that asked for 1000 and got 100 would read the short page as the end.
	if page, _, err := reg.ListClients(ctx, 0, ""); err != nil || len(page) != len(ids) {
		t.Fatalf("default limit page = %d rows (%v), want %d", len(page), err, len(ids))
	}
	if _, err := ResolveClientPageLimit(0); err != nil || DefaultClientPageSize < 1 {
		t.Fatalf("the default limit is not usable: %v", err)
	}
	for _, bad := range []int{-1, MaxClientPageSize + 1} {
		if _, _, err := reg.ListClients(ctx, bad, ""); !errors.Is(err, ErrInvalidClientLimit) {
			t.Errorf("ListClients(limit=%d) = %v, want ErrInvalidClientLimit", bad, err)
		}
	}
	if _, _, err := reg.ListClients(ctx, 1, "!!!not-base64!!!"); !errors.Is(err, ErrInvalidClientCursor) {
		t.Errorf("ListClients with a bogus cursor = %v, want ErrInvalidClientCursor", err)
	}
}
