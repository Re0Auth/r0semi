package federation

import (
	"net/http"
	"testing"
)

// budgetState reads the two accounting totals under the budget's own lock, so
// the tests never touch the fields unsynchronised.
func budgetState(b *bufferBudget) (held, keys int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.held, len(b.perKey)
}

// TestBufferBudgetShareIsPerCaller pins the Z09-4 property: one caller can spend
// its own share but not the whole global budget, while a second caller still has
// its own share to draw from.
//
// limit = 8 x maxBody, so share = max(2 x maxBody, limit/4) = 2 x maxBody.
func TestBufferBudgetShareIsPerCaller(t *testing.T) {
	const limit = 8 * maxBody
	b := newBufferBudget(limit)
	if b.share != 2*maxBody {
		t.Fatalf("share = %d, want %d (max(2*maxBody, limit/4))", b.share, 2*maxBody)
	}

	// One caller may fill exactly its share...
	if !b.acquire("usr_a", maxBody) {
		t.Fatal("the first half of a caller's own share was refused")
	}
	if !b.acquire("usr_a", maxBody) {
		t.Fatal("the second half of a caller's own share was refused")
	}
	// ...and no more, even though the global limit is far from full.
	if b.acquire("usr_a", 1) {
		t.Error("a caller exceeded its share while the global limit had room; the budget is still " +
			"first-come-first-served")
	}

	// A second caller is unaffected by the first caller's share.
	if !b.acquire("usr_b", maxBody) {
		t.Error("a second caller could not use its own share after a different caller filled its share")
	}

	if held, keys := budgetState(b); held != 3*maxBody || keys != 2 {
		t.Errorf("held = %d, keys = %d, want %d and 2", held, keys, 3*maxBody)
	}
	if held, _ := budgetState(b); held > limit {
		t.Errorf("held = %d exceeds the global limit %d: the invariant held <= limit is broken", held, limit)
	}
}

// TestBufferBudgetGlobalLimitStillBinds keeps the original P0-3 property: the
// global limit is what bounds total memory, even for callers each inside their
// own share.
//
// limit = 3 x maxBody, so share = 2 x maxBody and the global limit binds first.
func TestBufferBudgetGlobalLimitStillBinds(t *testing.T) {
	const limit = 3 * maxBody
	b := newBufferBudget(limit)
	if !b.acquire("usr_a", 2*maxBody) {
		t.Fatal("a caller was refused within both its share and the global limit")
	}
	if !b.acquire("usr_b", maxBody) {
		t.Fatal("a second caller was refused within both its share and the global limit")
	}
	if held, _ := budgetState(b); held != limit {
		t.Fatalf("held = %d, want the global limit %d", held, limit)
	}
	if b.acquire("usr_c", 1) {
		t.Error("a third caller was admitted with the global limit already full")
	}
}

// TestBufferBudgetReleaseRestoresAndEmptiesTheMap pins the release half: bytes
// come back to both counters and the per-caller entry is deleted at zero, so the
// map holds only callers with a live reservation.
func TestBufferBudgetReleaseRestoresAndEmptiesTheMap(t *testing.T) {
	b := newBufferBudget(8 * maxBody)

	if !b.acquire("usr_a", maxBody) {
		t.Fatal("acquire refused")
	}
	if held, keys := budgetState(b); held != maxBody || keys != 1 {
		t.Fatalf("after acquire: held = %d, keys = %d, want %d and 1", held, keys, maxBody)
	}

	b.release("usr_a", maxBody)
	if held, keys := budgetState(b); held != 0 || keys != 0 {
		t.Fatalf("after release: held = %d, keys = %d, want 0 and 0 (the key entry must be deleted at zero)",
			held, keys)
	}

	// The released share is available again.
	if !b.acquire("usr_a", 2*maxBody) {
		t.Error("a caller could not reuse its share after releasing it")
	}
	b.release("usr_a", 2*maxBody)
	if held, keys := budgetState(b); held != 0 || keys != 0 {
		t.Fatalf("after second release: held = %d, keys = %d, want 0 and 0", held, keys)
	}

	// A release without its acquire must not hand out budget that was never
	// reserved, nor panic on a key the map has never seen.
	b.release("usr_never_seen", 5)
	if held, keys := budgetState(b); held != 0 || keys != 0 {
		t.Errorf("a stray release drifted the counters: held = %d, keys = %d, want 0 and 0", held, keys)
	}
}

// TestBufferBudgetNilAndZeroRefuse preserves the fail-closed behaviour: a budget
// that was never constructed, or constructed with a zero limit, admits nothing.
// "No budget" must not read as "unbounded".
func TestBufferBudgetNilAndZeroRefuse(t *testing.T) {
	var nilBudget *bufferBudget
	if nilBudget.acquire("usr_a", 1) {
		t.Error("a nil budget admitted a read; nil must fail closed")
	}
	nilBudget.release("usr_a", 1) // must not panic

	zero := newBufferBudget(0)
	if zero.acquire("usr_a", 1) {
		t.Error("a zero-limit budget admitted a read")
	}
	if held, keys := budgetState(zero); held != 0 || keys != 0 {
		t.Errorf("a refused acquire changed the counters: held = %d, keys = %d", held, keys)
	}

	// A limit below the share floor still refuses globally at the limit.
	small := newBufferBudget(maxBody / 2)
	if small.share != 2*maxBody {
		t.Fatalf("share = %d, want the 2*maxBody floor even below it", small.share)
	}
	if small.acquire("usr_a", maxBody) {
		t.Error("a read larger than the global limit was admitted because it fit the share floor")
	}
	if !small.acquire("usr_a", 1) {
		t.Error("a read inside the global limit was refused")
	}
}

// TestBufferBudgetShareFormula states the sizing rule, including the shipped
// default: max(2 x maxBody, limit/4).
func TestBufferBudgetShareFormula(t *testing.T) {
	cases := []struct {
		limit int
		want  int
	}{
		{defaultMaxBufferedBytes, defaultMaxBufferedBytes / 4}, // 64 MiB -> 16 MiB
		{100 << 20, 25 << 20},  // limit/4 wins
		{4 << 20, 2 * maxBody}, // the 2*maxBody floor wins
		{maxBody, 2 * maxBody}, // floor above the limit
		{0, 2 * maxBody},       // floor, though acquires refuse
	}
	for _, tc := range cases {
		if got := bufferShare(tc.limit); got != tc.want {
			t.Errorf("bufferShare(%d) = %d, want %d", tc.limit, got, tc.want)
		}
		if got := newBufferBudget(tc.limit).share; got != tc.want {
			t.Errorf("newBufferBudget(%d).share = %d, want %d", tc.limit, got, tc.want)
		}
	}
}

// TestReserveFor pins what one read must hold: the cap it reads to, or one byte
// past a smaller declared length — and the cap when the declaration says nothing
// (zero or negative, the zero value of a hand-built response and a chunked body).
func TestReserveFor(t *testing.T) {
	cases := []struct {
		name     string
		declared int64
		readCap  int
		want     int
	}{
		{"smaller declaration reserves one past it", 100, 4 << 20, 101},
		{"declaration at the cap reserves the cap", 4 << 20, 4 << 20, 4 << 20},
		{"declaration over the cap reserves the cap", (4 << 20) + 1, 4 << 20, 4 << 20},
		{"zero declaration reserves the cap", 0, 4 << 20, 4 << 20},
		{"negative declaration reserves the cap", -1, 4 << 20, 4 << 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{ContentLength: tc.declared}
			if got := reserveFor(resp, tc.readCap); got != tc.want {
				t.Errorf("reserveFor(declared=%d, cap=%d) = %d, want %d",
					tc.declared, tc.readCap, got, tc.want)
			}
		})
	}
}
