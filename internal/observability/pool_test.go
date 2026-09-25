package observability

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakePoolStats is a PoolStats the collector test drives without a database. Its
// distinct values make the mapping testable: a mis-wired field (idle read as
// acquired) shows up as a wrong number rather than a passing test.
type fakePoolStats struct{}

func (fakePoolStats) TotalConns() int32              { return 3 }
func (fakePoolStats) IdleConns() int32               { return 1 }
func (fakePoolStats) AcquiredConns() int32           { return 2 }
func (fakePoolStats) MaxConns() int32                { return 16 }
func (fakePoolStats) AcquireCount() int64            { return 100 }
func (fakePoolStats) EmptyAcquireCount() int64       { return 4 }
func (fakePoolStats) CanceledAcquireCount() int64    { return 1 }
func (fakePoolStats) NewConnsCount() int64           { return 7 }
func (fakePoolStats) AcquireDuration() time.Duration { return 2 * time.Second }

// The pool collector must produce the re0auth_db_pool_* series the dashboard and
// rules read. The names are this package's contract, so the mapping is asserted
// against a fake rather than a live pool.
func TestPoolCollectorExportsMetrics(t *testing.T) {
	m := New()
	if err := m.RegisterPoolStats(func() PoolStats { return fakePoolStats{} }); err != nil {
		t.Fatal(err)
	}

	got := make(map[string]float64)
	for _, line := range strings.Split(scrape(t, m), "\n") {
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "re0auth_db_pool_") {
			continue
		}
		name, value, _ := strings.Cut(line, " ")
		name, _, _ = strings.Cut(name, "{")
		v, err := strconv.ParseFloat(value, 64)
		if err != nil {
			continue
		}
		got[name] = v
	}

	want := map[string]float64{
		"re0auth_db_pool_total_conns":                    3,
		"re0auth_db_pool_idle_conns":                     1,
		"re0auth_db_pool_acquired_conns":                 2,
		"re0auth_db_pool_max_conns":                      16,
		"re0auth_db_pool_acquire_count_total":            100,
		"re0auth_db_pool_empty_acquire_count_total":      4,
		"re0auth_db_pool_canceled_acquire_count_total":   1,
		"re0auth_db_pool_new_conns_count_total":          7,
		"re0auth_db_pool_acquire_duration_seconds_total": 2,
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("%s = %v, want %v (exported: %v)", name, got[name], value, got)
		}
	}
}
