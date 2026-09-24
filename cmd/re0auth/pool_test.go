package main

import (
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/store/postgres"
)

func TestResolvePoolDefaults(t *testing.T) {
	got, err := resolvePool(storageSection{})
	if err != nil {
		t.Fatal(err)
	}
	defaults := postgres.DefaultPoolOptions()
	want := poolSettings{
		MaxConns:         defaults.MaxConns,
		MinConns:         defaults.MinConns,
		ConnectTimeout:   defaults.ConnectTimeout,
		StatementTimeout: defaults.StatementTimeout,
	}
	if got != want {
		t.Fatalf("resolvePool(empty) = %+v, want the defaults %+v", got, want)
	}
}

func TestResolvePoolFileOverrides(t *testing.T) {
	maxConns, minConns := 32, 8
	connect, statement := "3s", "10s"

	got, err := resolvePool(storageSection{
		MaxConns:         &maxConns,
		MinConns:         &minConns,
		ConnectTimeout:   &connect,
		StatementTimeout: &statement,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxConns != 32 || got.MinConns != 8 {
		t.Errorf("connections = %d/%d, want 32/8", got.MaxConns, got.MinConns)
	}
	if got.ConnectTimeout != 3*time.Second || got.StatementTimeout != 10*time.Second {
		t.Errorf("timeouts = %v/%v, want 3s/10s", got.ConnectTimeout, got.StatementTimeout)
	}
}

// The whole file promises environment > file > default; the pool settings are no
// exception, or a deployment that configures by environment alone could not size
// its pool.
func TestResolvePoolEnvironmentOverridesTheFile(t *testing.T) {
	maxConns := 4
	t.Setenv("RE0AUTH_STORAGE_MAX_CONNS", "64")
	t.Setenv("RE0AUTH_STORAGE_STATEMENT_TIMEOUT", "1m")

	got, err := resolvePool(storageSection{MaxConns: &maxConns})
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxConns != 64 {
		t.Errorf("MaxConns = %d, want the environment's 64 to beat the file's 4", got.MaxConns)
	}
	if got.StatementTimeout != time.Minute {
		t.Errorf("StatementTimeout = %v, want 1m", got.StatementTimeout)
	}
}

// "0s" is how a deployment says "apply no statement timeout" — distinguished from
// absent, which takes the default. Both mean something; neither is a typo.
func TestResolvePoolZeroDisablesTheStatementTimeout(t *testing.T) {
	statement := "0s"

	got, err := resolvePool(storageSection{StatementTimeout: &statement})
	if err != nil {
		t.Fatal(err)
	}
	if got.StatementTimeout != 0 {
		t.Fatalf("StatementTimeout = %v, want 0 (leave the server's setting alone)", got.StatementTimeout)
	}

	// Absent is not the same value: it takes the default.
	byDefault, err := resolvePool(storageSection{})
	if err != nil {
		t.Fatal(err)
	}
	if byDefault.StatementTimeout == 0 {
		t.Fatal("an absent statement_timeout fell back to zero instead of the default")
	}
}

// Contradictions and typos refuse startup rather than being clamped into
// something runnable that the operator did not choose.
func TestResolvePoolRejectsContradictions(t *testing.T) {
	zero, negative := 0, -1
	maxConns, bigMin := 4, 9
	unparseable := "30 seconds"
	negativeTimeout := "-1s"

	cases := map[string]storageSection{
		"max_conns of zero":           {MaxConns: &zero},
		"negative min_conns":          {MinConns: &negative},
		"min_conns above max_conns":   {MaxConns: &maxConns, MinConns: &bigMin},
		"unparseable connect_timeout": {ConnectTimeout: &unparseable},
		"negative statement_timeout":  {StatementTimeout: &negativeTimeout},
	}
	for name, section := range cases {
		if _, err := resolvePool(section); err == nil {
			t.Errorf("%s was accepted; it must refuse startup", name)
		}
	}
}

func TestResolvePoolRejectsUnparseableEnvironment(t *testing.T) {
	t.Setenv("RE0AUTH_STORAGE_MAX_CONNS", "many")

	if _, err := resolvePool(storageSection{}); err == nil {
		t.Fatal("a non-numeric RE0AUTH_STORAGE_MAX_CONNS was accepted")
	}
}

func TestParseDuration(t *testing.T) {
	if d, err := parseDuration(" 5s ", "x"); err != nil || d != 5*time.Second {
		t.Fatalf("parseDuration(\" 5s \") = %v, %v; want 5s", d, err)
	}
	if _, err := parseDuration("30 seconds", "storage.connect_timeout"); err == nil {
		t.Fatal("a duration with an unparseable unit was accepted")
	}
}
