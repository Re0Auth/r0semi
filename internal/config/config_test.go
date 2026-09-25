package config

import "testing"

// A boolean that is present but unparseable must be an error, like Float and Int:
// otherwise "RE0AUTH_COOKIE_SECURE=yes" silently uses the fallback and looks
// applied.
func TestBoolRejectsUnparseableValues(t *testing.T) {
	t.Setenv("TEST_BOOL", "")
	if v, err := Bool("TEST_BOOL", true); err != nil || v != true {
		t.Fatalf("unset = %v, %v; want the fallback", v, err)
	}
	for raw, want := range map[string]bool{"true": true, "1": true, "false": false, "0": false} {
		t.Setenv("TEST_BOOL", raw)
		got, err := Bool("TEST_BOOL", !want)
		if err != nil || got != want {
			t.Fatalf("Bool(%q) = %v, %v; want %v", raw, got, err, want)
		}
	}
	t.Setenv("TEST_BOOL", "yes")
	if _, err := Bool("TEST_BOOL", false); err == nil {
		t.Fatal("an unparseable boolean was accepted")
	}
}

func TestNumberParsersRejectUnparseableValues(t *testing.T) {
	t.Setenv("TEST_FLOAT", "50/s")
	if _, err := Float("TEST_FLOAT", 1); err == nil {
		t.Fatal("an unparseable float was accepted")
	}
	t.Setenv("TEST_INT", "many")
	if _, err := Int("TEST_INT", 1); err == nil {
		t.Fatal("an unparseable int was accepted")
	}
}
