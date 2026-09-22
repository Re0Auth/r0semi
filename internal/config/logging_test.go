package config

import (
	"io"
	"log/slog"
	"testing"
)

func TestSetupLoggingAcceptsTheDocumentedValues(t *testing.T) {
	for _, tc := range []struct{ level, format string }{
		{"", ""},
		{"info", "text"},
		{"DEBUG", "JSON"},
		{"warn", ""},
		{"error", "json"},
	} {
		t.Setenv("TEST_LOG_LEVEL", tc.level)
		t.Setenv("TEST_LOG_FORMAT", tc.format)
		if err := SetupLogging("TEST"); err != nil {
			t.Errorf("level=%q format=%q: %v", tc.level, tc.format, err)
		}
	}
	// Leave the default logger pointing somewhere harmless for whatever runs after
	// this test, rather than at whatever the last sub-test installed.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// A malformed value is an error rather than a silent fallback, for the same
// reason RE0AUTH_RATE_LIMIT is: a setting that looks applied and is not is worse
// than one that refuses to start.
func TestSetupLoggingRefusesUnknownValues(t *testing.T) {
	t.Setenv("TEST_LOG_LEVEL", "verbose")
	t.Setenv("TEST_LOG_FORMAT", "")
	if err := SetupLogging("TEST"); err == nil {
		t.Error("an unknown level was accepted")
	}

	t.Setenv("TEST_LOG_LEVEL", "")
	t.Setenv("TEST_LOG_FORMAT", "logfmt")
	if err := SetupLogging("TEST"); err == nil {
		t.Error("an unknown format was accepted")
	}
}
