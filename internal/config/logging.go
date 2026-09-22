package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// SetupLogging installs the process's default slog logger.
//
// # Why this is not the audit trail
//
// Operational logging and the audit record stay separate on purpose. Audit events
// are a domain record with an integrity requirement, written through
// audit.Logger; these are diagnostics for whoever is running the process. Merging
// them would mean the audit record inherits whatever level an operator lowered to
// quiet a noisy deployment.
//
// # Why the environment and not the config file
//
// Level and format describe where the process runs — a terminal, or a collector
// that wants JSON — rather than what the process is. Every deployment of the same
// binary may differ, which is the rule this project uses to decide.
//
// prefix names the variables: "RE0AUTH" means RE0AUTH_LOG_LEVEL and
// RE0AUTH_LOG_FORMAT. A value that is present but unrecognised is an error rather
// than a silent default, for the same reason a malformed number is: quietly
// logging at a level other than the one written is how a setting that looks
// applied turns out not to be.
func SetupLogging(prefix string) error {
	levelKey, formatKey := prefix+"_LOG_LEVEL", prefix+"_LOG_FORMAT"

	level, err := parseLevel(levelKey, os.Getenv(levelKey))
	if err != nil {
		return err
	}
	format, err := parseFormat(formatKey, os.Getenv(formatKey))
	if err != nil {
		return err
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
	return nil
}

func parseLevel(key, value string) (slog.Level, error) {
	switch strings.ToLower(value) {
	case "", "info":
		// Info by default: warnings and errors are what an operator must not miss,
		// and debug is for whoever is already looking for something.
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("%s=%q must be debug, info, warn or error", key, value)
	}
}

func parseFormat(key, value string) (string, error) {
	switch strings.ToLower(value) {
	case "", "text":
		return "text", nil
	case "json":
		return "json", nil
	default:
		return "", fmt.Errorf("%s=%q must be text or json", key, value)
	}
}
