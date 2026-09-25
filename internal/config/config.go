// Package config holds the helpers the composition roots share: reading a TOML
// file, applying environment overrides, and resolving secrets by name.
//
// The convention it enforces is the important part: a config file never contains
// a secret. It names the environment variable that holds it, so "where does this
// key come from" stays auditable and a committed config cannot leak a credential.
package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"
)

// Read decodes a TOML file into out. An empty path is not an error: it means the
// process is running from the environment alone.
func Read(path string, out any) error {
	if path == "" {
		return nil
	}
	//nolint:gosec // the path is the config flag from startup, never request input.
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := toml.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// Secret resolves an environment variable by name. field names the config key,
// so a misconfiguration points at the file rather than only at the variable.
func Secret(envName, field string) (string, error) {
	if envName == "" {
		return "", fmt.Errorf("%s is required", field)
	}
	value := os.Getenv(envName)
	if value == "" {
		return "", fmt.Errorf("%s names %q, which is not set", field, envName)
	}
	return value, nil
}

// FirstNonEmpty returns the first non-empty value. It is how the precedence
// "environment > file > default" is written at each call site.
func FirstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// Bool reads a boolean environment variable, falling back when it is unset.
//
// A value that is present but not a boolean is an error, on the same terms as
// Float and Int: "RE0AUTH_COOKIE_SECURE=yes" otherwise runs with whatever the
// file said and looks applied while it is not.
func Bool(key string, fallback bool) (bool, error) {
	switch raw := os.Getenv(key); raw {
	case "":
		return fallback, nil
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("%s=%q is not a boolean (true/false/1/0)", key, raw)
	}
}

// Float reads a numeric environment variable, falling back when it is unset.
//
// Unlike Bool, a value that is present but unparseable is an error rather than a
// silent fallback. "RE0AUTH_RATE_LIMIT=50/s" is a typo, and quietly running with
// a different limit than the operator wrote is how a setting that looks applied
// turns out not to be.
func Float(key string, fallback float64) (float64, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a number", key, raw)
	}
	return v, nil
}

// Int reads an integer environment variable, on the same terms as Float.
func Int(key string, fallback int) (int, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not an integer", key, raw)
	}
	return v, nil
}

// Path picks the config file: the flag, then the environment variable, then the
// default path if it exists. explicit reports whether a specific file was asked
// for, so a missing explicit file can be a hard error rather than a silent
// fallback to the environment.
func Path(flagValue, envKey, defaultPath string) (path string, explicit bool) {
	if flagValue != "" {
		return flagValue, true
	}
	if fromEnv := os.Getenv(envKey); fromEnv != "" {
		return fromEnv, true
	}
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath, false
	}
	return "", false
}
