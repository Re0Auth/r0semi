// Package config holds the helpers the composition roots share: reading a TOML
// file, applying environment overrides, and resolving secrets by name.
//
// The convention it enforces is the important part: a config file never contains
// a secret. It names the environment variable that holds it, so "where does this
// key come from" stays auditable and a committed config cannot leak a credential.
package config

import (
	"cmp"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Read decodes a TOML file into out. An empty path is not an error: it means the
// process is running from the environment alone.
//
// A key the schema does not know is an error rather than a shrug. Silently
// ignoring one produces a deployment that starts with a setting the operator
// believes they typed: `dsn` instead of `dsn_env` leaves the driver empty, and the
// driver's default is memory — a durable deployment comes up ephemeral and says so
// only in a warning. The same applies to `trusted_proxies`, `expose_internal` and
// the admin allowlist. Every other configuration decision in this process fails
// closed; this one now does too.
func Read(path string, out any) error {
	if path == "" {
		return nil
	}
	//nolint:gosec // the path is the config flag from startup, never request input.
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	md, err := toml.Decode(string(raw), out)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		return fmt.Errorf("%s: unknown keys (a typo here is a setting that never takes effect): %s",
			path, strings.Join(keys, ", "))
	}
	return nil
}

// Secret resolves an environment variable by name. field names the config key,
// so a misconfiguration points at the file rather than only at the variable.
//
// The configured string itself is never repeated. The schema's contract is that
// the file names the variable holding a secret rather than the secret, so the
// mistake it invites is putting the value in the name slot — and
// "field names %q, which is not set" then printed a live KEK, client secret or
// DSN into the startup log (Z19-1). The refusal is deliberately *not* gated on
// the name's shape: a purely alphanumeric secret matches any environment-variable
// pattern, so an echo conditioned on shape would still leak. `field` names the
// position, and -print-secret-env is where a legal name is read back.
func Secret(envName, field string) (string, error) {
	if envName == "" {
		return "", fmt.Errorf("%s is required", field)
	}
	value := os.Getenv(envName)
	if value == "" {
		return "", fmt.Errorf("%s names an environment variable that is not set", field)
	}
	return value, nil
}

// FirstNonEmpty returns the first non-empty value. It is how the precedence
// "environment > file > default" is written at each call site.
func FirstNonEmpty(values ...string) string {
	return cmp.Or(values...)
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
