package main

import (
	"path/filepath"
	"testing"

	"github.com/Re0Auth/r0semi/internal/config"
)

// The example shipped with the repository has to decode under the real schema.
// Unknown keys are refused since the config loader was made fail-closed, so drift
// between this example and the settings struct turns into a startup failure for
// whoever copies it — the same guard cmd/re0auth has for its example.
func TestShippedExampleConfigDecodes(t *testing.T) {
	var f file
	path := filepath.Join("..", "..", "config", "referencesource.example.toml")
	if err := config.Read(path, &f); err != nil {
		t.Fatalf("the shipped example config does not match the schema: %v", err)
	}
	if f.Source.Provider == "" {
		t.Fatal("the example declares no source provider, so this guard could pass on an empty file")
	}
}
