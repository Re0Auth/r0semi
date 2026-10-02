//go:build audit7

// Z12-5: -migrate-down runs the whole serving-time loader before it can roll a
// migration back.
package z12configstartupobservability

import (
	"strings"
	"testing"
)

// Z12-5 — 原为发现演示，现为回归守卫.
//
// The finding was that -migrate-down ran the whole serving-time loader before it
// could roll a migration back, so the rollback command was refused unless every
// serving-time secret was in place — including the audit chain key, which the
// rollback path never touches.
//
// cmd/re0auth/config.go:646-670 now gives the command its own narrow loader
// (loadMigrateConfig): it resolves only the DSN and the pool, through the same
// helpers loadConfig uses, and ignores the serving-time secrets the rollback does
// not read. main.go:405-407 routes -migrate-down through it.
//
// The guard asserts that a rollback with no audit chain key still reaches the
// database, and — so the guard is not vacuous — that the SAME environment is still
// refused at the config stage for a normal serving start, i.e. the audit key is
// genuinely required where it is used and only the rollback path is narrower.
//
// The probe measures the stage that refuses; an unreachable-but-well-formed DSN
// makes the run die on the connection instead.
func TestZ12MigrateDownRequiresTheServingTimeSecrets(t *testing.T) {
	base := map[string]string{
		"RE0AUTH_ISSUER":                  "https://re0auth.test",
		"RE0AUTH_COOKIE_SECURE":           "true",
		"RE0AUTH_KEK":                     key32("Z12-MIGRATE-KEK-MATERIAL-32-A!"),
		"RE0AUTH_STORAGE_DRIVER":          "postgres",
		"RE0AUTH_STORAGE_CONNECT_TIMEOUT": "1s",
		"DATABASE_URL":                    "postgres://z12u:z12p@127.0.0.1:1/z12db?sslmode=disable",
	}
	with := func(extra map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	path := writeConfig(t, "migrate.toml", serverOnly)

	// Anti-vacuity: the same environment really is missing a secret the serving
	// path needs, so "reached the database without it" is meaningful. Without the
	// audit key a normal start is refused by the serving-time loader.
	serving := runBinary(t, with(nil), "-config", path)
	if !strings.Contains(serving.out, "stage=config") ||
		!strings.Contains(serving.out, "RE0AUTH_AUDIT_KEY") {
		t.Fatalf("anti-vacuity: a serving start without RE0AUTH_AUDIT_KEY was not refused at the "+
			"config stage, so this probe's subject environment proves nothing:\n%s", serving.out)
	}

	// Control: with the chain key present the rollback runs and dies on the
	// unreachable database — i.e. the command really does reach MigrateDown.
	ctrl := runBinary(t, with(map[string]string{
		"RE0AUTH_AUDIT_KEY": key32("Z12-MIGRATE-AUDIT-KEY-32-AA!!"),
	}), "-config", path, "-migrate-down")
	if !strings.Contains(ctrl.out, "stage=migrate-down") {
		t.Fatalf("control failed: with the audit key present, -migrate-down never reached the "+
			"database:\n%s", ctrl.out)
	}

	// Subject: the same rollback, without the audit chain key. Nothing on the
	// rollback path reads the chain, so the narrow loader must let it through to
	// MigrateDown rather than refuse it at stage=config.
	got := runBinary(t, with(nil), "-config", path, "-migrate-down")
	if strings.Contains(got.out, "stage=config") {
		t.Errorf("-migrate-down was refused by the configuration loader (exit=%d) over a key the "+
			"rollback never uses: %s. loadMigrateConfig (config.go:646-670) must resolve only the DSN "+
			"and the pool, so an operator recovering from a bad migration is not blocked on every "+
			"serving-time secret", got.code, oneLine(got.out))
	}
	if !strings.Contains(got.out, "stage=migrate-down") {
		t.Errorf("-migrate-down did not reach the database without the audit key (exit=%d):\n%s",
			got.code, oneLine(got.out))
	}
	t.Logf("-migrate-down without the audit key reached the database: %s", oneLine(got.out))
}
