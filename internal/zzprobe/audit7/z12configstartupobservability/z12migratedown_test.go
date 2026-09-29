//go:build audit7

// Z12-5: -migrate-down runs the whole serving-time loader before it can roll a
// migration back.
package z12configstartupobservability

import (
	"strings"
	"testing"
)

// Z12-5: -migrate-down runs the whole configuration loader, so the rollback
// command is refused unless every serving-time secret is in place — including the
// audit chain key, which the rollback path never touches.
//
// run() calls loadConfig (main.go:332) before it looks at any flag, and main.go:369
// sends -migrate-down into migrateDownAndReport only after both loadConfig and the
// metrics registry. loadConfig requires RE0AUTH_AUDIT_KEY whenever the DSN selects
// postgres (config.go:741-751) — a rule whose stated reason is the durable audit
// chain ("a durable chain signed with no key would be a control that only looks
// like one"). migrateDownAndReport (main.go:1158-1166) passes that DSN to
// postgres.MigrateDown with only the connect timeout: no audit sink, no chain, no
// key is on the path.
//
// The probe measures the stage that refuses, with the documented "RE0AUTH_AUDIT_KEY
// is required when the audit log is durable" message as the marker, and uses an
// unreachable-but-well-formed DSN so the control dies on the connection instead.
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
	// rollback path reads the chain.
	got := runBinary(t, with(nil), "-config", path, "-migrate-down")
	if !strings.Contains(got.out, "stage=config") {
		t.Fatalf("the run was not refused by the configuration loader, so this probe observed "+
			"nothing:\n%s", got.out)
	}
	t.Errorf("-migrate-down was refused by the configuration loader (exit=%d) over a key the "+
		"rollback never uses: %s. The command needs a DSN and a connect timeout, but run() runs "+
		"the whole serving-time loader first, so an operator recovering from a bad migration "+
		"cannot roll back until every OIDC/vault/audit secret is in place",
		got.code, oneLine(got.out))
}
