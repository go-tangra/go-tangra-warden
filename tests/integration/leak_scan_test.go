//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
)

// ScanForMaterial dumps every warden table, the audit hypertable and every
// captured service log and fails when any marker appears (SC-005).
func (e *Env) ScanForMaterial(t *testing.T, markers []string) {
	t.Helper()
	e.Warden.Audit.Flush()
	var dump strings.Builder
	err := e.Warden.Store.Tx(context.Background(), store.Scope{System: true}, func(tx pgx.Tx) error {
		for _, table := range []string{"folders", "secrets", "secret_versions", "grants", "shares", "warden_audit_events"} {
			rows, err := tx.Query(context.Background(), "SELECT to_jsonb(t) FROM "+table+" t") // #nosec G202 -- fixed table names
			if err != nil {
				return err
			}
			for rows.Next() {
				var js []byte
				if err := rows.Scan(&js); err != nil {
					rows.Close()
					return err
				}
				dump.WriteString(table + ": " + string(js) + "\n")
			}
			rows.Close()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range e.logs {
		b, _ := os.ReadFile(p)
		dump.WriteString(fmt.Sprintf("log %s: %s\n", name, b))
	}
	text := dump.String()
	for _, m := range markers {
		if i := strings.Index(text, m); i >= 0 {
			start := i - 120
			if start < 0 {
				start = 0
			}
			t.Fatalf("marker %q found in a dump: …%s…", m, text[start:min(len(text), i+80)])
		}
	}
}
