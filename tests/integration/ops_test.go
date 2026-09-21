//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-freya/freya/services/warden/internal/store"
)

// TestOps covers a vault outage (fail closed within budget, no partial rows,
// recovery), the reconciler, statistics, the audit trail and the generator.
func TestOps(t *testing.T) {
	e := StartPlatform(t)
	owner, tid := e.CreateTenant("acme", "owner@acme.test")
	code, sec := owner.JSON(http.MethodPost, "/api/warden/v1/secrets", map[string]any{"name": "db", "password": "WARDEN-MARKER-PW-ops"})
	if code != 201 {
		t.Fatalf("secret → %d %v", code, sec)
	}
	sid := sec["id"].(string)

	t.Run("VaultOutage", func(t *testing.T) {
		e.VaultStop()
		defer e.VaultStart()
		started := time.Now()
		if code, out := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/"+sid+"/password", nil); code != 503 || out["reason"] != "vault_unavailable" {
			t.Fatalf("reveal → %d %v", code, out)
		}
		// The vault client fails closed on its request timeout (5 s, one retry) rather than hanging.
		if d := time.Since(started); d > 15*time.Second {
			t.Fatalf("reveal took %s", d)
		}
		if code, out := owner.JSON(http.MethodPost, "/api/warden/v1/secrets", map[string]any{"name": "partial", "password": "x"}); code != 503 || out["reason"] != "vault_unavailable" {
			t.Fatalf("create → %d %v", code, out)
		}
		// No partial row survives the failed create.
		var n int
		_ = e.Warden.Store.Tx(context.Background(), store.Scope{System: true}, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), "SELECT count(*) FROM secrets WHERE tenant_id = $1 AND name = 'partial'", tid).Scan(&n)
		})
		if n != 0 {
			t.Fatal("partial row left behind")
		}
		// Listings and health keep working; health reports the vault.
		if code, _ := owner.JSON(http.MethodGet, "/api/warden/v1/secrets?root=true", nil); code != 200 {
			t.Fatal("listing during outage")
		}
		if code, h := owner.JSON(http.MethodGet, "/api/warden/v1/health", nil); code != 200 || h["status"] != "degraded" || h["vault"] != "unreachable" || h["db"] != "ok" {
			t.Fatalf("health → %d %v", code, h)
		}
	})

	t.Run("Recovery", func(t *testing.T) {
		deadline := time.Now().Add(30 * time.Second)
		for {
			code, h := owner.JSON(http.MethodGet, "/api/warden/v1/health", nil)
			if code == 200 && h["status"] == "ok" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("health never recovered: %v", h)
			}
			time.Sleep(500 * time.Millisecond)
		}
		if code, out := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/"+sid+"/password", nil); code != 200 || out["password"] != "WARDEN-MARKER-PW-ops" {
			t.Fatalf("reveal after recovery → %d %v", code, out)
		}
	})

	t.Run("Reconciler", func(t *testing.T) {
		// Simulate a service killed between the vault write and the commit: a
		// row at version 0 with material in the vault, older than the grace.
		orphan := store.NewID()
		by := owner.UserID
		if err := e.Warden.Store.Tx(context.Background(), store.Scope{TenantID: tid}, func(tx pgx.Tx) error {
			if err := store.InsertSecret(context.Background(), tx, store.Secret{ID: orphan, TenantID: tid, Name: "interrupted", VaultPath: tid + "/secrets/" + orphan, CreatedBy: &by}); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), "UPDATE secrets SET created_at = now() - interval '10 minutes' WHERE id = $1", orphan)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.Warden.Vault.PutPassword(context.Background(), tid, orphan, "WARDEN-MARKER-PW-orphan"); err != nil {
			t.Fatal(err)
		}
		if err := e.Warden.Authz.GrantOwner(context.Background(), tid, "secret", orphan, owner.UserID); err != nil {
			t.Fatal(err)
		}
		rep, err := e.Warden.Secrets.Reconcile(context.Background())
		if err != nil || rep.Repaired != 1 {
			t.Fatalf("%+v %v", rep, err)
		}
		if code, out := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/"+orphan, nil); code != 200 || out["current_version"] != float64(1) {
			t.Fatalf("repaired → %d %v", code, out)
		}
	})

	t.Run("Stats", func(t *testing.T) {
		code, s := owner.JSON(http.MethodGet, "/api/warden/v1/stats", nil)
		if code != 200 || s["secrets"] != float64(2) || s["versions"] != float64(2) || s["grants"].(map[string]any)["owner"] != float64(2) || s["operations_24h"].(float64) < 3 {
			t.Fatalf("stats → %d %v", code, s)
		}
		member := e.Invite(owner, "bob@acme.test", "member")
		if code, _ := member.JSON(http.MethodGet, "/api/warden/v1/stats", nil); code != 403 {
			t.Fatal("member stats")
		}
	})

	t.Run("Audit", func(t *testing.T) {
		code, page := owner.JSON(http.MethodGet, "/api/warden/v1/audit?event_type=secret_password_read", nil)
		items := page["items"].([]any)
		if code != 200 || len(items) < 2 {
			t.Fatalf("audit → %d %v", code, page)
		}
		first := items[0].(map[string]any)
		if first["actor_id"] != owner.UserID || first["subject_id"] != sid {
			t.Fatalf("%v", first)
		}
		if code, page := owner.JSON(http.MethodGet, "/api/warden/v1/audit?event_type=vault_unavailable", nil); code != 200 || len(page["items"].([]any)) < 1 {
			t.Fatalf("outage audited → %d %v", code, page)
		}
		if code, _ := owner.JSON(http.MethodGet, "/api/warden/v1/audit?event_type=nope", nil); code != 400 {
			t.Fatal("filter validation")
		}
		e.ScanForMaterial(t, []string{"WARDEN-MARKER-PW-"})
	})

	t.Run("Generator", func(t *testing.T) {
		code, out := owner.JSON(http.MethodPost, "/api/warden/v1/generate", map[string]any{"length": 32, "symbols": false})
		pw, _ := out["password"].(string)
		if code != 200 || len(pw) != 32 {
			t.Fatalf("generate → %d %v", code, out)
		}
		for _, c := range pw {
			if c < '0' || (c > '9' && c < 'A') || (c > 'Z' && c < 'a') || c > 'z' {
				t.Fatalf("symbol in %q", pw)
			}
		}
		if code, _ := owner.JSON(http.MethodPost, "/api/warden/v1/generate", map[string]any{"length": 4}); code != 400 {
			t.Fatal("bounds")
		}
		// The generated value is nowhere in the audit trail or logs.
		e.ScanForMaterial(t, []string{pw})
	})
}
