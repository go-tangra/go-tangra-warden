//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
)

const (
	markerPW   = "WARDEN-MARKER-PW-integration-1"
	markerPW2  = "WARDEN-MARKER-PW-integration-2"
	markerSeed = "JBSWY3DPEHPK3PXP" // the seed corpus marker is the otpauth form
)

// TestSecrets runs quickstart §3 through the gateway against real Vault and
// TimescaleDB: folders, secrets, versions, search, TOTP, and the leak scan.
func TestSecrets(t *testing.T) {
	e := StartPlatform(t)
	owner, tid := e.CreateTenant("acme", "owner@acme.test")
	var infra, databases, secretID string

	t.Run("Folders", func(t *testing.T) {
		code, out := owner.JSON(http.MethodPost, "/api/warden/v1/folders", map[string]any{"name": "Infra"})
		if code != 201 || out["path"] != "/Infra" {
			t.Fatalf("create → %d %v", code, out)
		}
		infra = out["id"].(string)
		code, out = owner.JSON(http.MethodPost, "/api/warden/v1/folders", map[string]any{"parent_id": infra, "name": "Databases"})
		if code != 201 || out["path"] != "/Infra/Databases" {
			t.Fatalf("child → %d %v", code, out)
		}
		databases = out["id"].(string)
		if code, out := owner.JSON(http.MethodPost, "/api/warden/v1/folders", map[string]any{"name": "infra"}); code != 409 || out["reason"] != "conflict" {
			t.Fatalf("sibling → %d %v", code, out)
		}
		code, out = owner.JSON(http.MethodGet, "/api/warden/v1/folders/tree", nil)
		if code != 200 || len(out["items"].([]any)) != 1 {
			t.Fatalf("tree → %d %v", code, out)
		}
		if e.AuditCount(tid, "folder_created", "ok") != 2 {
			t.Fatal("folder audit")
		}
	})

	t.Run("Secrets", func(t *testing.T) {
		in := map[string]any{"folder_id": databases, "name": "prod-db", "username": "root", "host_url": "https://db.acme.test", "description": "Primary database", "password": markerPW, "metadata": map[string]any{"env": "prod"}}
		code, out := owner.JSON(http.MethodPost, "/api/warden/v1/secrets", in)
		if code != 201 || out["current_version"] != float64(1) || out["folder_path"] != "/Infra/Databases" {
			t.Fatalf("create → %d %v", code, out)
		}
		secretID = out["id"].(string)
		if _, ok := out["password"]; ok {
			t.Fatal("password in the create response")
		}
		code, out = owner.JSON(http.MethodGet, "/api/warden/v1/secrets/"+secretID+"/password", nil)
		if code != 200 || out["password"] != markerPW || out["version"] != float64(1) {
			t.Fatalf("reveal → %d %v", code, out)
		}
		// Material lives in Vault at the tenant path, nowhere in the database.
		var n int
		_ = e.Warden.Store.Tx(context.Background(), store.Scope{System: true}, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), "SELECT count(*) FROM secrets WHERE vault_path = $1", tid+"/secrets/"+secretID).Scan(&n)
		})
		if n != 1 {
			t.Fatal("vault path reference missing")
		}
		if e.AuditCount(tid, "secret_password_read", "ok") != 1 || e.AuditCount(tid, "secret_created", "ok") != 1 {
			t.Fatal("secret audit")
		}
		// A member without a grant cannot see it; the owner's listing shows permissions.
		bob := e.Invite(owner, "bob@acme.test", "member")
		if code, out := bob.JSON(http.MethodGet, "/api/warden/v1/secrets/"+secretID, nil); code != 403 || out["reason"] != "forbidden" {
			t.Fatalf("bob → %d %v", code, out)
		}
		if e.AuditCount(tid, "access_refused", "refused") < 1 {
			t.Fatal("refusal audit")
		}
		code, out = owner.JSON(http.MethodGet, "/api/warden/v1/secrets?folder_id="+databases, nil)
		if code != 200 || len(out["items"].([]any)) != 1 {
			t.Fatalf("list → %d %v", code, out)
		}
	})

	t.Run("Versions", func(t *testing.T) {
		if code, out := owner.JSON(http.MethodPut, "/api/warden/v1/secrets/"+secretID+"/password", map[string]any{"password": markerPW2, "comment": "rotated"}); code != 200 || out["version"] != float64(2) {
			t.Fatalf("change → %d %v", code, out)
		}
		if code, out := owner.JSON(http.MethodPut, "/api/warden/v1/secrets/"+secretID+"/password", map[string]any{"password": markerPW2 + "b", "comment": "rotated again"}); code != 200 || out["version"] != float64(3) {
			t.Fatalf("change → %d %v", code, out)
		}
		code, out := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/"+secretID+"/versions", nil)
		items, _ := out["items"].([]any)
		if code != 200 || len(items) != 3 || items[0].(map[string]any)["version"] != float64(3) || items[1].(map[string]any)["comment"] != "rotated" {
			t.Fatalf("versions → %d %v", code, out)
		}
		if code, out := owner.JSON(http.MethodPost, "/api/warden/v1/secrets/"+secretID+"/versions/1/restore", map[string]any{"comment": "back to v1"}); code != 200 || out["version"] != float64(4) {
			t.Fatalf("restore → %d %v", code, out)
		}
		if code, out := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/"+secretID+"/password", nil); code != 200 || out["password"] != markerPW || out["version"] != float64(4) {
			t.Fatalf("restored reveal → %d %v", code, out)
		}
		if code, out := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/"+secretID+"/password?version=2", nil); code != 200 || out["password"] != markerPW2 {
			t.Fatalf("old version → %d %v", code, out)
		}
		if e.AuditCount(tid, "secret_restored", "ok") != 1 || e.AuditCount(tid, "secret_version_read", "ok") != 1 {
			t.Fatal("version audit")
		}
	})

	t.Run("Search", func(t *testing.T) {
		code, out := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/search?q=db", nil)
		if code != 200 || len(out["items"].([]any)) != 1 {
			t.Fatalf("search → %d %v", code, out)
		}
		if code, out := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/search?q=Databases", nil); code != 200 || len(out["items"].([]any)) != 1 {
			t.Fatalf("path search → %d %v", code, out)
		}
		if code, out := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/search?q="+markerPW, nil); code != 200 || len(out["items"].([]any)) != 0 {
			t.Fatalf("material searchable → %d %v", code, out)
		}
		// Move to Infra: the path follows.
		if code, out := owner.JSON(http.MethodPost, "/api/warden/v1/secrets/"+secretID+"/move", map[string]any{"folder_id": infra}); code != 200 || out["folder_path"] != "/Infra" {
			t.Fatalf("move → %d %v", code, out)
		}
	})

	t.Run("Totp", func(t *testing.T) {
		if code, _ := owner.JSON(http.MethodPut, "/api/warden/v1/secrets/"+secretID+"/totp", map[string]any{"totp": "otpauth://totp/Acme:root?secret=" + markerSeed + "&issuer=Acme"}); code != 204 {
			t.Fatalf("set totp → %d", code)
		}
		code, out := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/"+secretID+"/totp", nil)
		if code != 200 || len(out["code"].(string)) != 6 || out["period"] != float64(30) {
			t.Fatalf("code → %d %v", code, out)
		}
		if code, out := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/"+secretID, nil); code != 200 || out["has_totp"] != true {
			t.Fatalf("has_totp → %d %v", code, out)
		}
		if code, _ := owner.JSON(http.MethodDelete, "/api/warden/v1/secrets/"+secretID+"/totp", nil); code != 204 {
			t.Fatal("remove totp")
		}
	})

	t.Run("VaultOutage", func(t *testing.T) {
		e.VaultStop()
		defer e.VaultStart()
		if code, out := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/"+secretID+"/password", nil); code != 503 || out["reason"] != "vault_unavailable" {
			t.Fatalf("reveal during outage → %d %v", code, out)
		}
		if code, out := owner.JSON(http.MethodPost, "/api/warden/v1/secrets", map[string]any{"name": "during-outage", "password": "x"}); code != 503 || out["reason"] != "vault_unavailable" {
			t.Fatalf("create during outage → %d %v", code, out)
		}
		// Metadata stays readable.
		if code, _ := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/"+secretID, nil); code != 200 {
			t.Fatal("metadata during outage")
		}
		if e.AuditCount(tid, "vault_unavailable", "failed") < 1 {
			t.Fatal("outage audit")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		if code, _ := owner.JSON(http.MethodPost, "/api/warden/v1/secrets/"+secretID+"/remove", nil); code != 204 {
			t.Fatal("delete")
		}
		if code, _ := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/"+secretID, nil); code != 404 {
			t.Fatal("deleted visible")
		}
		if _, err := e.Warden.Vault.GetPassword(context.Background(), tid, secretID, 0); err == nil {
			t.Fatal("material survived the delete")
		}
		if code, _ := owner.JSON(http.MethodPost, "/api/warden/v1/folders/"+infra+"/remove", map[string]any{"recursive": true}); code != 204 {
			t.Fatal("folder delete")
		}
	})

	t.Run("MaterialNeverLeaks", func(t *testing.T) {
		e.ScanForMaterial(t, []string{"WARDEN-MARKER-PW-", markerSeed, "otpauth://"})
	})
}
