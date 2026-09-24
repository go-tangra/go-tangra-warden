package httpapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-warden/v4/internal/generator"
	"github.com/go-tangra/go-tangra-warden/v4/internal/stats"
	"github.com/go-tangra/go-tangra-warden/v4/internal/vault"
)

func TestOpsRoutes(t *testing.T) {
	st := newStory(t)
	vaultState := vault.HealthOK
	dbState := "ok"
	st.s.RegisterOps(OpsDeps{Generator: generator.New(), Stats: stats.New(st.ms), Audit: st.ms, Version: "test",
		Health: func(context.Context) (string, vault.Health) { return dbState, vaultState }})
	// Generator: defaults, options, bounds, not audited.
	code, out := st.call(st.alice, "POST", "/api/warden/v1/generate", "{}")
	if code != 200 || len(out["password"].(string)) != 20 {
		t.Fatalf("default: %d %v", code, out)
	}
	code, out = st.call(st.alice, "POST", "/api/warden/v1/generate", `{"length":12,"symbols":false,"upper":false}`)
	pw := out["password"].(string)
	if code != 200 || !generator.Satisfies(pw, generator.Options{Length: 12, Lower: true, Digits: true}) {
		t.Fatalf("options: %d %v", code, out)
	}
	for _, body := range []string{`{"length":4}`, `{"length":200}`, `{"lower":false,"upper":false,"digits":false,"symbols":false}`, `{"length":"x"}`} {
		if code, _ := st.call(st.alice, "POST", "/api/warden/v1/generate", body); code != 400 {
			t.Fatalf("%s: %d", body, code)
		}
	}
	if code, _ := st.call("", "POST", "/api/warden/v1/generate", "{}"); code != 401 {
		t.Fatal("anonymous generate")
	}
	st.aw.Flush()
	for _, r := range st.ms.Audit {
		if strings.Contains(string(r.Details), pw) {
			t.Fatal("generated password audited")
		}
	}
	// Stats reflect the tenant; the other tenant sees its own zeros.
	_, infra := st.call(st.alice, "POST", "/api/warden/v1/folders", `{"name":"Infra"}`)
	_, sec := st.call(st.alice, "POST", "/api/warden/v1/secrets", `{"folder_id":"`+infra["id"].(string)+`","name":"db","password":"`+pw+`","totp":"JBSWY3DPEHPK3PXP"}`)
	_, _ = st.call(st.alice, "GET", "/api/warden/v1/secrets/"+sec["id"].(string)+"/password", "")
	st.aw.Flush()
	code, s := st.call(st.alice, "GET", "/api/warden/v1/stats", "")
	if code != 200 || s["secrets"] != float64(1) || s["secrets_with_totp"] != float64(1) || s["folders"] != float64(1) || s["versions"] != float64(1) || s["grants"].(map[string]any)["owner"] != float64(2) || s["operations_24h"].(float64) < 3 {
		t.Fatalf("stats: %d %v", code, s)
	}
	if code, s := st.call(st.other, "GET", "/api/warden/v1/stats", ""); code != 200 || s["secrets"] != float64(0) {
		t.Fatalf("other stats: %d %v", code, s)
	}
	// Audit: filters, paging, no material, foreign tenant sees nothing.
	code, page := st.call(st.alice, "GET", "/api/warden/v1/audit?event_type=secret_password_read", "")
	items := page["items"].([]any)
	if code != 200 || len(items) != 1 || items[0].(map[string]any)["actor_id"] != uA || strings.Contains(st.raw(st.alice, "GET", "/api/warden/v1/audit", ""), pw) {
		t.Fatalf("audit: %d %v", code, page)
	}
	if code, page := st.call(st.alice, "GET", "/api/warden/v1/audit?actor_id="+uB, ""); code != 200 || len(page["items"].([]any)) != 0 {
		t.Fatalf("actor filter: %d %v", code, page)
	}
	from := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	to := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if code, page := st.call(st.alice, "GET", "/api/warden/v1/audit?from="+from+"&to="+to, ""); code != 200 || len(page["items"].([]any)) < 3 {
		t.Fatalf("window: %d %v", code, page)
	}
	if code, _ := st.call(st.alice, "GET", "/api/warden/v1/audit?event_type=nope", ""); code != 400 {
		t.Fatal("unknown event type")
	}
	if code, _ := st.call(st.alice, "GET", "/api/warden/v1/audit?cursor=abc", ""); code != 400 {
		t.Fatal("bad cursor")
	}
	if code, _ := st.call(st.alice, "GET", "/api/warden/v1/audit?from=2020-01-01T00:00:00Z&to=2019-01-01T00:00:00Z", ""); code != 400 {
		t.Fatal("inverted window")
	}
	if code, page := st.call(st.other, "GET", "/api/warden/v1/audit", ""); code != 200 || len(page["items"].([]any)) != 0 {
		t.Fatalf("foreign audit: %d %v", code, page)
	}
	// Health states.
	if code, h := st.call(st.alice, "GET", "/api/warden/v1/health", ""); code != 200 || h["status"] != "ok" || h["vault"] != "ok" || h["version"] != "test" {
		t.Fatalf("health: %d %v", code, h)
	}
	vaultState = vault.HealthSealed
	if _, h := st.call(st.alice, "GET", "/api/warden/v1/health", ""); h["status"] != "degraded" || h["vault"] != "sealed" {
		t.Fatalf("sealed: %v", h)
	}
	vaultState, dbState = vault.HealthOK, "unreachable"
	if _, h := st.call(st.alice, "GET", "/api/warden/v1/health", ""); h["status"] != "degraded" || h["db"] != "unreachable" {
		t.Fatalf("db down: %v", h)
	}
	if code, _ := st.call("", "GET", "/api/warden/v1/health", ""); code != 401 {
		t.Fatal("anonymous health")
	}
	// Store failures surface as 503 without details.
	st.ms.FailOn("TenantStats", errTest)
	if code, out := st.call(st.alice, "GET", "/api/warden/v1/stats", ""); code != 503 || out["reason"] != "temporarily_unavailable" {
		t.Fatalf("stats db: %d %v", code, out)
	}
	st.ms.FailOn("TenantStats", nil)
	st.ms.FailOn("QueryAudit", errTest)
	if code, _ := st.call(st.alice, "GET", "/api/warden/v1/audit", ""); code != 503 {
		t.Fatal("audit db")
	}
	st.ms.FailOn("QueryAudit", nil)
}

var errTest = &Error{Status: 503, Reason: "temporarily_unavailable"}
