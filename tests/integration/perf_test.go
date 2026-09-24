//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"sort"
	"testing"
	"time"
)

// TestPerformance measures reveal latency (p95 < 300 ms) and a 1,000-secret
// listing (< 500 ms) through the gateway on the reference box (SC-002).
// Set WARDEN_PERF_STRICT=1 to fail on the budgets; otherwise they are logged.
func TestPerformance(t *testing.T) {
	e := StartPlatform(t)
	owner, _ := e.CreateTenant("acme", "owner@acme.test")
	code, out := owner.JSON(http.MethodPost, "/api/warden/v1/folders", map[string]any{"name": "Bulk"})
	if code != 201 {
		t.Fatalf("folder → %d %v", code, out)
	}
	folder := out["id"].(string)
	// 1,000 secrets through the import path (one document) to keep setup fast.
	items := make([]map[string]any, 0, 1000)
	for i := 0; i < 1000; i++ {
		items = append(items, map[string]any{"type": 1, "name": fmt.Sprintf("perf %04d", i), "login": map[string]any{"username": "u", "password": fmt.Sprintf("WARDEN-MARKER-PW-perf-%04d", i)}})
	}
	doc := map[string]any{"encrypted": false, "folders": []any{}, "items": items}
	if code, rep := owner.JSON(http.MethodPost, "/api/warden/v1/transfer/bitwarden/import?folder_id="+folder+"&duplicates=skip", doc); code != 200 || rep["created"] != float64(1000) {
		t.Fatalf("import → %d %v", code, rep)
	}
	code, page := owner.JSON(http.MethodGet, "/api/warden/v1/secrets?folder_id="+folder+"&limit=1", nil)
	if code != 200 {
		t.Fatalf("list → %d", code)
	}
	sid := page["items"].([]any)[0].(map[string]any)["id"].(string)
	// Reveal p95 over 100 sequential calls (each hits Vault).
	var reveal []time.Duration
	for i := 0; i < 100; i++ {
		started := time.Now()
		if code, _ := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/"+sid+"/password", nil); code != 200 {
			t.Fatalf("reveal → %d", code)
		}
		reveal = append(reveal, time.Since(started))
	}
	sort.Slice(reveal, func(i, j int) bool { return reveal[i] < reveal[j] })
	p95 := reveal[94]
	// Listing 1,000 secrets: ten pages of 100.
	started := time.Now()
	cursor := ""
	n := 0
	for {
		q := "/api/warden/v1/secrets?folder_id=" + folder + "&limit=100"
		if cursor != "" {
			q += "&cursor=" + cursor
		}
		code, page := owner.JSON(http.MethodGet, q, nil)
		if code != 200 {
			t.Fatalf("list → %d", code)
		}
		n += len(page["items"].([]any))
		next, _ := page["next"].(string)
		if next == "" {
			break
		}
		cursor = next
	}
	listing := time.Since(started)
	if n != 1000 {
		t.Fatalf("listed %d", n)
	}
	t.Logf("reveal p95 %s (median %s), 1,000-secret listing %s", p95, reveal[49], listing)
	strict := getenv("WARDEN_PERF_STRICT") == "1"
	if p95 > 300*time.Millisecond {
		if strict {
			t.Fatalf("reveal p95 %s over budget", p95)
		}
		t.Logf("reveal p95 %s over the 300 ms budget (non-strict run)", p95)
	}
	if listing > 500*time.Millisecond {
		if strict {
			t.Fatalf("listing %s over budget", listing)
		}
		t.Logf("listing %s over the 500 ms budget (non-strict run)", listing)
	}
	e.ScanForMaterial(t, []string{"WARDEN-MARKER-PW-"})
}
