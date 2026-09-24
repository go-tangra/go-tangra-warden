// Package bitwarden generates deterministic Bitwarden export fixtures for
// tests and fuzz seeds: `go run ./tests/testdata/bitwarden -out <dir>` writes
// sample.json (20 items, 3 folders, history, totp, non-login items),
// empty.json, nested.json (deep folder paths) and huge.json (5,000 items).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	out := flag.String("out", ".", "output directory")
	flag.Parse()
	for name, doc := range Fixtures() {
		b, _ := json.MarshalIndent(doc, "", " ")
		if err := os.WriteFile(filepath.Join(*out, name+".json"), b, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

// Fixtures returns every fixture document by name.
func Fixtures() map[string]map[string]any {
	return map[string]map[string]any{
		"sample": Sample(20, 3, true),
		"empty":  {"encrypted": false, "folders": []any{}, "items": []any{}},
		"nested": nested(),
		"huge":   Sample(5000, 50, false),
	}
}

// Sample builds n login items over f folders; with extras it adds password
// history, TOTP seeds, custom fields, a secure note and a broken seed.
func Sample(n, f int, extras bool) map[string]any {
	folders := make([]any, 0, f)
	for i := 0; i < f; i++ {
		folders = append(folders, map[string]any{"id": fmt.Sprintf("bw-folder-%d", i), "name": fmt.Sprintf("Imported/Team %d", i)})
	}
	items := make([]any, 0, n+2)
	for i := 0; i < n; i++ {
		fid := fmt.Sprintf("bw-folder-%d", i%f)
		it := map[string]any{
			"id": fmt.Sprintf("bw-item-%d", i), "folderId": fid, "type": 1, "name": fmt.Sprintf("Service %03d", i), "notes": fmt.Sprintf("Login for service %d", i), "favorite": i%7 == 0,
			"login": map[string]any{"username": fmt.Sprintf("user%d", i), "password": fmt.Sprintf("WARDEN-MARKER-PW-bw-%04d", i), "uris": []any{map[string]any{"uri": fmt.Sprintf("https://svc%d.example.org", i), "match": nil}}},
		}
		if extras {
			login := it["login"].(map[string]any)
			if i%5 == 0 {
				login["totp"] = "JBSWY3DPEHPK3PXP"
			}
			if i%9 == 1 {
				login["totp"] = "not a seed"
			}
			if i%4 == 0 {
				it["passwordHistory"] = []any{map[string]any{"lastUsedDate": "2026-01-01T00:00:00Z", "password": fmt.Sprintf("WARDEN-MARKER-PW-bw-old-%04d", i)}, map[string]any{"lastUsedDate": "2025-01-01T00:00:00Z", "password": fmt.Sprintf("WARDEN-MARKER-PW-bw-older-%04d", i)}}
			}
			if i%3 == 0 {
				it["fields"] = []any{map[string]any{"name": "env", "value": "prod", "type": 0}, map[string]any{"name": "owner", "value": "team", "type": 0}}
			}
		}
		items = append(items, it)
	}
	if extras {
		items = append(items, map[string]any{"id": "bw-note", "folderId": nil, "type": 2, "name": "A secure note", "notes": "not a login", "secureNote": map[string]any{"type": 0}})
		items = append(items, map[string]any{"id": "bw-card", "folderId": nil, "type": 3, "name": "A card", "card": map[string]any{"number": "4111"}})
	}
	return map[string]any{"encrypted": false, "folders": folders, "items": items}
}

func nested() map[string]any {
	deep := strings.Repeat("Level/", 12) + "Leaf"
	return map[string]any{"encrypted": false,
		"folders": []any{map[string]any{"id": "d", "name": deep}, map[string]any{"id": "e", "name": "  /Trim/  "}, map[string]any{"id": "bad", "name": "tab\there"}},
		"items": []any{
			map[string]any{"type": 1, "name": "deep one", "folderId": "d", "login": map[string]any{"username": "u", "password": "p"}},
			map[string]any{"type": 1, "name": "trimmed", "folderId": "e", "login": map[string]any{"username": "u", "password": "p"}},
			map[string]any{"type": 1, "name": strings.Repeat("N", 200), "folderId": "bad", "login": map[string]any{"password": "p"}},
			map[string]any{"type": 1, "name": "no password", "folderId": nil, "login": map[string]any{"username": "u"}},
			map[string]any{"type": 1, "name": "unknown folder", "folderId": "zzz", "login": map[string]any{"password": "p"}},
			map[string]any{"type": 1, "name": "bad/name", "folderId": nil, "login": map[string]any{"password": "p"}},
		}}
}
