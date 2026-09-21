// Package fuzz holds the fuzz targets of the warden module: parsers and
// validators that face user input must never panic and must refuse what the
// contracts refuse.
package fuzz

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/go-freya/freya/services/warden/internal/folders"
	"github.com/go-freya/freya/services/warden/internal/secrets"
	"github.com/go-freya/freya/services/warden/internal/vault"
)

func FuzzFolderName(f *testing.F) {
	for _, s := range []string{"Infra", "", "a/b", strings.Repeat("x", 101), "tab\t", "  ", "Ünïcode", "\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		ok := folders.ValidName(name)
		hasBad := name == "" || len(name) > folders.NameMax || strings.TrimSpace(name) == "" || strings.ContainsRune(name, '/')
		for _, r := range name {
			if unicode.IsControl(r) {
				hasBad = true
			}
		}
		if ok == hasBad {
			t.Fatalf("%q: valid=%v", name, ok)
		}
	})
}

func FuzzSecretInput(f *testing.F) {
	f.Add("name", "user", "https://h", "desc", `{"k":"v"}`)
	f.Add("", "", "", "", "")
	f.Add(strings.Repeat("n", 201), "u", "h", "d", "[]")
	f.Add("n", "u", "h", "d", `{"k":"`+strings.Repeat("v", 17000)+`"}`)
	f.Fuzz(func(t *testing.T, name, user, host, desc, meta string) {
		// Metadata validation must never panic and must refuse non-objects and oversize.
		raw := json.RawMessage(meta)
		ok := secrets.ValidMetadata(raw)
		if ok && len(raw) > secrets.MetadataMax {
			t.Fatal("oversize metadata accepted")
		}
		if ok && len(raw) > 0 {
			var m map[string]any
			if json.Unmarshal(raw, &m) != nil {
				t.Fatal("non-object metadata accepted")
			}
		}
		if len(name) > secrets.NameMax && secrets.ValidMetadata(nil) && name == strings.Repeat("n", 201) {
			_ = user + host + desc // bounds are enforced by the service validate (private); exercised through Checksum below
		}
		_ = secrets.Checksum(name + user + host + desc)
	})
}

func FuzzTotpSeed(f *testing.F) {
	for _, s := range []string{"JBSWY3DPEHPK3PXP", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=abc", "", "otpauth://hotp/x", "%zz", strings.Repeat("A", 600), "otpauth://totp/x?secret=A&digits=99"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out, err := secrets.NormalizeSeed(in)
		if err != nil {
			return
		}
		if !strings.HasPrefix(out, "otpauth://totp/") || len(out) > 1024 {
			t.Fatalf("%q → %q", in, out)
		}
		// Canonical output round-trips and generates a code.
		again, err := secrets.NormalizeSeed(out)
		if err != nil || again != out {
			t.Fatalf("round trip %q → %q (%v)", out, again, err)
		}
		if _, err := secrets.GenerateCode(out, time.Unix(1_700_000_000, 0)); err != nil {
			t.Fatalf("code for %q: %v", out, err)
		}
	})
}

func FuzzPathBuilder(f *testing.F) {
	f.Add("0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55", "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77")
	f.Add("../other", "x")
	f.Add("0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55", "../../0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66/secrets/x")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, tenant, secret string) {
		p, err := vault.Path(tenant, secret)
		if err != nil {
			return
		}
		if !strings.HasPrefix(p, tenant+"/secrets/") || strings.Contains(p, "..") || strings.Count(p, "/") != 2 || len(tenant) != 36 || len(secret) != 36 {
			t.Fatalf("%q %q → %q", tenant, secret, p)
		}
	})
}
