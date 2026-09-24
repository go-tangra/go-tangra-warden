package fuzz

import (
	"testing"

	"github.com/go-tangra/go-tangra-warden/v4/internal/share"
)

// FuzzShareToken: only 43-character base64url strings are tokens; hashing is
// constant-length and never panics.
func FuzzShareToken(f *testing.F) {
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add("")
	f.Add("../../../etc/passwd")
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	f.Fuzz(func(t *testing.T, s string) {
		ok := share.ValidToken(s)
		if ok && len(s) != share.TokenLength {
			t.Fatalf("%q accepted", s)
		}
		if ok {
			for _, r := range s {
				if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
					t.Fatalf("%q accepted with %q", s, r)
				}
			}
		}
		if len(share.Hash(s)) != 64 {
			t.Fatal("hash length")
		}
	})
}
