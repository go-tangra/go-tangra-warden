package fuzz

import (
	"bytes"
	"testing"

	"github.com/go-tangra/go-tangra-warden/v4/internal/migrate3"
)

// FuzzV3Bundle: the v3 bundle decoder never panics and every accepted
// document respects the format, the limits and the version grammar.
func FuzzV3Bundle(f *testing.F) {
	f.Add([]byte(`{"format":"warden-v3-export","version":1,"folders":[],"secrets":[],"grants":[]}`))
	f.Add([]byte(`{"format":"warden-v3-export","version":1,"secrets":[{"id":"s","name":"n","versions":[{"version":1,"password":"p"},{"version":2,"missing":true}],"metadata":{"a":[1,{"b":[]}]}}]}`))
	f.Add([]byte(`{"format":"warden-v3-export","version":1,"secrets":[{"id":"s","versions":[{"version":1},{"version":1}]}]}`))
	f.Add([]byte(`{"format":"warden-v3-export","version":2}`))
	f.Add([]byte(`{"format":"warden-v3-export","version":1,"folders":[{"id":""}]}`))
	f.Add([]byte(`[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := migrate3.Decode(data)
		if err != nil {
			return
		}
		if b.Format != migrate3.Format || b.Version != migrate3.FormatVersion {
			t.Fatal("format not enforced")
		}
		if len(b.Folders) > migrate3.MaxFolders || len(b.Secrets) > migrate3.MaxSecrets || len(b.Grants) > migrate3.MaxGrants {
			t.Fatal("limits not enforced")
		}
		for _, s := range b.Secrets {
			seen := map[int]bool{}
			for _, v := range s.Versions {
				if v.Version < 1 || v.Version > migrate3.MaxVersionNumber || seen[v.Version] {
					t.Fatal("version grammar not enforced")
				}
				seen[v.Version] = true
			}
		}
	})
}

// FuzzV3Sealed: opening arbitrary bytes never panics, and only an
// authentic bundle under the key is accepted.
func FuzzV3Sealed(f *testing.F) {
	key := bytes.Repeat([]byte{7}, migrate3.KeySize)
	good, err := migrate3.Seal(&migrate3.Bundle{Format: migrate3.Format, Version: migrate3.FormatVersion}, key)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add(good[:20])
	f.Add([]byte("WARDEN-V3-EXPORT\x00\x01"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := migrate3.Open(data, key)
		if err != nil {
			return
		}
		if b.Format != migrate3.Format {
			t.Fatal("unauthenticated bundle accepted")
		}
	})
}
