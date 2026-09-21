package fuzz

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/go-freya/freya/services/warden/internal/transfer"
)

func seedFiles(f *testing.F) {
	for _, name := range []string{"sample", "empty", "nested"} {
		if b, err := os.ReadFile("../testdata/bitwarden/" + name + ".json"); err == nil {
			f.Add(b)
		}
	}
}

// FuzzBitwarden: the parser never panics, never accepts encrypted or
// oversized documents, and every accepted document re-encodes.
func FuzzBitwarden(f *testing.F) {
	seedFiles(f)
	f.Add([]byte(`{"encrypted":true,"items":[]}`))
	f.Add([]byte(`{"encrypted":false,"items":[{"type":1,"name":"x","login":{"password":"p","totp":"broken"}}]}`))
	f.Add([]byte(`{"encrypted":false,"items":[{"type":1,"name":"` + string(make([]byte, 300)) + `"}]}`))
	f.Add([]byte(`{"encrypted":false,"items":[{"type":2,"name":"note"}]}`))
	f.Add([]byte(`[[[[[[[[[[[[]]]]]]]]]]]]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := transfer.ParseBitwarden(data)
		if err != nil {
			return
		}
		if doc.Encrypted || len(doc.Items) > transfer.MaxItems || len(doc.Folders) > transfer.MaxFolders {
			t.Fatal("limits not enforced")
		}
		if _, err := json.Marshal(doc); err != nil {
			t.Fatal(err)
		}
	})
}

// FuzzBackup: the backup parser never panics and refuses foreign schemas.
func FuzzBackup(f *testing.F) {
	f.Add([]byte(`{"module":"warden","schema_version":1,"tenant_id":"t","folders":[],"secrets":[],"versions":[],"grants":[],"shares":[]}`))
	f.Add([]byte(`{"module":"warden","schema_version":2}`))
	f.Add([]byte(`{"module":"other","schema_version":1}`))
	f.Add([]byte(`{"module":"warden","schema_version":1,"secrets":[{"id":"s","name":"n","metadata":{"a":[1,2,{"b":[]}]}}],"versions":[{"secret_id":"s","version":1,"password":"p"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := transfer.ParseBackup(data)
		if err != nil {
			return
		}
		if b.Module != "warden" || b.SchemaVersion != transfer.SchemaVersion {
			t.Fatal("schema not enforced")
		}
		if len(b.Secrets) > transfer.MaxItems || len(b.Folders) > transfer.MaxFolders {
			t.Fatal("limits not enforced")
		}
	})
}
