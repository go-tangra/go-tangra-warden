package migrate3

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleBundle() *Bundle {
	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	fid := "f1"
	return &Bundle{Format: Format, Version: FormatVersion, ExportedAt: ts, Tenant: 0,
		Folders: []Folder{{ID: fid, Name: "Infra", Path: "/Infra", CreatedAt: &ts, CreatedBy: "a@example.org"}},
		Secrets: []Secret{{ID: "s1", FolderID: &fid, Name: "db", Status: "active", CurrentVersion: 2, HasTOTP: true, TOTPURL: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
			Versions: []Version{{Version: 1, Missing: true}, {Version: 2, Password: "WARDEN-MARKER-PW-1", Checksum: "abc"}}}},
		Grants:   []Grant{{ResourceType: "folder", ResourceID: fid, SubjectType: "user", Subject: "a@example.org", Relation: "owner"}},
		Warnings: []string{},
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key, err := NewKey()
	if err != nil || len(key) != KeySize {
		t.Fatal(err)
	}
	sealed, err := Seal(sampleBundle(), key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(sealed, header) {
		t.Fatal("header missing")
	}
	if bytes.Contains(sealed, []byte("MARKER")) || bytes.Contains(sealed, []byte("JBSWY3DP")) || bytes.Contains(sealed, []byte("example.org")) {
		t.Fatal("plaintext in sealed bundle")
	}
	b, err := Open(sealed, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Secrets) != 1 || b.Secrets[0].Versions[1].Password != "WARDEN-MARKER-PW-1" || !b.Secrets[0].Versions[0].Missing || b.Folders[0].CreatedAt == nil {
		t.Fatalf("%+v", b)
	}
	// A fresh nonce per seal: two seals differ.
	again, _ := Seal(sampleBundle(), key)
	if bytes.Equal(again, sealed) {
		t.Fatal("nonce reused")
	}
}

func TestOpenRefusesTamperingAndWrongKey(t *testing.T) {
	key, _ := NewKey()
	sealed, _ := Seal(sampleBundle(), key)
	flip := func(i int) []byte {
		c := append([]byte(nil), sealed...)
		c[i] ^= 0x01
		return c
	}
	cases := map[string][]byte{
		"header":     flip(3),
		"version":    flip(len(header) - 1),
		"nonce":      flip(len(header) + 2),
		"ciphertext": flip(len(header) + nonceSize + 5),
		"tag":        flip(len(sealed) - 1),
		"truncated":  sealed[:len(header)+nonceSize+4],
		"short":      sealed[:5],
		"empty":      nil,
	}
	for name, data := range cases {
		if _, err := Open(data, key); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	other, _ := NewKey()
	if _, err := Open(sealed, other); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := Open(sealed, key[:16]); !errors.Is(err, ErrKey) {
		t.Fatalf("short key: %v", err)
	}
	bad := sampleBundle()
	bad.Secrets[0].Metadata = []byte("{not json")
	if _, err := Seal(bad, key); err == nil {
		t.Fatal("invalid metadata sealed")
	}
	if _, err := sealBytes(nil, key[:3]); !errors.Is(err, ErrKey) {
		t.Fatal("sealBytes short key")
	}
	if _, err := Seal(sampleBundle(), key[:10]); !errors.Is(err, ErrKey) {
		t.Fatalf("seal short key: %v", err)
	}
}

func TestOpenValidatesContent(t *testing.T) {
	key, _ := NewKey()
	for name, mut := range map[string]func(b *Bundle){
		"format":      func(b *Bundle) { b.Format = "other" },
		"version":     func(b *Bundle) { b.Version = 2 },
		"version0":    func(b *Bundle) { b.Secrets[0].Versions[0].Version = 0 },
		"versionHuge": func(b *Bundle) { b.Secrets[0].Versions[0].Version = MaxVersionNumber + 1 },
		"duplicate":   func(b *Bundle) { b.Secrets[0].Versions[0].Version = 2 },
		"noSecretID":  func(b *Bundle) { b.Secrets[0].ID = "" },
		"noFolderID":  func(b *Bundle) { b.Folders[0].ID = "" },
		"tooMany":     func(b *Bundle) { b.Folders = make([]Folder, MaxFolders+1) },
	} {
		b := sampleBundle()
		mut(b)
		sealed, err := Seal(b, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Open(sealed, key); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Well-formed ciphertext around garbage: not gzip, not JSON, too deep.
	for name, plain := range map[string][]byte{
		"notgzip": []byte("plain"),
		"notjson": gz(t, []byte("{nope")),
		"deep":    gz(t, []byte(strings.Repeat("[", MaxDepth+1)+strings.Repeat("]", MaxDepth+1))),
	} {
		if _, err := Open(sealRaw(t, plain, key), key); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestOpenBoundsDecompression(t *testing.T) {
	key, _ := NewKey()
	old := maxPlain
	maxPlain = 1 << 10
	defer func() { maxPlain = old }()
	bomb := gz(t, bytes.Repeat([]byte(" "), 4<<10))
	if _, err := Open(sealRaw(t, bomb, key), key); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("bomb: %v", err)
	}
	if _, err := Decode(bytes.Repeat([]byte(" "), 2<<10)); !errors.Is(err, ErrTooLarge) {
		t.Fatal("oversized plaintext accepted")
	}
	if _, err := Open(make([]byte, maxSealed+1), key); !errors.Is(err, ErrTooLarge) {
		t.Fatal("oversized sealed file accepted")
	}
}

func TestKeyEncoding(t *testing.T) {
	key, _ := NewKey()
	enc := EncodeKey(key)
	got, err := DecodeKey(" " + enc + "\n")
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "not base64!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := DecodeKey(bad); !errors.Is(err, ErrKey) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestWriteReadFiles(t *testing.T) {
	dir := t.TempDir()
	out, keyOut := filepath.Join(dir, "v3.bundle"), filepath.Join(dir, "v3.key")
	if err := WriteFiles(out, keyOut, sampleBundle()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{out, keyOut} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, err, st.Mode())
		}
	}
	b, err := ReadFiles(out, keyOut)
	if err != nil || len(b.Secrets) != 1 {
		t.Fatal(err)
	}
	// Never overwrite either file; a refused key leaves no bundle behind.
	if err := WriteFiles(out, filepath.Join(dir, "k2"), sampleBundle()); err == nil {
		t.Fatal("bundle overwritten")
	}
	if _, err := os.Stat(filepath.Join(dir, "k2")); !os.IsNotExist(err) {
		t.Fatal("key written although the bundle was refused")
	}
	if err := WriteFiles(filepath.Join(dir, "b2"), keyOut, sampleBundle()); err == nil {
		t.Fatal("key overwritten")
	}
	if _, err := os.Stat(filepath.Join(dir, "b2")); !os.IsNotExist(err) {
		t.Fatal("bundle left behind")
	}
	if err := WriteFiles(filepath.Join(dir, "missing", "b"), filepath.Join(dir, "k3"), sampleBundle()); err == nil {
		t.Fatal("unwritable bundle path accepted")
	}
	if err := WriteFiles(filepath.Join(dir, "b4"), filepath.Join(dir, "missing", "k"), sampleBundle()); err == nil {
		t.Fatal("unwritable key path accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "b4")); !os.IsNotExist(err) {
		t.Fatal("bundle left behind after key failure")
	}
	if _, err := ReadFiles(filepath.Join(dir, "none"), keyOut); err == nil {
		t.Fatal("missing bundle")
	}
	if _, err := ReadFiles(out, filepath.Join(dir, "none")); err == nil {
		t.Fatal("missing key")
	}
	_ = os.WriteFile(filepath.Join(dir, "badkey"), []byte("x"), 0o600)
	if _, err := ReadFiles(out, filepath.Join(dir, "badkey")); !errors.Is(err, ErrKey) {
		t.Fatal("bad key")
	}
}

func gz(t *testing.T, plain []byte) []byte {
	t.Helper()
	out, err := gzipBytes(plain)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sealRaw(t *testing.T, compressed, key []byte) []byte {
	t.Helper()
	out, err := sealBytes(compressed, key)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
