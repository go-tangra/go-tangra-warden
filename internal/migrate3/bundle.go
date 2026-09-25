package migrate3

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-warden/v4/internal/transfer"
)

// Bundle format identifiers.
const (
	Format        = "warden-v3-export"
	FormatVersion = 1
	KeySize       = 32 // AES-256
	nonceSize     = 12 // GCM standard nonce

	// MaxDepth bounds JSON nesting (secret metadata is free-form).
	MaxDepth = 32
	// MaxVersionNumber bounds a KV version number in a bundle.
	MaxVersionNumber = 10000
	// MaxFolders / MaxSecrets / MaxGrants bound the entity counts.
	MaxFolders = transfer.MaxFolders
	MaxSecrets = transfer.MaxItems
	MaxGrants  = transfer.MaxItems * 4
)

// header opens every sealed bundle and is the GCM additional data: a changed
// magic or format version fails authentication.
var header = []byte("WARDEN-V3-EXPORT\x00\x01")

// Size limits (variables so tests can lower them).
var (
	maxSealed int64 = 512 << 20 // sealed file
	maxPlain  int64 = 512 << 20 // decompressed JSON
)

// Errors.
var (
	ErrKey      = errors.New("migrate3: key must be 32 bytes (base64)")
	ErrCorrupt  = errors.New("migrate3: bundle is corrupt, tampered with or sealed with another key")
	ErrFormat   = errors.New("migrate3: unsupported or invalid bundle")
	ErrTooLarge = errors.New("migrate3: bundle too large")
)

// Bundle is the decrypted export document.
type Bundle struct {
	Format     string    `json:"format"`
	Version    int       `json:"version"`
	ExportedAt time.Time `json:"exported_at"`
	Tenant     uint32    `json:"tenant"`
	Folders    []Folder  `json:"folders"`
	Secrets    []Secret  `json:"secrets"`
	Grants     []Grant   `json:"grants"`
	Warnings   []string  `json:"warnings"`
}

// Folder is one v3 folder; authors are e-mail addresses ("" when unknown).
type Folder struct {
	ID          string     `json:"id"`
	ParentID    *string    `json:"parent_id,omitempty"`
	Name        string     `json:"name"`
	Path        string     `json:"path"`
	Description string     `json:"description,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
	CreatedBy   string     `json:"created_by_email,omitempty"`
}

// Secret is one v3 secret with its replayable history.
type Secret struct {
	ID             string          `json:"id"`
	FolderID       *string         `json:"folder_id,omitempty"`
	Name           string          `json:"name"`
	Username       string          `json:"username,omitempty"`
	HostURL        string          `json:"host_url,omitempty"`
	Description    string          `json:"description,omitempty"`
	Metadata       json.RawMessage `json:"metadata,omitempty"`
	Status         string          `json:"status"` // active | archived | deleted
	CurrentVersion int             `json:"current_version"`
	HasTOTP        bool            `json:"has_totp"`
	TOTPURL        string          `json:"totp_url,omitempty"` // material
	CreatedAt      *time.Time      `json:"created_at,omitempty"`
	UpdatedAt      *time.Time      `json:"updated_at,omitempty"`
	CreatedBy      string          `json:"created_by_email,omitempty"`
	UpdatedBy      string          `json:"updated_by_email,omitempty"`
	Versions       []Version       `json:"versions"` // ascending
}

// Version is one KV version: its password, or Missing when Vault no longer
// holds it (destroyed, deleted or pruned).
type Version struct {
	Version          int        `json:"version"`
	CreatedAt        *time.Time `json:"created_at,omitempty"`
	CreatedBy        string     `json:"created_by_email,omitempty"`
	Comment          string     `json:"comment,omitempty"`
	Checksum         string     `json:"checksum,omitempty"`
	Password         string     `json:"password,omitempty"` // material
	Missing          bool       `json:"missing,omitempty"`
	ChecksumMismatch bool       `json:"checksum_mismatch,omitempty"`
}

// Grant is one v3 permission row. Subject is an e-mail (user), a role code
// (role) or "all" (tenant); SubjectV3 keeps the raw v3 subject id.
type Grant struct {
	ResourceType string     `json:"resource_type"` // folder | secret
	ResourceID   string     `json:"resource_id"`
	SubjectType  string     `json:"subject_type"` // user | role | tenant
	Subject      string     `json:"subject"`
	SubjectV3    string     `json:"subject_v3"`
	Relation     string     `json:"relation"` // owner | editor | viewer | sharer
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	GrantedAt    *time.Time `json:"granted_at,omitempty"`
	GrantedBy    string     `json:"granted_by_email,omitempty"`
}

// NewKey returns a fresh random AES-256 key (crypto/rand never fails
// short: it aborts the program instead).
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	_, _ = rand.Read(k)
	return k, nil
}

// EncodeKey is the key file encoding (standard base64).
func EncodeKey(k []byte) string { return base64.StdEncoding.EncodeToString(k) }

// DecodeKey parses a key file's content.
func DecodeKey(s string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(k) != KeySize {
		return nil, ErrKey
	}
	return k, nil
}

// Seal encodes, compresses and encrypts b: header ‖ nonce ‖ ciphertext.
func Seal(b *Bundle, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrKey
	}
	plain, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	defer wipe(plain)
	compressed, _ := gzipBytes(plain)
	defer wipe(compressed)
	return sealBytes(compressed, key)
}

// gzipBytes compresses into memory (writes to a bytes.Buffer cannot fail).
func gzipBytes(plain []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(plain)
	_ = zw.Close()
	return buf.Bytes(), nil
}

func sealBytes(compressed, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrKey
	}
	gcm := newGCM(key)
	nonce := make([]byte, nonceSize)
	_, _ = rand.Read(nonce)
	out := make([]byte, 0, len(header)+nonceSize+len(compressed)+gcm.Overhead())
	out = append(out, header...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, compressed, header), nil
}

// newGCM builds AES-256-GCM; callers have checked the key length, the only
// way either constructor fails.
func newGCM(key []byte) cipher.AEAD {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	return gcm
}

// Open authenticates, decrypts, decompresses (bounded) and validates a
// sealed bundle. Any tampering or a wrong key is ErrCorrupt.
func Open(data, key []byte) (*Bundle, error) {
	if len(key) != KeySize {
		return nil, ErrKey
	}
	if int64(len(data)) > maxSealed {
		return nil, ErrTooLarge
	}
	gcm := newGCM(key)
	if len(data) < len(header)+nonceSize+gcm.Overhead() || !bytes.Equal(data[:len(header)], header) {
		return nil, ErrCorrupt
	}
	nonce := data[len(header) : len(header)+nonceSize]
	compressed, err := gcm.Open(nil, nonce, data[len(header)+nonceSize:], header)
	if err != nil {
		return nil, ErrCorrupt
	}
	defer wipe(compressed)
	plain, err := gunzipBounded(compressed)
	if err != nil {
		return nil, err
	}
	defer wipe(plain)
	return Decode(plain)
}

func gunzipBounded(compressed []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	plain, err := io.ReadAll(io.LimitReader(zr, maxPlain+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if int64(len(plain)) > maxPlain {
		wipe(plain)
		return nil, ErrTooLarge
	}
	return plain, nil
}

// Decode parses and validates the plaintext JSON of a bundle (bounded depth
// and counts). Exposed for the fuzz tests.
func Decode(plain []byte) (*Bundle, error) {
	if int64(len(plain)) > maxPlain {
		return nil, ErrTooLarge
	}
	d, err := transfer.Depth(plain)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed JSON", ErrFormat)
	}
	if d > MaxDepth {
		return nil, fmt.Errorf("%w: nested too deep", ErrFormat)
	}
	var b Bundle
	if err := json.Unmarshal(plain, &b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if err := b.validate(); err != nil {
		return nil, err
	}
	return &b, nil
}

func (b *Bundle) validate() error {
	bad := func(msg string, a ...any) error { return fmt.Errorf("%w: "+msg, append([]any{ErrFormat}, a...)...) }
	if b.Format != Format || b.Version != FormatVersion {
		return bad("format %q version %d", b.Format, b.Version)
	}
	if len(b.Folders) > MaxFolders || len(b.Secrets) > MaxSecrets || len(b.Grants) > MaxGrants {
		return bad("too many entities")
	}
	for i, f := range b.Folders {
		if f.ID == "" {
			return bad("folder %d without id", i)
		}
	}
	for i, s := range b.Secrets {
		if s.ID == "" {
			return bad("secret %d without id", i)
		}
		seen := map[int]bool{}
		for _, v := range s.Versions {
			if v.Version < 1 || v.Version > MaxVersionNumber || seen[v.Version] {
				return bad("secret %d: version number %d", i, v.Version)
			}
			seen[v.Version] = true
		}
	}
	return nil
}

// WriteFiles seals b under a fresh key and writes the bundle and the base64
// key to two new 0600 files; neither may exist. A failure leaves nothing.
func WriteFiles(outPath, keyPath string, b *Bundle) error {
	key, err := NewKey()
	if err != nil {
		return err
	}
	defer wipe(key)
	sealed, err := Seal(b, key)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(keyPath); err == nil {
		return fmt.Errorf("migrate3: %s exists; refusing to overwrite", keyPath)
	}
	if err := writeNew(outPath, sealed); err != nil {
		return err
	}
	if err := writeNew(keyPath, []byte(EncodeKey(key)+"\n")); err != nil {
		_ = os.Remove(outPath)
		return err
	}
	return nil
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-chosen output path
	if err != nil {
		return fmt.Errorf("migrate3: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("migrate3: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("migrate3: %w", err)
	}
	return nil
}

// ReadFiles opens a bundle with the key file written by WriteFiles.
func ReadFiles(inPath, keyPath string) (*Bundle, error) {
	rawKey, err := os.ReadFile(keyPath) // #nosec G304 -- operator-chosen input path
	if err != nil {
		return nil, fmt.Errorf("migrate3: key: %w", err)
	}
	key, err := DecodeKey(string(rawKey))
	wipe(rawKey)
	if err != nil {
		return nil, err
	}
	defer wipe(key)
	f, err := os.Open(inPath) // #nosec G304 -- operator-chosen input path
	if err != nil {
		return nil, fmt.Errorf("migrate3: bundle: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSealed+1))
	if err != nil {
		return nil, fmt.Errorf("migrate3: bundle: %w", err)
	}
	return Open(data, key)
}

// wipe overwrites a buffer that held key material or plaintext (best effort:
// the garbage collector may have copied it).
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
