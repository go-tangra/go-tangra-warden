package migrate3

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrNoKV is returned by a KV reader for a path or version Vault does not
// hold (never written, deleted, destroyed or pruned).
var ErrNoKV = errors.New("migrate3: not in vault")

// Source rows (v3 tables). Every read of one export runs in the same
// read-only snapshot and is scoped to the exported tenant.
type (
	SrcFolder struct {
		ID                     string
		ParentID               *string
		Name, Path             string
		Description            string
		CreateBy               *uint32
		CreateTime, UpdateTime *time.Time
	}
	SrcSecret struct {
		ID                     string
		FolderID               *string
		Name, Username         string
		HostURL, VaultPath     string
		CurrentVersion         int
		Metadata               []byte
		Description, Status    string
		HasTOTP                bool
		CreateBy, UpdateBy     *uint32
		CreateTime, UpdateTime *time.Time
	}
	SrcVersion struct {
		SecretID          string
		Version           int
		Comment, Checksum string
		CreateBy          *uint32
		CreateTime        *time.Time
	}
	SrcPermission struct {
		ResourceType, ResourceID string
		Relation                 string
		SubjectType, SubjectID   string
		GrantedBy                *uint32
		ExpiresAt, CreateTime    *time.Time
	}
)

// Source reads the v3 tables of one tenant (live rows, unexpired grants).
type Source interface {
	Folders(ctx context.Context) ([]SrcFolder, error)
	Secrets(ctx context.Context, includeDeleted bool) ([]SrcSecret, error)
	Versions(ctx context.Context, secretIDs []string) ([]SrcVersion, error)
	Permissions(ctx context.Context) ([]SrcPermission, error)
	UserEmails(ctx context.Context, ids []uint32) (map[uint32]string, error)
	RoleCodes(ctx context.Context) (map[string]string, error) // role id (decimal) → code
}

// KVVersion is one entry of a KV v2 path's metadata.
type KVVersion struct {
	CreatedTime        time.Time
	Deleted, Destroyed bool
}

// KVMeta is a KV v2 path's metadata.
type KVMeta struct {
	Versions map[int]KVVersion
}

// KV reads the v3 Vault (KV v2): metadata and data (version 0 = latest).
type KV interface {
	Metadata(ctx context.Context, path string) (KVMeta, error)
	Read(ctx context.Context, path string, version int) (map[string]any, error)
}

// ExportOptions select the tenant and whether DELETED secrets are included.
type ExportOptions struct {
	Tenant         uint32
	IncludeDeleted bool
	Now            func() time.Time
}

// ExportSummary is what the operator sees: counts and names, never material.
type ExportSummary struct {
	Tenant             uint32         `json:"tenant"`
	Folders            int            `json:"folders"`
	Secrets            int            `json:"secrets"`
	SecretsByStatus    map[string]int `json:"secrets_by_status"`
	Versions           int            `json:"versions"`
	VersionsMissing    int            `json:"versions_missing"`
	ChecksumMismatches []string       `json:"checksum_mismatches"`
	ChecksumUnverified int            `json:"versions_without_checksum"`
	TOTP               int            `json:"authenticators"`
	TOTPMissing        int            `json:"authenticators_missing"`
	Grants             int            `json:"grants"`
	GrantsSkipped      int            `json:"grants_on_unexported_resources"`
	UsersWithoutEmail  int            `json:"users_without_email"`
	Warnings           []string       `json:"warnings"`
}

// Export reads one v3 tenant into a bundle. A database or Vault failure
// aborts the export (fail closed); a version Vault no longer holds is
// recorded as missing.
func Export(ctx context.Context, src Source, kv KV, o ExportOptions) (*Bundle, ExportSummary, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	sum := ExportSummary{Tenant: o.Tenant, SecretsByStatus: map[string]int{}, ChecksumMismatches: []string{}, Warnings: []string{}}
	b := &Bundle{Format: Format, Version: FormatVersion, ExportedAt: o.Now().UTC(), Tenant: o.Tenant, Folders: []Folder{}, Secrets: []Secret{}, Grants: []Grant{}}
	folders, err := src.Folders(ctx)
	if err != nil {
		return nil, sum, fmt.Errorf("migrate3: folders: %w", err)
	}
	secs, err := src.Secrets(ctx, o.IncludeDeleted)
	if err != nil {
		return nil, sum, fmt.Errorf("migrate3: secrets: %w", err)
	}
	ids := make([]string, 0, len(secs))
	for _, s := range secs {
		ids = append(ids, s.ID)
	}
	vers, err := src.Versions(ctx, ids)
	if err != nil {
		return nil, sum, fmt.Errorf("migrate3: versions: %w", err)
	}
	perms, err := src.Permissions(ctx)
	if err != nil {
		return nil, sum, fmt.Errorf("migrate3: permissions: %w", err)
	}
	roles, err := src.RoleCodes(ctx)
	if err != nil {
		return nil, sum, fmt.Errorf("migrate3: roles: %w", err)
	}
	emails, err := src.UserEmails(ctx, referencedUsers(folders, secs, vers, perms))
	if err != nil {
		return nil, sum, fmt.Errorf("migrate3: users: %w", err)
	}
	noEmail := map[string]bool{}
	email := func(id *uint32) string {
		if id == nil {
			return ""
		}
		e := strings.ToLower(strings.TrimSpace(emails[*id]))
		if e == "" {
			noEmail[strconv.FormatUint(uint64(*id), 10)] = true
		}
		return e
	}

	paths := map[string]string{}
	for _, f := range folders {
		paths[f.ID] = f.Path
		b.Folders = append(b.Folders, Folder{ID: f.ID, ParentID: f.ParentID, Name: f.Name, Path: f.Path, Description: f.Description,
			CreatedAt: f.CreateTime, UpdatedAt: f.UpdateTime, CreatedBy: email(f.CreateBy)})
	}
	sum.Folders = len(b.Folders)

	rows := map[string]map[int]SrcVersion{}
	for _, v := range vers {
		if rows[v.SecretID] == nil {
			rows[v.SecretID] = map[int]SrcVersion{}
		}
		rows[v.SecretID][v.Version] = v
	}
	exported := map[string]bool{}
	for _, s := range secs {
		label := s.Name
		if s.FolderID != nil {
			label = paths[*s.FolderID] + "/" + s.Name
		}
		out := Secret{ID: s.ID, FolderID: s.FolderID, Name: s.Name, Username: s.Username, HostURL: s.HostURL, Description: s.Description,
			Status: enum(s.Status, "SECRET_STATUS_"), CurrentVersion: s.CurrentVersion, HasTOTP: s.HasTOTP,
			CreatedAt: s.CreateTime, UpdatedAt: s.UpdateTime, CreatedBy: email(s.CreateBy), UpdatedBy: email(s.UpdateBy)}
		if len(s.Metadata) > 0 && string(s.Metadata) != "null" {
			out.Metadata = json.RawMessage(s.Metadata)
		}
		history, err := exportHistory(ctx, kv, s, rows[s.ID], label, email, &sum)
		if err != nil {
			return nil, sum, err
		}
		out.Versions = history
		if s.HasTOTP {
			data, err := kv.Read(ctx, s.VaultPath+"/totp", 0)
			if err != nil && !errors.Is(err, ErrNoKV) {
				return nil, sum, fmt.Errorf("migrate3: vault: TOTP of %s: %w", label, err)
			}
			if u, ok := data["totp_url"].(string); ok && u != "" {
				out.TOTPURL = u
				sum.TOTP++
			} else {
				sum.TOTPMissing++
				sum.Warnings = append(sum.Warnings, fmt.Sprintf("secret %s: flagged with TOTP but Vault holds no totp_url", label))
			}
		}
		b.Secrets = append(b.Secrets, out)
		exported[s.ID] = true
		sum.SecretsByStatus[out.Status]++
	}
	sum.Secrets = len(b.Secrets)
	for _, f := range folders {
		exported[f.ID] = true
	}

	for _, p := range perms {
		if !exported[p.ResourceID] {
			sum.GrantsSkipped++
			continue
		}
		g := Grant{ResourceType: enum(p.ResourceType, "RESOURCE_TYPE_"), ResourceID: p.ResourceID, SubjectType: enum(p.SubjectType, "SUBJECT_TYPE_"),
			SubjectV3: p.SubjectID, Relation: enum(p.Relation, "RELATION_"), ExpiresAt: p.ExpiresAt, GrantedAt: p.CreateTime, GrantedBy: email(p.GrantedBy)}
		switch g.SubjectType {
		case "user":
			if n, err := strconv.ParseUint(p.SubjectID, 10, 32); err == nil {
				id := uint32(n)
				g.Subject = email(&id)
			} else {
				noEmail[p.SubjectID] = true
			}
		case "role":
			g.Subject = p.SubjectID
			if code, ok := roles[p.SubjectID]; ok && code != "" {
				g.Subject = code
			}
		default:
			g.Subject = p.SubjectID
		}
		b.Grants = append(b.Grants, g)
	}
	sum.Grants = len(b.Grants)
	sum.UsersWithoutEmail = len(noEmail)
	if sum.GrantsSkipped > 0 {
		sum.Warnings = append(sum.Warnings, fmt.Sprintf("%d permissions reference folders or secrets that are not exported (deleted)", sum.GrantsSkipped))
	}
	if sum.UsersWithoutEmail > 0 {
		sum.Warnings = append(sum.Warnings, fmt.Sprintf("%d referenced v3 users have no e-mail; their grants cannot be mapped and their records are attributed to the importing operator", sum.UsersWithoutEmail))
	}
	b.Warnings = append([]string{}, sum.Warnings...)
	return b, sum, nil
}

// exportHistory reads every version Vault still holds, ascending, and marks
// the others missing. The numbers are the union of the KV metadata and the
// v3 version rows.
func exportHistory(ctx context.Context, kv KV, s SrcSecret, rows map[int]SrcVersion, label string, email func(*uint32) string, sum *ExportSummary) ([]Version, error) {
	meta, err := kv.Metadata(ctx, s.VaultPath)
	if errors.Is(err, ErrNoKV) {
		sum.Warnings = append(sum.Warnings, fmt.Sprintf("secret %s: Vault holds no data at its path", label))
		meta, err = KVMeta{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("migrate3: vault: metadata of %s: %w", label, err)
	}
	numbers := map[int]bool{}
	for n := range meta.Versions {
		numbers[n] = true
	}
	for n := range rows {
		numbers[n] = true
	}
	sorted := make([]int, 0, len(numbers))
	for n := range numbers {
		sorted = append(sorted, n)
	}
	sort.Ints(sorted)
	out := make([]Version, 0, len(sorted))
	for _, n := range sorted {
		row, hasRow := rows[n]
		v := Version{Version: n, Comment: row.Comment, Checksum: row.Checksum, CreatedBy: email(row.CreateBy), CreatedAt: row.CreateTime}
		mv, inMeta := meta.Versions[n]
		if v.CreatedAt == nil && inMeta && !mv.CreatedTime.IsZero() {
			ct := mv.CreatedTime.UTC()
			v.CreatedAt = &ct
		}
		v.Missing = true
		if inMeta && !mv.Deleted && !mv.Destroyed {
			data, err := kv.Read(ctx, s.VaultPath, n)
			if err != nil && !errors.Is(err, ErrNoKV) {
				return nil, fmt.Errorf("migrate3: vault: %s version %d: %w", label, n, err)
			}
			if pw, ok := data["password"].(string); ok {
				v.Password, v.Missing = pw, false
			} else if err == nil {
				sum.Warnings = append(sum.Warnings, fmt.Sprintf("secret %s: version %d has no password field", label, n))
			}
		}
		sum.Versions++
		if v.Missing {
			sum.VersionsMissing++
		} else if !hasRow || row.Checksum == "" {
			sum.ChecksumUnverified++
		} else if !strings.EqualFold(sha256Hex(v.Password), strings.TrimSpace(row.Checksum)) {
			v.ChecksumMismatch = true
			sum.ChecksumMismatches = append(sum.ChecksumMismatches, fmt.Sprintf("secret %s version %d", label, n))
		}
		out = append(out, v)
	}
	return out, nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// enum turns a v3 enum value (RELATION_OWNER) into the bundle form (owner).
func enum(v, prefix string) string { return strings.ToLower(strings.TrimPrefix(v, prefix)) }

// referencedUsers collects every v3 user id the export mentions.
func referencedUsers(folders []SrcFolder, secs []SrcSecret, vers []SrcVersion, perms []SrcPermission) []uint32 {
	set := map[uint32]bool{}
	add := func(id *uint32) {
		if id != nil {
			set[*id] = true
		}
	}
	for _, f := range folders {
		add(f.CreateBy)
	}
	for _, s := range secs {
		add(s.CreateBy)
		add(s.UpdateBy)
	}
	for _, v := range vers {
		add(v.CreateBy)
	}
	for _, p := range perms {
		add(p.GrantedBy)
		if p.SubjectType == "SUBJECT_TYPE_USER" {
			if n, err := strconv.ParseUint(p.SubjectID, 10, 32); err == nil {
				id := uint32(n)
				set[id] = true
			}
		}
	}
	out := make([]uint32, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ExportConfig names the output files of RunExport.
type ExportConfig struct {
	Out, KeyOut    string
	Tenant         uint32
	IncludeDeleted bool
}

// RunExport exports and writes the sealed bundle and its key. It refuses to
// start when either output already exists.
func RunExport(ctx context.Context, cfg ExportConfig, src Source, kv KV) (ExportSummary, error) {
	if cfg.Out == "" || cfg.KeyOut == "" {
		return ExportSummary{}, errors.New("migrate3: -out and -key-out are required")
	}
	for _, p := range []string{cfg.Out, cfg.KeyOut} {
		if _, err := os.Lstat(p); err == nil {
			return ExportSummary{}, fmt.Errorf("migrate3: %s exists; refusing to overwrite", p)
		}
	}
	b, sum, err := Export(ctx, src, kv, ExportOptions{Tenant: cfg.Tenant, IncludeDeleted: cfg.IncludeDeleted})
	if err != nil {
		return sum, err
	}
	defer scrub(b)
	return sum, WriteFiles(cfg.Out, cfg.KeyOut, b)
}

// scrub drops the material references of a bundle once it is sealed or
// imported (strings cannot be wiped in Go; this only shortens their life).
func scrub(b *Bundle) {
	for i := range b.Secrets {
		b.Secrets[i].TOTPURL = ""
		for j := range b.Secrets[i].Versions {
			b.Secrets[i].Versions[j].Password = ""
		}
	}
}
