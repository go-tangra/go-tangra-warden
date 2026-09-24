// Package secrets manages credential metadata in the database and their
// material in the vault: create, read, update, reveal, versioned password
// changes with restore, move, delete, search and TOTP. Writes are two-phase
// (row, vault, commit) and repaired by Reconcile; every operation is audited
// and material never appears in metadata, logs or audit details.
package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-tangra/go-tangra-warden/v4/internal/audit"
	"github.com/go-tangra/go-tangra-warden/v4/internal/authz"
	"github.com/go-tangra/go-tangra-warden/v4/internal/repo"
	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
	"github.com/go-tangra/go-tangra-warden/v4/internal/vault"
)

// Limits (contracts/warden-api.openapi.yaml).
const (
	NameMax        = 200
	UsernameMax    = 200
	HostURLMax     = 2048
	DescriptionMax = 2000
	MetadataMax    = 16 << 10
	PasswordMax    = 4096
	CommentMax     = 500
	SearchMax      = 200
)

// Errors.
var (
	ErrInvalid          = errors.New("secrets: invalid input")
	ErrVaultUnavailable = vault.ErrUnavailable
	ErrNotFound         = authz.ErrNotFound
	ErrForbidden        = authz.ErrForbidden
	ErrNoTOTP           = errors.New("secrets: no totp seed")
)

// Service is the secrets service.
type Service struct {
	st    repo.Store
	vault vault.Store
	az    *authz.Authz
	audit *audit.Writer
	now   func() time.Time
}

// New wires the service.
func New(st repo.Store, v vault.Store, az *authz.Authz, aw *audit.Writer) *Service {
	return &Service{st: st, vault: v, az: az, audit: aw, now: time.Now}
}

// SetClock injects the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Input creates or updates a secret. Password and TOTP are material.
type Input struct {
	FolderID    *string
	Name        string
	Username    string
	HostURL     string
	Description string
	Metadata    json.RawMessage
	Password    string
	TOTP        string
	Source      string // version source label; "" = create (import, backup)
}

// Patch updates metadata fields; nil = unchanged.
type Patch struct {
	Name        *string
	Username    *string
	HostURL     *string
	Description *string
	Metadata    json.RawMessage
}

// View is a secret without material.
type View struct {
	ID             string            `json:"id"`
	FolderID       *string           `json:"folder_id"`
	FolderPath     string            `json:"folder_path"`
	Name           string            `json:"name"`
	Username       string            `json:"username"`
	HostURL        string            `json:"host_url"`
	Description    string            `json:"description"`
	Metadata       json.RawMessage   `json:"metadata"`
	CurrentVersion int               `json:"current_version"`
	HasTOTP        bool              `json:"has_totp"`
	CreatedBy      string            `json:"created_by,omitempty"`
	UpdatedBy      string            `json:"updated_by,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
	Permissions    authz.Permissions `json:"permissions"`
}

// VersionView is one version without material.
type VersionView struct {
	Version   int       `json:"version"`
	Comment   string    `json:"comment"`
	Checksum  string    `json:"checksum"`
	Source    string    `json:"source"`
	Missing   bool      `json:"material_missing"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Current   bool      `json:"current"`
}

func view(sec store.Secret, p authz.Permissions) View {
	v := View{ID: sec.ID, FolderID: sec.FolderID, FolderPath: sec.FolderPath, Name: sec.Name, Username: sec.Username, HostURL: sec.HostURL, Description: sec.Description,
		Metadata: json.RawMessage(sec.Metadata), CurrentVersion: sec.CurrentVersion, HasTOTP: sec.HasTOTP, CreatedAt: sec.CreatedAt, UpdatedAt: sec.UpdatedAt, Permissions: p}
	if len(v.Metadata) == 0 {
		v.Metadata = json.RawMessage("{}")
	}
	if sec.CreatedBy != nil {
		v.CreatedBy = *sec.CreatedBy
	}
	if sec.UpdatedBy != nil {
		v.UpdatedBy = *sec.UpdatedBy
	}
	return v
}

// Checksum is the hex SHA-256 of the material (integrity, never reversible).
func Checksum(material string) string {
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func validText(s string, max int, required bool) bool {
	if len(s) > max || (required && strings.TrimSpace(s) == "") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return false
		}
	}
	return true
}

// ValidMetadata checks a free-form JSON object within the size limit.
func ValidMetadata(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	if len(raw) > MetadataMax {
		return false
	}
	var m map[string]any
	return json.Unmarshal(raw, &m) == nil && m != nil
}

// Validate checks the metadata fields of an input (no material rules).
func (in Input) Validate() error { return in.validate(false) }

func (in Input) validate(create bool) error {
	if !validText(in.Name, NameMax, true) || !validText(in.Username, UsernameMax, false) || !validText(in.HostURL, HostURLMax, false) || !validText(in.Description, DescriptionMax, false) {
		return ErrInvalid
	}
	if !ValidMetadata(in.Metadata) {
		return ErrInvalid
	}
	if create && in.Password == "" {
		return ErrInvalid
	}
	if len(in.Password) > PasswordMax {
		return ErrInvalid
	}
	return nil
}

func mapErr(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, vault.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, vault.ErrBadPath):
		return ErrInvalid
	}
	return err
}

func (s *Service) emit(e audit.Event) {
	if s.audit != nil {
		_ = s.audit.Emit(e)
	}
}

func (s *Service) event(t audit.EventType, subj authz.Subjects, id, outcome, reason string, details map[string]any) {
	s.emit(audit.Event{Type: t, TenantID: subj.TenantID, ActorKind: "user", ActorID: subj.UserID, SubjectKind: "secret", SubjectID: id, Outcome: outcome, Reason: reason, Details: details})
}

// Create stores a secret: the row (version 0) and the creator-owner grant,
// then the material in the vault, then the version row and current version.
// A vault failure leaves nothing behind; a failure after the vault write is
// settled by Reconcile.
func (s *Service) Create(ctx context.Context, subj authz.Subjects, in Input) (View, error) {
	return s.create(ctx, subj, in, false)
}

// CreateChecked is Create for callers that already verified write on the
// target folder for this request (bulk imports into folders they own).
func (s *Service) CreateChecked(ctx context.Context, subj authz.Subjects, in Input) (View, error) {
	return s.create(ctx, subj, in, true)
}

func (s *Service) create(ctx context.Context, subj authz.Subjects, in Input, checked bool) (View, error) {
	if err := in.validate(true); err != nil {
		return View{}, err
	}
	var seed string
	if in.TOTP != "" {
		var err error
		if seed, err = NormalizeSeed(in.TOTP); err != nil {
			return View{}, err
		}
	}
	if in.FolderID != nil && !checked {
		if _, err := s.az.Require(ctx, subj, authz.Folder, *in.FolderID, authz.Write); err != nil {
			return View{}, err
		}
	}
	id := store.NewID()
	path, err := vault.Path(subj.TenantID, id)
	if err != nil {
		return View{}, ErrInvalid
	}
	by := subj.UserID
	row := store.Secret{ID: id, TenantID: subj.TenantID, FolderID: in.FolderID, Name: in.Name, Username: in.Username, HostURL: in.HostURL, Description: in.Description,
		Metadata: []byte(in.Metadata), VaultPath: path, CreatedBy: &by, UpdatedBy: &by}
	err = s.st.Atomic(ctx, subj.TenantID, func(tx repo.Store) error {
		if err := tx.InsertSecret(ctx, row); err != nil {
			return err
		}
		return authz.New(tx, nil).GrantOwner(ctx, subj.TenantID, authz.Secret, id, subj.UserID)
	})
	if err != nil {
		return View{}, mapErr(err)
	}
	version, err := s.vault.PutPassword(ctx, subj.TenantID, id, in.Password)
	if err != nil {
		_ = s.st.HardDeleteSecret(ctx, subj.TenantID, id)
		s.event(audit.SecretCreated, subj, id, "failed", "vault_unavailable", nil)
		s.emit(audit.Event{Type: audit.VaultUnavailable, TenantID: subj.TenantID, ActorKind: "system", SubjectKind: "system", Outcome: "failed", Reason: "put"})
		return View{}, mapErr(err)
	}
	source := in.Source
	if source == "" {
		source = "create"
	}
	if err := s.commitVersion(ctx, subj, id, version, "", source, Checksum(in.Password)); err != nil {
		return View{}, err // row stays at version 0; Reconcile settles it
	}
	if seed != "" {
		if err := s.vault.PutTOTP(ctx, subj.TenantID, id, seed); err != nil {
			s.event(audit.SecretTOTPSet, subj, id, "failed", "vault_unavailable", nil)
			return View{}, mapErr(err)
		}
		if err := s.st.SetSecretTOTP(ctx, subj.TenantID, id, true, &by); err != nil {
			return View{}, mapErr(err)
		}
		s.event(audit.SecretTOTPSet, subj, id, "ok", "", nil)
	}
	s.event(audit.SecretCreated, subj, id, "ok", "", map[string]any{"version": version, "folder_id": strp(in.FolderID)})
	stored, err := s.st.GetSecret(ctx, subj.TenantID, id)
	if err != nil {
		return View{}, mapErr(err)
	}
	return view(stored, authz.Of(authz.Owner)), nil
}

// commitVersion records a vault version in the database.
func (s *Service) commitVersion(ctx context.Context, subj authz.Subjects, id string, version int, comment, source, checksum string) error {
	by := subj.UserID
	return s.st.Atomic(ctx, subj.TenantID, func(tx repo.Store) error {
		if err := tx.InsertVersion(ctx, store.SecretVersion{SecretID: id, TenantID: subj.TenantID, Version: version, Comment: comment, Checksum: checksum, Source: source, CreatedBy: &by}); err != nil {
			return err
		}
		return tx.SetSecretVersion(ctx, subj.TenantID, id, version, &by)
	})
}

// Get returns a readable secret without material.
func (s *Service) Get(ctx context.Context, subj authz.Subjects, id string) (View, error) {
	d, err := s.az.Require(ctx, subj, authz.Secret, id, authz.Read)
	if err != nil {
		return View{}, err
	}
	sec, err := s.st.GetSecret(ctx, subj.TenantID, id)
	if err != nil {
		return View{}, mapErr(err)
	}
	s.event(audit.SecretRead, subj, id, "ok", "", nil)
	return view(sec, d.Permissions), nil
}

// Page is a cursor-paged list.
type Page struct {
	Items []View `json:"items"`
	Next  string `json:"next,omitempty"`
}

func encodeCursor(name, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(name + "\x00" + id))
}

func decodeCursor(c string) (name, id string, ok bool) {
	if c == "" {
		return "", "", true
	}
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(b), "\x00", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// List pages the secrets of a folder (root when nil). Under a readable folder
// every secret is readable; at the root each secret is checked.
func (s *Service) List(ctx context.Context, subj authz.Subjects, folderID *string, cursor string, limit int) (Page, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	afterName, afterID, ok := decodeCursor(cursor)
	if !ok {
		return Page{}, ErrInvalid
	}
	var inherited *authz.Permissions
	if folderID != nil {
		d, err := s.az.Require(ctx, subj, authz.Folder, *folderID, authz.Read)
		if err != nil {
			return Page{}, err
		}
		inherited = &d.Permissions
	}
	// Direct grants on secrets come from one query; secrets of one folder all
	// inherit the same folder decision, so no per-row evaluation is needed.
	direct, err := s.directSecretPermissions(ctx, subj)
	if err != nil {
		return Page{}, err
	}
	page := Page{Items: []View{}}
	for len(page.Items) < limit {
		batch, err := s.st.SecretsInFolder(ctx, subj.TenantID, folderID, afterName, afterID, limit+1)
		if err != nil {
			return Page{}, err
		}
		if len(batch) == 0 {
			break
		}
		for _, sec := range batch {
			afterName, afterID = sec.Name, sec.ID
			p := direct[sec.ID]
			if inherited != nil {
				p = union(p, *inherited)
			}
			if !p.Read {
				continue
			}
			if len(page.Items) == limit {
				page.Next = encodeCursor(page.Items[limit-1].Name, page.Items[limit-1].ID)
				return page, nil
			}
			page.Items = append(page.Items, view(sec, p))
		}
		if len(batch) <= limit {
			break
		}
	}
	return page, nil
}

// directSecretPermissions maps secret ids to the permissions the subjects
// hold through grants placed directly on those secrets (one query).
func (s *Service) directSecretPermissions(ctx context.Context, subj authz.Subjects) (map[string]authz.Permissions, error) {
	grants, err := s.st.GrantsForSubjects(ctx, subj.TenantID, subj.UserID, subj.Roles, s.now())
	if err != nil {
		return nil, err
	}
	out := map[string]authz.Permissions{}
	for _, g := range grants {
		if g.ResourceType == authz.Secret {
			out[g.ResourceID] = union(out[g.ResourceID], authz.Of(g.Relation))
		}
	}
	return out, nil
}

// folderPermissions evaluates a folder once per distinct id (search results
// span folders).
func (s *Service) folderPermissions(ctx context.Context, subj authz.Subjects, cache map[string]authz.Permissions, folderID *string) (authz.Permissions, error) {
	if folderID == nil {
		return authz.Permissions{}, nil
	}
	if p, ok := cache[*folderID]; ok {
		return p, nil
	}
	p, err := s.az.PermissionsOn(ctx, subj, authz.Folder, *folderID)
	if err != nil {
		return authz.Permissions{}, err
	}
	cache[*folderID] = p
	return p, nil
}

func union(a, b authz.Permissions) authz.Permissions {
	return authz.Permissions{Read: a.Read || b.Read, Write: a.Write || b.Write, Delete: a.Delete || b.Delete, Share: a.Share || b.Share}
}

// Search finds readable secrets by name, username, host, description or
// folder path. Material is never searched. Offset paging via the cursor.
func (s *Service) Search(ctx context.Context, subj authz.Subjects, q, cursor string, limit int) (Page, error) {
	q = strings.TrimSpace(q)
	if q == "" || len(q) > SearchMax {
		return Page{}, ErrInvalid
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	offset := 0
	if cursor != "" {
		n, err := parseOffset(cursor)
		if err != nil {
			return Page{}, ErrInvalid
		}
		offset = n
	}
	secretIDs, folderIDs, err := s.readableScope(ctx, subj)
	if err != nil {
		return Page{}, err
	}
	rows, err := s.st.SearchSecrets(ctx, subj.TenantID, q, secretIDs, folderIDs, false, offset+limit+1)
	if err != nil {
		return Page{}, err
	}
	page := Page{Items: []View{}}
	if offset > len(rows) {
		return page, nil
	}
	rows = rows[offset:]
	direct, err := s.directSecretPermissions(ctx, subj)
	if err != nil {
		return Page{}, err
	}
	folderCache := map[string]authz.Permissions{}
	for i, sec := range rows {
		if i == limit {
			page.Next = formatOffset(offset + limit)
			break
		}
		fp, err := s.folderPermissions(ctx, subj, folderCache, sec.FolderID)
		if err != nil {
			return Page{}, err
		}
		page.Items = append(page.Items, view(sec, union(direct[sec.ID], fp)))
	}
	return page, nil
}

func parseOffset(c string) (int, error) {
	if len(c) > 9 {
		return 0, ErrInvalid
	}
	n, err := strconv.Atoi(c)
	if err != nil || n < 0 {
		return 0, ErrInvalid
	}
	return n, nil
}

func formatOffset(n int) string { return strconv.Itoa(n) }

// readableScope lists the secret ids and folder ids the subjects may read
// (folder grants expanded to subtrees).
func (s *Service) readableScope(ctx context.Context, subj authz.Subjects) (secretIDs, folderIDs []string, err error) {
	grants, err := s.st.GrantsForSubjects(ctx, subj.TenantID, subj.UserID, subj.Roles, s.now())
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{}
	for _, g := range grants { // every relation carries read
		if g.ResourceType == authz.Secret {
			secretIDs = append(secretIDs, g.ResourceID)
			continue
		}
		if seen[g.ResourceID] {
			continue
		}
		sub, err := s.st.FolderSubtree(ctx, subj.TenantID, g.ResourceID)
		if err != nil {
			return nil, nil, err
		}
		for _, f := range sub {
			if !seen[f.ID] {
				seen[f.ID] = true
				folderIDs = append(folderIDs, f.ID)
			}
		}
	}
	return secretIDs, folderIDs, nil
}

// Update changes metadata fields (no new version); write is required.
func (s *Service) Update(ctx context.Context, subj authz.Subjects, id string, p Patch) (View, error) {
	if _, err := s.az.Require(ctx, subj, authz.Secret, id, authz.Write); err != nil {
		return View{}, err
	}
	sec, err := s.st.GetSecret(ctx, subj.TenantID, id)
	if err != nil {
		return View{}, mapErr(err)
	}
	var fields []string
	if p.Name != nil {
		sec.Name, fields = *p.Name, append(fields, "name")
	}
	if p.Username != nil {
		sec.Username, fields = *p.Username, append(fields, "username")
	}
	if p.HostURL != nil {
		sec.HostURL, fields = *p.HostURL, append(fields, "host_url")
	}
	if p.Description != nil {
		sec.Description, fields = *p.Description, append(fields, "description")
	}
	if p.Metadata != nil {
		sec.Metadata, fields = []byte(p.Metadata), append(fields, "metadata")
	}
	if err := (Input{Name: sec.Name, Username: sec.Username, HostURL: sec.HostURL, Description: sec.Description, Metadata: sec.Metadata}).validate(false); err != nil {
		return View{}, err
	}
	by := subj.UserID
	sec.UpdatedBy = &by
	if err := s.st.UpdateSecret(ctx, sec); err != nil {
		return View{}, mapErr(err)
	}
	s.event(audit.SecretUpdated, subj, id, "ok", "", map[string]any{"fields": fields})
	return s.Get(ctx, subj, id)
}

// Material is a revealed password.
type Material struct {
	Password string `json:"password"`
	Version  int    `json:"version"`
}

// Reveal returns the current password (version 0) or a specific version;
// read is required and the reveal is audited with the version.
func (s *Service) Reveal(ctx context.Context, subj authz.Subjects, id string, version int) (Material, error) {
	if _, err := s.az.Require(ctx, subj, authz.Secret, id, authz.Read); err != nil {
		return Material{}, err
	}
	sec, err := s.st.GetSecret(ctx, subj.TenantID, id)
	if err != nil {
		return Material{}, mapErr(err)
	}
	want := version
	if want == 0 {
		want = sec.CurrentVersion
	} else if _, err := s.st.GetVersion(ctx, subj.TenantID, id, want); err != nil {
		return Material{}, mapErr(err)
	}
	pw, err := s.vault.GetPassword(ctx, subj.TenantID, id, want)
	if err != nil {
		s.event(audit.SecretPasswordRead, subj, id, "failed", "vault_unavailable", map[string]any{"version": want})
		return Material{}, mapErr(err)
	}
	t := audit.SecretPasswordRead
	if version != 0 && version != sec.CurrentVersion {
		t = audit.SecretVersionRead
	}
	s.event(t, subj, id, "ok", "", map[string]any{"version": want})
	return Material{Password: pw, Version: want}, nil
}

// UpdatePassword stores a new version; write is required.
func (s *Service) UpdatePassword(ctx context.Context, subj authz.Subjects, id, password, comment string) (int, error) {
	return s.UpdatePasswordFrom(ctx, subj, id, password, comment, "api")
}

// UpdatePasswordFrom is UpdatePassword with a version source label
// (import, overwrite, backup).
func (s *Service) UpdatePasswordFrom(ctx context.Context, subj authz.Subjects, id, password, comment, source string) (int, error) {
	if password == "" || len(password) > PasswordMax || !validText(comment, CommentMax, false) || source == "" {
		return 0, ErrInvalid
	}
	if _, err := s.az.Require(ctx, subj, authz.Secret, id, authz.Write); err != nil {
		return 0, err
	}
	version, err := s.vault.PutPassword(ctx, subj.TenantID, id, password)
	if err != nil {
		s.event(audit.SecretPasswordUpdated, subj, id, "failed", "vault_unavailable", nil)
		return 0, mapErr(err)
	}
	if err := s.commitVersion(ctx, subj, id, version, comment, source, Checksum(password)); err != nil {
		return 0, mapErr(err)
	}
	s.event(audit.SecretPasswordUpdated, subj, id, "ok", "", map[string]any{"version": version, "source": source})
	return version, nil
}

// Readable lists every secret the subjects may read, optionally limited to a
// folder subtree (the folder itself must be readable). Used by exports; the
// caller audits the bulk disclosure.
func (s *Service) Readable(ctx context.Context, subj authz.Subjects, folderID *string, limit int) ([]View, error) {
	if limit <= 0 {
		limit = 50000
	}
	if folderID != nil {
		d, err := s.az.Require(ctx, subj, authz.Folder, *folderID, authz.Read)
		if err != nil {
			return nil, err
		}
		sub, err := s.st.FolderSubtree(ctx, subj.TenantID, *folderID)
		if err != nil {
			return nil, err
		}
		ids := make([]string, 0, len(sub))
		for _, f := range sub {
			ids = append(ids, f.ID)
		}
		rows, err := s.st.SecretsInFolders(ctx, subj.TenantID, ids)
		if err != nil {
			return nil, err
		}
		out := make([]View, 0, len(rows))
		for i, sec := range rows {
			if i == limit {
				break
			}
			out = append(out, view(sec, d.Permissions))
		}
		return out, nil
	}
	secretIDs, folderIDs, err := s.readableScope(ctx, subj)
	if err != nil {
		return nil, err
	}
	direct, err := s.directSecretPermissions(ctx, subj)
	if err != nil {
		return nil, err
	}
	folderCache := map[string]authz.Permissions{}
	seen := map[string]bool{}
	var out []View
	add := func(rows []store.Secret) error {
		for _, sec := range rows {
			if seen[sec.ID] || len(out) >= limit {
				continue
			}
			fp, err := s.folderPermissions(ctx, subj, folderCache, sec.FolderID)
			if err != nil {
				return err
			}
			seen[sec.ID] = true
			out = append(out, view(sec, union(direct[sec.ID], fp)))
		}
		return nil
	}
	if len(folderIDs) > 0 {
		rows, err := s.st.SecretsInFolders(ctx, subj.TenantID, folderIDs)
		if err != nil {
			return nil, err
		}
		if err := add(rows); err != nil {
			return nil, err
		}
	}
	if len(secretIDs) > 0 {
		rows, err := s.st.SecretsByIDs(ctx, subj.TenantID, secretIDs)
		if err != nil {
			return nil, err
		}
		if err := add(rows); err != nil {
			return nil, err
		}
	}
	if out == nil {
		out = []View{}
	}
	return out, nil
}

// MaterialOf reads the current password and seed of a readable secret
// without the per-secret audit (bulk operations audit once with counts).
func (s *Service) MaterialOf(ctx context.Context, subj authz.Subjects, v View) (password, seed string, err error) {
	if !v.Permissions.Read {
		return "", "", ErrForbidden
	}
	if v.CurrentVersion > 0 {
		if password, err = s.vault.GetPassword(ctx, subj.TenantID, v.ID, 0); err != nil {
			return "", "", mapErr(err)
		}
	}
	if v.HasTOTP {
		if seed, err = s.vault.GetTOTP(ctx, subj.TenantID, v.ID); err != nil && !errors.Is(err, vault.ErrNotFound) {
			return "", "", mapErr(err)
		}
	}
	return password, seed, nil
}

// Versions lists the versions newest first; read is required.
func (s *Service) Versions(ctx context.Context, subj authz.Subjects, id string) ([]VersionView, error) {
	if _, err := s.az.Require(ctx, subj, authz.Secret, id, authz.Read); err != nil {
		return nil, err
	}
	sec, err := s.st.GetSecret(ctx, subj.TenantID, id)
	if err != nil {
		return nil, mapErr(err)
	}
	rows, err := s.st.VersionsOf(ctx, subj.TenantID, id)
	if err != nil {
		return nil, err
	}
	out := make([]VersionView, 0, len(rows))
	for _, v := range rows {
		vv := VersionView{Version: v.Version, Comment: v.Comment, Checksum: v.Checksum, Source: v.Source, Missing: v.MaterialMissing, CreatedAt: v.CreatedAt, Current: v.Version == sec.CurrentVersion}
		if v.CreatedBy != nil {
			vv.CreatedBy = *v.CreatedBy
		}
		out = append(out, vv)
	}
	return out, nil
}

// Restore makes an old version current by writing its material as a new
// version (source "restore:<n>"); write is required.
func (s *Service) Restore(ctx context.Context, subj authz.Subjects, id string, version int, comment string) (int, error) {
	if version < 1 || !validText(comment, CommentMax, false) {
		return 0, ErrInvalid
	}
	if _, err := s.az.Require(ctx, subj, authz.Secret, id, authz.Write); err != nil {
		return 0, err
	}
	old, err := s.st.GetVersion(ctx, subj.TenantID, id, version)
	if err != nil {
		return 0, mapErr(err)
	}
	pw, err := s.vault.GetPassword(ctx, subj.TenantID, id, version)
	if err != nil {
		s.event(audit.SecretRestored, subj, id, "failed", "vault_unavailable", map[string]any{"from": version})
		return 0, mapErr(err)
	}
	nv, err := s.vault.PutPassword(ctx, subj.TenantID, id, pw)
	if err != nil {
		s.event(audit.SecretRestored, subj, id, "failed", "vault_unavailable", map[string]any{"from": version})
		return 0, mapErr(err)
	}
	if err := s.commitVersion(ctx, subj, id, nv, comment, "restore:"+formatOffset(version), old.Checksum); err != nil {
		return 0, mapErr(err)
	}
	s.event(audit.SecretRestored, subj, id, "ok", "", map[string]any{"from": version, "version": nv})
	return nv, nil
}

// Move changes the folder; write on the secret and on the target folder.
func (s *Service) Move(ctx context.Context, subj authz.Subjects, id string, folderID *string) (View, error) {
	if _, err := s.az.Require(ctx, subj, authz.Secret, id, authz.Write); err != nil {
		return View{}, err
	}
	if folderID != nil {
		if _, err := s.az.Require(ctx, subj, authz.Folder, *folderID, authz.Write); err != nil {
			return View{}, err
		}
	}
	sec, err := s.st.GetSecret(ctx, subj.TenantID, id)
	if err != nil {
		return View{}, mapErr(err)
	}
	by := subj.UserID
	if err := s.st.MoveSecret(ctx, subj.TenantID, id, folderID, &by); err != nil {
		return View{}, mapErr(err)
	}
	s.event(audit.SecretMoved, subj, id, "ok", "", map[string]any{"from": strp(sec.FolderID), "to": strp(folderID)})
	return s.Get(ctx, subj, id)
}

// Delete hides the row, destroys every vault version and the seed, then
// removes the row. When the vault is down the row stays hidden until
// Reconcile finishes the job.
func (s *Service) Delete(ctx context.Context, subj authz.Subjects, id string) error {
	if _, err := s.az.Require(ctx, subj, authz.Secret, id, authz.Delete); err != nil {
		return err
	}
	return s.destroy(ctx, subj, id)
}

// DeleteMany removes secrets of a folder subtree being deleted (the folder
// permission was checked by the caller).
func (s *Service) DeleteMany(ctx context.Context, subj authz.Subjects, ids []string) error {
	for _, id := range ids {
		if err := s.destroy(ctx, subj, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) destroy(ctx context.Context, subj authz.Subjects, id string) error {
	if err := s.st.SoftDeleteSecret(ctx, subj.TenantID, id); err != nil {
		return mapErr(err)
	}
	if err := s.vault.DeleteSecret(ctx, subj.TenantID, id); err != nil {
		s.event(audit.SecretDeleted, subj, id, "failed", "vault_unavailable", map[string]any{"pending": true})
		return mapErr(err)
	}
	if err := s.st.HardDeleteSecret(ctx, subj.TenantID, id); err != nil {
		return err
	}
	s.event(audit.SecretDeleted, subj, id, "ok", "", nil)
	return nil
}

// SetTOTP stores a seed (otpauth URL or base32); write is required.
func (s *Service) SetTOTP(ctx context.Context, subj authz.Subjects, id, seedInput string) error {
	seed, err := NormalizeSeed(seedInput)
	if err != nil {
		return err
	}
	if _, err := s.az.Require(ctx, subj, authz.Secret, id, authz.Write); err != nil {
		return err
	}
	if _, err := s.st.GetSecret(ctx, subj.TenantID, id); err != nil {
		return mapErr(err)
	}
	if err := s.vault.PutTOTP(ctx, subj.TenantID, id, seed); err != nil {
		s.event(audit.SecretTOTPSet, subj, id, "failed", "vault_unavailable", nil)
		return mapErr(err)
	}
	by := subj.UserID
	if err := s.st.SetSecretTOTP(ctx, subj.TenantID, id, true, &by); err != nil {
		return mapErr(err)
	}
	s.event(audit.SecretTOTPSet, subj, id, "ok", "", nil)
	return nil
}

// TOTPCode computes the current code; read is required. The seed never
// leaves the service.
func (s *Service) TOTPCode(ctx context.Context, subj authz.Subjects, id string) (Code, error) {
	if _, err := s.az.Require(ctx, subj, authz.Secret, id, authz.Read); err != nil {
		return Code{}, err
	}
	sec, err := s.st.GetSecret(ctx, subj.TenantID, id)
	if err != nil {
		return Code{}, mapErr(err)
	}
	if !sec.HasTOTP {
		return Code{}, ErrNoTOTP
	}
	seed, err := s.vault.GetTOTP(ctx, subj.TenantID, id)
	if err != nil {
		s.event(audit.SecretTOTPRead, subj, id, "failed", "vault_unavailable", nil)
		return Code{}, mapErr(err)
	}
	code, err := GenerateCode(seed, s.now())
	if err != nil {
		return Code{}, err
	}
	s.event(audit.SecretTOTPRead, subj, id, "ok", "", nil)
	return code, nil
}

// RemoveTOTP deletes the seed; write is required.
func (s *Service) RemoveTOTP(ctx context.Context, subj authz.Subjects, id string) error {
	if _, err := s.az.Require(ctx, subj, authz.Secret, id, authz.Write); err != nil {
		return err
	}
	if err := s.vault.DeleteTOTP(ctx, subj.TenantID, id); err != nil {
		s.event(audit.SecretTOTPRemoved, subj, id, "failed", "vault_unavailable", nil)
		return mapErr(err)
	}
	by := subj.UserID
	if err := s.st.SetSecretTOTP(ctx, subj.TenantID, id, false, &by); err != nil {
		return mapErr(err)
	}
	s.event(audit.SecretTOTPRemoved, subj, id, "ok", "", nil)
	return nil
}

func strp(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
