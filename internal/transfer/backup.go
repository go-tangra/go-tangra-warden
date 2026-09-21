package transfer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-freya/freya/services/warden/internal/audit"
	"github.com/go-freya/freya/services/warden/internal/authz"
	"github.com/go-freya/freya/services/warden/internal/repo"
	"github.com/go-freya/freya/services/warden/internal/secrets"
	"github.com/go-freya/freya/services/warden/internal/store"
	"github.com/go-freya/freya/services/warden/internal/vault"
)

// SchemaVersion of the backup document (research R7).
const SchemaVersion = 1

// Backup document shapes.
type (
	Backup struct {
		Module        string         `json:"module"`
		SchemaVersion int            `json:"schema_version"`
		TenantID      string         `json:"tenant_id"`
		ExportedAt    time.Time      `json:"exported_at"`
		WithMaterial  bool           `json:"with_material"`
		Folders       []BackupFolder `json:"folders"`
		Secrets       []BackupSecret `json:"secrets"`
		Versions      []BackupVer    `json:"versions"`
		Grants        []BackupGrant  `json:"grants"`
		Shares        []any          `json:"shares"`
	}
	BackupFolder struct {
		ID       string  `json:"id"`
		ParentID *string `json:"parent_id"`
		Name     string  `json:"name"`
		Path     string  `json:"path"`
	}
	BackupSecret struct {
		ID             string          `json:"id"`
		FolderID       *string         `json:"folder_id"`
		Name           string          `json:"name"`
		Username       string          `json:"username"`
		HostURL        string          `json:"host_url"`
		Description    string          `json:"description"`
		Metadata       json.RawMessage `json:"metadata"`
		CurrentVersion int             `json:"current_version"`
		HasTOTP        bool            `json:"has_totp"`
		Seed           string          `json:"seed,omitempty"` // material
	}
	BackupVer struct {
		SecretID string `json:"secret_id"`
		Version  int    `json:"version"`
		Comment  string `json:"comment"`
		Checksum string `json:"checksum"`
		Source   string `json:"source"`
		Password string `json:"password,omitempty"` // material
	}
	BackupGrant struct {
		ResourceType string     `json:"resource_type"`
		ResourceID   string     `json:"resource_id"`
		SubjectType  string     `json:"subject_type"`
		SubjectID    string     `json:"subject_id"`
		Relation     string     `json:"relation"`
		ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	}
)

// BackupReport counts what an import did per entity.
type BackupReport struct {
	Folders  Counts   `json:"folders"`
	Secrets  Counts   `json:"secrets"`
	Versions Counts   `json:"versions"`
	Grants   Counts   `json:"grants"`
	Warnings []string `json:"warnings"`
}

// Counts per entity.
type Counts struct {
	Created int `json:"created"`
	Skipped int `json:"skipped"`
	Failed  int `json:"failed"`
}

// ExportBackup writes the whole tenant; with material every version carries
// its password and secrets their seed. Audited as a bulk disclosure.
func (s *Service) ExportBackup(ctx context.Context, subj authz.Subjects, withMaterial bool, v vault.Store) (Backup, error) {
	b := Backup{Module: "warden", SchemaVersion: SchemaVersion, TenantID: subj.TenantID, ExportedAt: s.now().UTC(), WithMaterial: withMaterial,
		Folders: []BackupFolder{}, Secrets: []BackupSecret{}, Versions: []BackupVer{}, Grants: []BackupGrant{}, Shares: []any{}}
	fail := func(err error) (Backup, error) {
		s.emit(audit.Event{Type: audit.BackupExported, TenantID: subj.TenantID, ActorKind: "user", ActorID: subj.UserID, SubjectKind: "backup", Outcome: "failed", Reason: describe(err)})
		return Backup{}, err
	}
	fs, err := s.st.AllFolders(ctx, subj.TenantID, MaxFolders)
	if err != nil {
		return fail(err)
	}
	ids := []string{}
	for _, f := range fs {
		b.Folders = append(b.Folders, BackupFolder{ID: f.ID, ParentID: f.ParentID, Name: f.Name, Path: f.Path})
		ids = append(ids, f.ID)
	}
	secs, err := s.st.AllSecrets(ctx, subj.TenantID, MaxItems)
	if err != nil {
		return fail(err)
	}
	for _, sec := range secs {
		bs := BackupSecret{ID: sec.ID, FolderID: sec.FolderID, Name: sec.Name, Username: sec.Username, HostURL: sec.HostURL, Description: sec.Description,
			Metadata: json.RawMessage(sec.Metadata), CurrentVersion: sec.CurrentVersion, HasTOTP: sec.HasTOTP}
		if len(bs.Metadata) == 0 {
			bs.Metadata = json.RawMessage("{}")
		}
		if withMaterial && sec.HasTOTP {
			seed, err := v.GetTOTP(ctx, subj.TenantID, sec.ID)
			if err != nil && !errors.Is(err, vault.ErrNotFound) {
				return fail(err)
			}
			bs.Seed = seed
		}
		b.Secrets = append(b.Secrets, bs)
		ids = append(ids, sec.ID)
		vers, err := s.st.VersionsOf(ctx, subj.TenantID, sec.ID)
		if err != nil {
			return fail(err)
		}
		sort.Slice(vers, func(i, j int) bool { return vers[i].Version < vers[j].Version })
		for _, ver := range vers {
			bv := BackupVer{SecretID: sec.ID, Version: ver.Version, Comment: ver.Comment, Checksum: ver.Checksum, Source: ver.Source}
			if withMaterial && !ver.MaterialMissing {
				pw, err := v.GetPassword(ctx, subj.TenantID, sec.ID, ver.Version)
				if err != nil && !errors.Is(err, vault.ErrNotFound) {
					return fail(err)
				}
				bv.Password = pw
			}
			b.Versions = append(b.Versions, bv)
		}
	}
	grants, err := s.st.GrantsOnResources(ctx, subj.TenantID, ids)
	if err != nil {
		return fail(err)
	}
	for _, g := range grants {
		b.Grants = append(b.Grants, BackupGrant{ResourceType: g.ResourceType, ResourceID: g.ResourceID, SubjectType: g.SubjectType, SubjectID: g.SubjectID, Relation: g.Relation, ExpiresAt: g.ExpiresAt})
	}
	s.emit(audit.Event{Type: audit.BackupExported, TenantID: subj.TenantID, ActorKind: "user", ActorID: subj.UserID, SubjectKind: "backup", Outcome: "ok",
		Details: map[string]any{"with_material": withMaterial, "folders": len(b.Folders), "secrets": len(b.Secrets), "versions": len(b.Versions), "grants": len(b.Grants)}})
	return b, nil
}

// ParseBackup decodes and checks a backup document.
func ParseBackup(data []byte) (Backup, error) {
	var b Backup
	if err := DecodeBounded(data, &b); err != nil {
		return Backup{}, err
	}
	if b.Module != "warden" || b.SchemaVersion != SchemaVersion {
		return Backup{}, fmt.Errorf("%w: unsupported backup schema", ErrInvalid)
	}
	if len(b.Folders) > MaxFolders || len(b.Secrets) > MaxItems || len(b.Versions) > MaxItems*10 || len(b.Grants) > MaxItems*4 {
		return Backup{}, fmt.Errorf("%w: too many entities", ErrInvalid)
	}
	return b, nil
}

// ImportBackup recreates the document in the caller's tenant with new ids.
// Folders come in path order under the tenant root; versions are written to
// the vault in order when they carry material, otherwise recorded as
// material_missing. The importer becomes owner of every imported resource
// and the original grants are kept.
func (s *Service) ImportBackup(ctx context.Context, subj authz.Subjects, data []byte, v vault.Store) (BackupReport, error) {
	rep := BackupReport{Warnings: []string{}}
	b, err := ParseBackup(data)
	if err != nil {
		return rep, err
	}
	folderMap := map[string]string{}
	sort.SliceStable(b.Folders, func(i, j int) bool {
		return strings.Count(b.Folders[i].Path, "/") < strings.Count(b.Folders[j].Path, "/")
	})
	by := subj.UserID
	for _, f := range b.Folders {
		var parent *string
		var ancestors []string
		path := "/" + f.Name
		if f.ParentID != nil {
			pid, ok := folderMap[*f.ParentID]
			if !ok {
				rep.Folders.Failed++
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("folder %s: parent missing", f.Path))
				continue
			}
			pf, err := s.st.GetFolder(ctx, subj.TenantID, pid)
			if err != nil {
				rep.Folders.Failed++
				continue
			}
			parent = &pid
			ancestors = append(append([]string{}, pf.Ancestors...), pf.ID)
			path = pf.Path + "/" + f.Name
		}
		nf := store.Folder{ID: store.NewID(), TenantID: subj.TenantID, ParentID: parent, Name: f.Name, Path: path, Ancestors: ancestors, CreatedBy: &by, UpdatedBy: &by}
		err := s.st.Atomic(ctx, subj.TenantID, func(tx repo.Store) error {
			if err := tx.InsertFolder(ctx, nf); err != nil {
				return err
			}
			return authz.New(tx, nil).GrantOwner(ctx, subj.TenantID, authz.Folder, nf.ID, subj.UserID)
		})
		if errors.Is(err, store.ErrConflict) {
			// Reuse the existing sibling with that name.
			kids, kerr := s.st.FolderChildren(ctx, subj.TenantID, parent)
			if kerr == nil {
				for _, k := range kids {
					if strings.EqualFold(k.Name, f.Name) {
						folderMap[f.ID] = k.ID
					}
				}
			}
			rep.Folders.Skipped++
			continue
		}
		if err != nil {
			rep.Folders.Failed++
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("folder %s: %v", f.Path, describe(err)))
			continue
		}
		folderMap[f.ID] = nf.ID
		rep.Folders.Created++
	}
	versionsOf := map[string][]BackupVer{}
	for _, ver := range b.Versions {
		versionsOf[ver.SecretID] = append(versionsOf[ver.SecretID], ver)
	}
	secretMap := map[string]string{}
	for _, bs := range b.Secrets {
		var folderID *string
		if bs.FolderID != nil {
			if nid, ok := folderMap[*bs.FolderID]; ok {
				folderID = &nid
			} else {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("secret %s: folder missing; placed at the root", bs.Name))
			}
		}
		id := store.NewID()
		path, err := vault.Path(subj.TenantID, id)
		if err != nil {
			rep.Secrets.Failed++
			continue
		}
		meta := bs.Metadata
		if len(meta) == 0 || !secrets.ValidMetadata(meta) {
			meta = json.RawMessage("{}")
		}
		row := store.Secret{ID: id, TenantID: subj.TenantID, FolderID: folderID, Name: bs.Name, Username: bs.Username, HostURL: bs.HostURL, Description: bs.Description, Metadata: []byte(meta), VaultPath: path, CreatedBy: &by, UpdatedBy: &by}
		if err := (secrets.Input{Name: bs.Name, Username: bs.Username, HostURL: bs.HostURL, Description: bs.Description, Metadata: meta}).Validate(); err != nil {
			rep.Secrets.Failed++
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("secret %s: invalid fields", bs.Name))
			continue
		}
		err = s.st.Atomic(ctx, subj.TenantID, func(tx repo.Store) error {
			if err := tx.InsertSecret(ctx, row); err != nil {
				return err
			}
			return authz.New(tx, nil).GrantOwner(ctx, subj.TenantID, authz.Secret, id, subj.UserID)
		})
		if err != nil {
			rep.Secrets.Failed++
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("secret %s: %v", bs.Name, describe(err)))
			continue
		}
		secretMap[bs.ID] = id
		rep.Secrets.Created++
		vers := versionsOf[bs.ID]
		sort.Slice(vers, func(i, j int) bool { return vers[i].Version < vers[j].Version })
		current := 0
		for _, ver := range vers {
			nv := ver.Version
			missing := ver.Password == ""
			if !missing {
				written, err := v.PutPassword(ctx, subj.TenantID, id, ver.Password)
				if err != nil {
					rep.Versions.Failed++
					rep.Warnings = append(rep.Warnings, fmt.Sprintf("secret %s version %d: %v", bs.Name, ver.Version, describe(err)))
					missing = true
				} else {
					nv = written
				}
			}
			if err := s.st.InsertVersion(ctx, store.SecretVersion{SecretID: id, TenantID: subj.TenantID, Version: nv, Comment: ver.Comment, Checksum: ver.Checksum, Source: "backup", MaterialMissing: missing, CreatedBy: &by}); err != nil {
				rep.Versions.Failed++
				continue
			}
			rep.Versions.Created++
			if nv > current {
				current = nv
			}
		}
		if current > 0 {
			if err := s.st.SetSecretVersion(ctx, subj.TenantID, id, current, &by); err != nil {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("secret %s: current version not set", bs.Name))
			}
		} else if len(vers) == 0 {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("secret %s: no versions in the backup", bs.Name))
		}
		if bs.HasTOTP && bs.Seed != "" {
			if err := v.PutTOTP(ctx, subj.TenantID, id, bs.Seed); err != nil {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("secret %s: seed not stored: %v", bs.Name, describe(err)))
			} else if err := s.st.SetSecretTOTP(ctx, subj.TenantID, id, true, &by); err != nil {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("secret %s: seed flag not set", bs.Name))
			}
		} else if bs.HasTOTP {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("secret %s: seed missing from the backup", bs.Name))
		}
	}
	for _, g := range b.Grants {
		var rid string
		var ok bool
		switch g.ResourceType {
		case authz.Folder:
			rid, ok = folderMap[g.ResourceID]
		case authz.Secret:
			rid, ok = secretMap[g.ResourceID]
		}
		if !ok || !authz.ValidRelation(g.Relation) || !authz.ValidSubjectType(g.SubjectType) {
			rep.Grants.Skipped++
			continue
		}
		if g.ExpiresAt != nil && !g.ExpiresAt.After(s.now()) {
			rep.Grants.Skipped++
			continue
		}
		if _, err := s.st.UpsertGrant(ctx, store.Grant{ID: store.NewID(), TenantID: subj.TenantID, ResourceType: g.ResourceType, ResourceID: rid, SubjectType: g.SubjectType, SubjectID: g.SubjectID, Relation: g.Relation, GrantedBy: &by, ExpiresAt: g.ExpiresAt}); err != nil {
			rep.Grants.Failed++
			continue
		}
		rep.Grants.Created++
	}
	s.emit(audit.Event{Type: audit.BackupImported, TenantID: subj.TenantID, ActorKind: "user", ActorID: subj.UserID, SubjectKind: "backup", Outcome: "ok",
		Details: map[string]any{"folders": rep.Folders.Created, "secrets": rep.Secrets.Created, "versions": rep.Versions.Created, "grants": rep.Grants.Created, "warnings": len(rep.Warnings)}})
	return rep, nil
}
