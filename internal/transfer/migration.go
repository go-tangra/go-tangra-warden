package transfer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-warden/v4/internal/audit"
	"github.com/go-tangra/go-tangra-warden/v4/internal/authz"
	"github.com/go-tangra/go-tangra-warden/v4/internal/folders"
	"github.com/go-tangra/go-tangra-warden/v4/internal/repo"
	"github.com/go-tangra/go-tangra-warden/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
	"github.com/go-tangra/go-tangra-warden/v4/internal/vault"
)

// MigrationSource labels the versions a v3 migration writes.
const MigrationSource = "migration-v3"

// ErrTenantNotEmpty refuses a migration into a tenant that already holds
// secrets: the import creates everything anew and is not idempotent.
var ErrTenantNotEmpty = errors.New("transfer: target tenant already has secrets")

// MigrationVault is the material store a migration writes to: it must be
// able to consume a version number without material so replayed histories
// keep their original numbers.
type MigrationVault interface {
	vault.Store
	SkipVersion(ctx context.Context, tenantID, secretID string) (int, error)
}

// Migration is a foreign tenant already mapped onto v4 subjects: user ids
// are v4 user UUIDs, roles are v4 role strings, the tenant subject has an
// empty id. Keys are the source ids, used only to link entities.
type Migration struct {
	TenantID string
	ActorID  string // the operator: audit actor and author of last resort
	Source   string // version source label (MigrationSource)
	Folders  []MigFolder
	Secrets  []MigSecret
	Grants   []MigGrant
}

// MigFolder is one folder with its original times and authors.
type MigFolder struct {
	Key                  string
	ParentKey            *string
	Name                 string
	CreatedAt, UpdatedAt time.Time
	CreatedBy, UpdatedBy string
}

// MigSecret is one secret with its history.
type MigSecret struct {
	Key                  string
	FolderKey            *string
	Name, Username       string
	HostURL, Description string
	Metadata             json.RawMessage
	TOTP                 string // otpauth URL or base32 secret (material)
	CreatedAt, UpdatedAt time.Time
	CreatedBy, UpdatedBy string
	Versions             []MigVersion
}

// MigVersion is one version: material, or Missing when the source no longer
// holds it.
type MigVersion struct {
	Number    int
	Password  string // material
	Missing   bool
	Comment   string
	Checksum  string // source checksum (sha256 hex of the password)
	CreatedAt time.Time
	CreatedBy string
}

// MigGrant is one relation tuple.
type MigGrant struct {
	ResourceType, ResourceKey string
	SubjectType, SubjectID    string
	Relation                  string
	ExpiresAt                 *time.Time
	GrantedAt                 time.Time
	GrantedBy                 string
}

// MigrationOptions select a dry run (no writes at all) and allow a target
// tenant that already has secrets.
type MigrationOptions struct {
	DryRun        bool
	AllowExisting bool
}

// MigrationReport counts what the import did (or, in a dry run, would do).
// It never carries material, seeds or links; entries name folders and
// secrets by their v4 path.
type MigrationReport struct {
	DryRun             bool     `json:"dry_run"`
	Folders            Counts   `json:"folders"`                 // skipped = merged into an existing folder of the same name
	Secrets            Counts   `json:"secrets"`                 //
	Versions           Counts   `json:"versions"`                // skipped = recorded as material_missing
	Grants             Counts   `json:"grants"`                  // skipped = duplicate, expired, resource not imported or merged
	TOTP               Counts   `json:"authenticators"`          // skipped = seed not accepted by v4
	Verified           int      `json:"verified"`                // secrets whose stored password matched the checksum
	Unowned            int      `json:"resources_without_owner"` // imported folders/secrets with no owner grant
	ChecksumMismatches []string `json:"checksum_mismatches"`
	NameConflicts      []string `json:"name_conflicts"`
	ValidationFailures []string `json:"validation_failures"`
	Warnings           []string `json:"warnings"`
}

// Failed reports whether anything needs the operator's attention.
func (r MigrationReport) Failed() bool {
	return r.Folders.Failed+r.Secrets.Failed+r.Versions.Failed+r.Grants.Failed+r.TOTP.Failed > 0 ||
		len(r.ChecksumMismatches) > 0 || len(r.ValidationFailures) > 0
}

// migFolderInfo is a folder of the target tenant as the import sees it.
type migFolderInfo struct {
	id        string
	path      string
	ancestors []string
	existing  bool // present before the import (merged into)
}

type migration struct {
	s        *Service
	m        Migration
	v        MigrationVault
	dry      bool
	rep      *MigrationReport
	folders  map[string]migFolderInfo            // source key → target folder
	byID     map[string]migFolderInfo            // target id → folder
	siblings map[string]map[string]migFolderInfo // parent id ("" = root) → lower(name) → folder
	secrets  map[string]string                   // source key → new secret id
	parent   map[string]string                   // new secret id → folder id ("" = root)
	names    map[string]map[string]bool          // folder id → lower(secret name) taken
	owned    map[string]bool                     // resource id → has an owner grant
}

// ImportMigration writes a mapped foreign tenant: folders parent-first with
// their original times and authors, each secret's versions replayed into the
// vault with their original numbers (versions the source no longer holds are
// skipped in the vault and recorded as material_missing), the TOTP seed in
// v4's canonical form, and the original grants (deduplicated, strongest
// relation kept). Unlike ImportBackup the importer receives no grant. Each
// secret is written vault first, then its row and versions in one
// transaction; a failure removes the material again. After each secret the
// stored current password is checked against the source checksum. A dry run
// reads the target tenant (conflicts) and writes nothing.
func (s *Service) ImportMigration(ctx context.Context, m Migration, v MigrationVault, o MigrationOptions) (MigrationReport, error) {
	rep := MigrationReport{DryRun: o.DryRun, ChecksumMismatches: []string{}, NameConflicts: []string{}, ValidationFailures: []string{}, Warnings: []string{}}
	if _, err := vault.Path(m.TenantID, m.ActorID); err != nil {
		return rep, fmt.Errorf("%w: tenant and actor must be UUIDs", ErrInvalid)
	}
	if m.Source == "" {
		m.Source = MigrationSource
	}
	if !o.AllowExisting {
		existing, err := s.st.AllSecrets(ctx, m.TenantID, 1)
		if err != nil {
			return rep, err
		}
		if len(existing) > 0 {
			return rep, ErrTenantNotEmpty
		}
	}
	im := &migration{s: s, m: m, v: v, dry: o.DryRun, rep: &rep,
		folders: map[string]migFolderInfo{}, byID: map[string]migFolderInfo{}, siblings: map[string]map[string]migFolderInfo{},
		secrets: map[string]string{}, parent: map[string]string{}, names: map[string]map[string]bool{}, owned: map[string]bool{}}
	if err := im.importFolders(ctx); err != nil {
		return rep, err
	}
	for _, sec := range m.Secrets {
		im.importSecret(ctx, sec)
	}
	im.importGrants(ctx)
	rep.Unowned = im.unowned()
	if rep.Unowned > 0 {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("%d imported folders/secrets have no owner grant", rep.Unowned))
	}
	if !o.DryRun {
		outcome := "ok"
		if rep.Failed() {
			outcome = "failed"
		}
		s.emit(audit.Event{Type: audit.MigrationImported, TenantID: m.TenantID, ActorKind: "user", ActorID: m.ActorID, SubjectKind: "migration", Outcome: outcome,
			Details: map[string]any{"source": m.Source, "folders": rep.Folders.Created, "folders_merged": rep.Folders.Skipped, "secrets": rep.Secrets.Created,
				"versions": rep.Versions.Created, "versions_missing": rep.Versions.Skipped, "grants": rep.Grants.Created, "authenticators": rep.TOTP.Created,
				"verified": rep.Verified, "failures": rep.Folders.Failed + rep.Secrets.Failed + rep.Versions.Failed + rep.Grants.Failed + rep.TOTP.Failed,
				"checksum_mismatches": len(rep.ChecksumMismatches), "warnings": len(rep.Warnings)}})
	}
	return rep, nil
}

func (im *migration) author(id string) *string {
	if id == "" {
		id = im.m.ActorID
	}
	return &id
}

func (im *migration) invalid(format string, a ...any) {
	im.rep.ValidationFailures = append(im.rep.ValidationFailures, fmt.Sprintf(format, a...))
}

// children returns the folders directly under parentID (lower(name) → folder),
// loading pre-existing ones from the target tenant on first use.
func (im *migration) children(ctx context.Context, parentID string) (map[string]migFolderInfo, error) {
	if kids, ok := im.siblings[parentID]; ok {
		return kids, nil
	}
	kids := map[string]migFolderInfo{}
	parent, known := im.byID[parentID]
	if parentID == "" || (known && parent.existing) {
		var pid *string
		if parentID != "" {
			pid = &parentID
		}
		rows, err := im.s.st.FolderChildren(ctx, im.m.TenantID, pid)
		if err != nil {
			return nil, err
		}
		for _, f := range rows {
			fi := migFolderInfo{id: f.ID, path: f.Path, ancestors: f.Ancestors, existing: true}
			kids[strings.ToLower(f.Name)] = fi
			im.byID[f.ID] = fi
		}
	}
	im.siblings[parentID] = kids
	return kids, nil
}

// importFolders creates folders parent-first. A folder whose parent is
// missing, invalid or part of a cycle fails with its subtree; a name that
// already exists among the siblings (case-insensitively) is merged into it.
func (im *migration) importFolders(ctx context.Context) error {
	keys := map[string]bool{}
	kids := map[string][]MigFolder{}
	done := map[string]bool{}
	for _, f := range im.m.Folders {
		keys[f.Key] = true
	}
	type item struct {
		f         MigFolder
		parentKey string // "" = root
	}
	var queue []item
	for _, f := range im.m.Folders {
		switch {
		case f.ParentKey == nil:
			queue = append(queue, item{f: f})
		case keys[*f.ParentKey]:
			kids[*f.ParentKey] = append(kids[*f.ParentKey], f)
		}
	}
	for _, f := range im.m.Folders {
		if f.ParentKey != nil && !keys[*f.ParentKey] {
			done[f.Key] = true
			im.rep.Folders.Failed++
			im.invalid("folder %q: parent folder missing from the source", f.Name)
			im.failSubtree(kids, f.Key, f.Name, done)
		}
	}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		done[it.f.Key] = true
		ok, err := im.importFolder(ctx, it.f, it.parentKey)
		if err != nil {
			return err
		}
		if !ok {
			im.failSubtree(kids, it.f.Key, it.f.Name, done)
			continue
		}
		for _, c := range kids[it.f.Key] {
			queue = append(queue, item{f: c, parentKey: it.f.Key})
		}
	}
	cycle := 0
	for _, f := range im.m.Folders {
		if !done[f.Key] {
			cycle++
		}
	}
	if cycle > 0 {
		im.rep.Folders.Failed += cycle
		im.invalid("%d folders form a parent cycle", cycle)
	}
	return nil
}

// failSubtree fails every descendant of a folder that was not imported.
func (im *migration) failSubtree(kids map[string][]MigFolder, key, name string, done map[string]bool) {
	var walk func(k string) int
	walk = func(k string) int {
		n := 0
		for _, c := range kids[k] {
			if done[c.Key] {
				continue
			}
			done[c.Key] = true
			n += 1 + walk(c.Key)
		}
		return n
	}
	if n := walk(key); n > 0 {
		im.rep.Folders.Failed += n
		im.invalid("folder %q: %d sub-folders not imported with their parent", name, n)
	}
}

// importFolder places one folder under its (already placed) parent.
func (im *migration) importFolder(ctx context.Context, f MigFolder, parentKey string) (bool, error) {
	var parent migFolderInfo
	parentID := ""
	if parentKey != "" {
		parent = im.folders[parentKey]
		parentID = parent.id
	}
	path := parent.path + "/" + f.Name
	if !folders.ValidName(f.Name) {
		im.rep.Folders.Failed++
		im.invalid("folder %q under %q: folder name invalid (1-%d characters, no '/' or control characters)", f.Name, parent.path+"/", folders.NameMax)
		return false, nil
	}
	siblings, err := im.children(ctx, parentID)
	if err != nil {
		return false, err
	}
	if same, ok := siblings[strings.ToLower(f.Name)]; ok {
		im.folders[f.Key] = same
		im.rep.Folders.Skipped++
		what := "an existing folder"
		if !same.existing {
			what = "another imported folder"
		}
		im.rep.NameConflicts = append(im.rep.NameConflicts, fmt.Sprintf("folder %s merged into %s %s", path, what, same.path))
		return true, nil
	}
	fi := migFolderInfo{id: store.NewID(), path: path}
	if parentID != "" {
		fi.ancestors = append(append([]string{}, parent.ancestors...), parentID)
	}
	if !im.dry {
		var pid *string
		if parentID != "" {
			pid = &parentID
		}
		row := store.Folder{ID: fi.id, TenantID: im.m.TenantID, ParentID: pid, Name: f.Name, Path: path, Ancestors: fi.ancestors,
			CreatedBy: im.author(f.CreatedBy), UpdatedBy: im.author(f.UpdatedBy), CreatedAt: f.CreatedAt, UpdatedAt: f.UpdatedAt}
		if err := im.s.st.InsertFolder(ctx, row); err != nil {
			im.rep.Folders.Failed++
			im.rep.Warnings = append(im.rep.Warnings, fmt.Sprintf("folder %s: %s", path, describe(err)))
			return false, nil
		}
	}
	im.folders[f.Key] = fi
	im.byID[fi.id] = fi
	siblings[strings.ToLower(f.Name)] = fi
	im.siblings[fi.id] = map[string]migFolderInfo{}
	im.rep.Folders.Created++
	return true, nil
}

// secretNames returns the lower-cased secret names already used in a folder.
func (im *migration) secretNames(ctx context.Context, folderID string) map[string]bool {
	if n, ok := im.names[folderID]; ok {
		return n
	}
	n := map[string]bool{}
	if fi, ok := im.byID[folderID]; folderID == "" || (ok && fi.existing) {
		var fid *string
		if folderID != "" {
			fid = &folderID
		}
		after, afterID := "", ""
		for {
			page, err := im.s.st.SecretsInFolder(ctx, im.m.TenantID, fid, after, afterID, 500)
			if err != nil || len(page) == 0 {
				break
			}
			for _, s := range page {
				n[strings.ToLower(s.Name)] = true
			}
			after, afterID = page[len(page)-1].Name, page[len(page)-1].ID
		}
	}
	im.names[folderID] = n
	return n
}

// validSecret checks the fields and the history; it returns the versions in
// ascending order, the current (highest with material) version and the
// normalised metadata.
func (im *migration) validSecret(sec MigSecret, label string) ([]MigVersion, int, json.RawMessage, bool) {
	meta := sec.Metadata
	if len(meta) == 0 || string(meta) == "null" {
		meta = json.RawMessage("{}")
	}
	if err := (secrets.Input{Name: sec.Name, Username: sec.Username, HostURL: sec.HostURL, Description: sec.Description, Metadata: meta}).Validate(); err != nil {
		im.invalid("secret %s: secret fields invalid (name 1-%d, username %d, host %d, description %d characters; metadata a JSON object <= %d bytes)",
			label, secrets.NameMax, secrets.UsernameMax, secrets.HostURLMax, secrets.DescriptionMax, secrets.MetadataMax)
		return nil, 0, nil, false
	}
	vers := append([]MigVersion(nil), sec.Versions...)
	sort.Slice(vers, func(i, j int) bool { return vers[i].Number < vers[j].Number })
	current := 0
	for i, ver := range vers {
		if ver.Number < 1 || ver.Number > maxMigrationVersion || (i > 0 && vers[i-1].Number == ver.Number) {
			im.invalid("secret %s: version number %d invalid", label, ver.Number)
			return nil, 0, nil, false
		}
		if ver.Missing {
			continue
		}
		if len(ver.Password) > secrets.PasswordMax {
			im.invalid("secret %s: version %d password too long (> %d bytes)", label, ver.Number, secrets.PasswordMax)
			return nil, 0, nil, false
		}
		current = ver.Number
	}
	if current == 0 {
		im.invalid("secret %s: no recoverable password (every version is missing)", label)
		return nil, 0, nil, false
	}
	for i := range vers {
		if r := []rune(vers[i].Comment); len(r) > secrets.CommentMax {
			vers[i].Comment = string(r[:secrets.CommentMax])
			im.rep.Warnings = append(im.rep.Warnings, fmt.Sprintf("secret %s: version %d comment truncated to %d characters", label, vers[i].Number, secrets.CommentMax))
		}
	}
	return vers, current, meta, true
}

// maxMigrationVersion bounds replayed version numbers.
const maxMigrationVersion = 10000

func (im *migration) importSecret(ctx context.Context, sec MigSecret) {
	folderID, folderPath := "", ""
	if sec.FolderKey != nil {
		fi, ok := im.folders[*sec.FolderKey]
		if !ok {
			im.rep.Secrets.Failed++
			im.invalid("secret %q: its folder was not imported", sec.Name)
			return
		}
		folderID, folderPath = fi.id, fi.path
	}
	label := folderPath + "/" + sec.Name
	vers, current, meta, ok := im.validSecret(sec, label)
	if !ok {
		im.rep.Secrets.Failed++
		return
	}
	taken := im.secretNames(ctx, folderID)
	if taken[strings.ToLower(sec.Name)] {
		im.rep.NameConflicts = append(im.rep.NameConflicts, fmt.Sprintf("secret %s: another secret with this name exists in the folder (both kept)", label))
	}
	taken[strings.ToLower(sec.Name)] = true
	seed := ""
	if sec.TOTP != "" {
		var err error
		if seed, err = secrets.NormalizeSeed(sec.TOTP); err != nil {
			seed = ""
			im.rep.TOTP.Skipped++
			im.rep.Warnings = append(im.rep.Warnings, fmt.Sprintf("secret %s: TOTP not accepted by v4 (base32 secret; SHA1/SHA256/SHA512; 6 or 8 digits; period 15-120 s); imported without it", label))
		}
	}
	if im.dry {
		im.countSecret(vers, seed)
		id := store.NewID()
		im.secrets[sec.Key], im.parent[id] = id, folderID
		return
	}
	id := store.NewID()
	if err := im.writeMaterial(ctx, id, vers, seed); err != nil {
		_ = im.v.DeleteSecret(ctx, im.m.TenantID, id)
		im.rep.Secrets.Failed++
		im.rep.Warnings = append(im.rep.Warnings, fmt.Sprintf("secret %s: vault write failed: %s", label, describe(err)))
		return
	}
	path, _ := vault.Path(im.m.TenantID, id)
	var fid *string
	if folderID != "" {
		fid = &folderID
	}
	row := store.Secret{ID: id, TenantID: im.m.TenantID, FolderID: fid, Name: sec.Name, Username: sec.Username, HostURL: sec.HostURL, Description: sec.Description,
		Metadata: []byte(meta), VaultPath: path, CurrentVersion: current, HasTOTP: seed != "",
		CreatedBy: im.author(sec.CreatedBy), UpdatedBy: im.author(sec.UpdatedBy), CreatedAt: sec.CreatedAt, UpdatedAt: sec.UpdatedAt}
	err := im.s.st.Atomic(ctx, im.m.TenantID, func(tx repo.Store) error {
		if err := tx.InsertSecret(ctx, row); err != nil {
			return err
		}
		for _, ver := range vers {
			sum := ver.Checksum
			if !ver.Missing {
				sum = secrets.Checksum(ver.Password)
			}
			if err := tx.InsertVersion(ctx, store.SecretVersion{SecretID: id, TenantID: im.m.TenantID, Version: ver.Number, Comment: ver.Comment, Checksum: sum,
				Source: im.m.Source, MaterialMissing: ver.Missing, CreatedBy: im.author(ver.CreatedBy), CreatedAt: ver.CreatedAt}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = im.v.DeleteSecret(ctx, im.m.TenantID, id)
		im.rep.Secrets.Failed++
		im.rep.Warnings = append(im.rep.Warnings, fmt.Sprintf("secret %s: %s", label, describe(err)))
		return
	}
	im.secrets[sec.Key] = id
	im.parent[id] = folderID
	im.countSecret(vers, seed)
	im.verify(ctx, id, label, vers)
}

func (im *migration) countSecret(vers []MigVersion, seed string) {
	im.rep.Secrets.Created++
	for _, ver := range vers {
		if ver.Missing {
			im.rep.Versions.Skipped++
		} else {
			im.rep.Versions.Created++
		}
	}
	if seed != "" {
		im.rep.TOTP.Created++
	}
}

// writeMaterial replays the history into the vault so every version keeps
// its number: numbers without material are consumed by SkipVersion.
func (im *migration) writeMaterial(ctx context.Context, id string, vers []MigVersion, seed string) error {
	byNumber := map[int]MigVersion{}
	for _, ver := range vers {
		byNumber[ver.Number] = ver
	}
	last := vers[len(vers)-1].Number
	for n := 1; n <= last; n++ {
		var got int
		var err error
		if ver, ok := byNumber[n]; ok && !ver.Missing {
			got, err = im.v.PutPassword(ctx, im.m.TenantID, id, ver.Password)
		} else {
			got, err = im.v.SkipVersion(ctx, im.m.TenantID, id)
		}
		if err != nil {
			return err
		}
		if got != n {
			return fmt.Errorf("%w: vault wrote version %d, expected %d", ErrInvalid, got, n)
		}
	}
	if seed != "" {
		return im.v.PutTOTP(ctx, im.m.TenantID, id, seed)
	}
	return nil
}

// verify reads the stored current password back and compares its sha256
// with the source checksum (or, without one, with the source password).
func (im *migration) verify(ctx context.Context, id, label string, vers []MigVersion) {
	var cur MigVersion
	for _, ver := range vers {
		if !ver.Missing {
			cur = ver
		}
	}
	want := strings.ToLower(cur.Checksum)
	if want == "" {
		want = secrets.Checksum(cur.Password)
	}
	pw, err := im.v.GetPassword(ctx, im.m.TenantID, id, 0)
	if err != nil || secrets.Checksum(pw) != want {
		im.rep.ChecksumMismatches = append(im.rep.ChecksumMismatches, fmt.Sprintf("secret %s: stored version %d does not match the source checksum", label, cur.Number))
		return
	}
	im.rep.Verified++
}

// importGrants deduplicates per (resource, subject), keeping the strongest
// relation, and writes the survivors with their original time and granter.
func (im *migration) importGrants(ctx context.Context) {
	type key struct{ rt, rk, st, sid string }
	best := map[key]int{}
	var order []key
	for i, g := range im.m.Grants {
		if !authz.ValidResourceType(g.ResourceType) || !authz.ValidSubjectType(g.SubjectType) || !authz.ValidRelation(g.Relation) {
			im.rep.Grants.Failed++
			im.invalid("grant %s on %s %s: invalid resource type, subject type or relation", g.Relation, g.ResourceType, g.ResourceKey)
			continue
		}
		if g.SubjectType == authz.SubjectTenant {
			g.SubjectID = ""
			im.m.Grants[i].SubjectID = ""
		}
		k := key{g.ResourceType, g.ResourceKey, g.SubjectType, g.SubjectID}
		prev, seen := best[k]
		switch {
		case !seen:
			best[k] = i
			order = append(order, k)
		case authzRank(g.Relation) > authzRank(im.m.Grants[prev].Relation):
			best[k] = i
			im.rep.Grants.Skipped++
		default:
			im.rep.Grants.Skipped++
		}
	}
	now := im.s.now()
	skipped := map[string]int{}
	for _, k := range order {
		g := im.m.Grants[best[k]]
		var rid string
		var ok bool
		if g.ResourceType == authz.Folder {
			var fi migFolderInfo
			fi, ok = im.folders[g.ResourceKey]
			if ok && fi.existing {
				skipped["on folders merged into existing ones"]++
				continue
			}
			rid = fi.id
		} else {
			rid, ok = im.secrets[g.ResourceKey]
		}
		if !ok {
			skipped["on resources not imported"]++
			continue
		}
		if g.ExpiresAt != nil && !g.ExpiresAt.After(now) {
			skipped["expired"]++
			continue
		}
		if !im.dry {
			if _, err := im.s.st.UpsertGrant(ctx, store.Grant{ID: store.NewID(), TenantID: im.m.TenantID, ResourceType: g.ResourceType, ResourceID: rid,
				SubjectType: g.SubjectType, SubjectID: g.SubjectID, Relation: g.Relation, GrantedBy: im.author(g.GrantedBy), GrantedAt: g.GrantedAt, ExpiresAt: g.ExpiresAt}); err != nil {
				im.rep.Grants.Failed++
				im.rep.Warnings = append(im.rep.Warnings, fmt.Sprintf("grant %s on %s: %s", g.Relation, g.ResourceType, describe(err)))
				continue
			}
		}
		im.rep.Grants.Created++
		if g.Relation == authz.Owner {
			im.owned[rid] = true
		}
	}
	reasons := make([]string, 0, len(skipped))
	for r := range skipped {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		im.rep.Grants.Skipped += skipped[r]
		im.rep.Warnings = append(im.rep.Warnings, fmt.Sprintf("%d grants skipped: %s", skipped[r], r))
	}
}

// unowned counts the imported folders and secrets that nobody owns, directly
// or through an ancestor folder (folders that existed before are not counted).
func (im *migration) unowned() int {
	ownedFolder := func(fi migFolderInfo) bool {
		if fi.existing || im.owned[fi.id] {
			return true
		}
		for _, a := range fi.ancestors {
			if im.owned[a] || im.byID[a].existing {
				return true
			}
		}
		return false
	}
	n := 0
	for _, fi := range im.byID {
		if !ownedFolder(fi) {
			n++
		}
	}
	for _, id := range im.secrets {
		if im.owned[id] {
			continue
		}
		if fid := im.parent[id]; fid == "" || !ownedFolder(im.byID[fid]) {
			n++
		}
	}
	return n
}

// authzRank orders relations (owner > editor > sharer > viewer).
func authzRank(r string) int {
	switch r {
	case authz.Owner:
		return 4
	case authz.Editor:
		return 3
	case authz.Sharer:
		return 2
	}
	return 1
}
