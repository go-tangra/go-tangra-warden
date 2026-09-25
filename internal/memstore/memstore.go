// Package memstore is the in-memory repo.Store double for unit tests. It
// applies the same tenant scoping, uniqueness and paging rules as the SQL
// repositories and supports failure injection per operation.
package memstore

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-warden/v4/internal/repo"
	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
)

// Store holds every table; exported maps ease assertions in tests.
type Store struct {
	mu       sync.Mutex
	Folders  map[string]store.Folder
	Secrets  map[string]store.Secret
	Versions map[string][]store.SecretVersion // by secret id
	Grants   map[string]store.Grant
	Shares   map[string]store.Share
	Audit    []store.AuditRow
	Fail     map[string]error // operation name → error to return
	Now      func() time.Time
}

// New returns an empty store.
func New() *Store {
	return &Store{Folders: map[string]store.Folder{}, Secrets: map[string]store.Secret{}, Versions: map[string][]store.SecretVersion{},
		Grants: map[string]store.Grant{}, Shares: map[string]store.Share{}, Fail: map[string]error{}, Now: time.Now}
}

// FailOn makes op return err until cleared (err nil).
func (m *Store) FailOn(op string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		delete(m.Fail, op)
		return
	}
	m.Fail[op] = err
}

func (m *Store) fail(op string) error { return m.Fail[op] }

type snapshot struct {
	folders  map[string]store.Folder
	secrets  map[string]store.Secret
	versions map[string][]store.SecretVersion
	grants   map[string]store.Grant
	shares   map[string]store.Share
	audit    []store.AuditRow
}

func (m *Store) snap() snapshot {
	s := snapshot{folders: map[string]store.Folder{}, secrets: map[string]store.Secret{}, versions: map[string][]store.SecretVersion{}, grants: map[string]store.Grant{}, shares: map[string]store.Share{}}
	for k, v := range m.Folders {
		s.folders[k] = v
	}
	for k, v := range m.Secrets {
		s.secrets[k] = v
	}
	for k, v := range m.Versions {
		s.versions[k] = append([]store.SecretVersion(nil), v...)
	}
	for k, v := range m.Grants {
		s.grants[k] = v
	}
	for k, v := range m.Shares {
		s.shares[k] = v
	}
	s.audit = append([]store.AuditRow(nil), m.Audit...)
	return s
}

// Atomic runs fn and rolls every table back when it fails.
func (m *Store) Atomic(_ context.Context, _ string, fn func(repo.Store) error) error {
	if err := m.fail("Atomic"); err != nil {
		return err
	}
	m.mu.Lock()
	s := m.snap()
	m.mu.Unlock()
	if err := fn(m); err != nil {
		m.mu.Lock()
		m.Folders, m.Secrets, m.Versions, m.Grants, m.Shares, m.Audit = s.folders, s.secrets, s.versions, s.grants, s.shares, s.audit
		m.mu.Unlock()
		return err
	}
	return nil
}

func strp(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func sameParent(a, b *string) bool { return strp(a) == strp(b) && (a == nil) == (b == nil) }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// stamp applies the insert timestamp rules of the database: a zero created
// time is now, a zero updated time is the created time.
func stamp(created, updated *time.Time, now time.Time) {
	if created.IsZero() {
		*created = now
	}
	if updated.IsZero() {
		*updated = *created
	}
}

// ---------------------------------------------------------------- folders

func (m *Store) InsertFolder(_ context.Context, f store.Folder) error {
	if err := m.fail("InsertFolder"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.Folders {
		if o.TenantID == f.TenantID && sameParent(o.ParentID, f.ParentID) && strings.EqualFold(o.Name, f.Name) {
			return store.ErrConflict
		}
	}
	if f.Ancestors == nil {
		f.Ancestors = []string{}
	}
	stamp(&f.CreatedAt, &f.UpdatedAt, m.Now())
	if f.UpdatedBy == nil {
		f.UpdatedBy = f.CreatedBy
	}
	m.Folders[f.ID] = f
	return nil
}

func (m *Store) GetFolder(_ context.Context, tid, id string) (store.Folder, error) {
	if err := m.fail("GetFolder"); err != nil {
		return store.Folder{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.Folders[id]
	if !ok || f.TenantID != tid {
		return store.Folder{}, store.ErrNotFound
	}
	return f, nil
}

func sortFolders(out []store.Folder, byPath bool) {
	sort.Slice(out, func(i, j int) bool {
		if byPath {
			return out[i].Path < out[j].Path
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
}

func (m *Store) FolderChildren(_ context.Context, tid string, parent *string) ([]store.Folder, error) {
	if err := m.fail("FolderChildren"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Folder
	for _, f := range m.Folders {
		if f.TenantID == tid && sameParent(f.ParentID, parent) {
			out = append(out, f)
		}
	}
	sortFolders(out, false)
	return out, nil
}

func (m *Store) AllFolders(_ context.Context, tid string, limit int) ([]store.Folder, error) {
	if err := m.fail("AllFolders"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Folder
	for _, f := range m.Folders {
		if f.TenantID == tid {
			out = append(out, f)
		}
	}
	sortFolders(out, true)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Store) FolderSubtree(_ context.Context, tid, id string) ([]store.Folder, error) {
	if err := m.fail("FolderSubtree"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Folder
	for _, f := range m.Folders {
		if f.TenantID == tid && (f.ID == id || contains(f.Ancestors, id)) {
			out = append(out, f)
		}
	}
	sortFolders(out, true)
	return out, nil
}

func parentPath(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return ""
}

func (m *Store) RenameFolder(_ context.Context, tid, id, name, by string) error {
	if err := m.fail("RenameFolder"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.Folders[id]
	if !ok || f.TenantID != tid {
		return store.ErrNotFound
	}
	for _, o := range m.Folders {
		if o.ID != id && o.TenantID == tid && sameParent(o.ParentID, f.ParentID) && strings.EqualFold(o.Name, name) {
			return store.ErrConflict
		}
	}
	oldPath := f.Path
	f.Name, f.Path, f.UpdatedAt = name, parentPath(f.Path)+"/"+name, m.Now()
	if by != "" {
		f.UpdatedBy = &by
	}
	m.Folders[id] = f
	for k, o := range m.Folders {
		if o.TenantID == tid && contains(o.Ancestors, id) {
			o.Path = f.Path + strings.TrimPrefix(o.Path, oldPath)
			m.Folders[k] = o
		}
	}
	return nil
}

func (m *Store) MoveFolder(_ context.Context, tid, id string, parent *string, anc []string, path, by string) error {
	if err := m.fail("MoveFolder"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.Folders[id]
	if !ok || f.TenantID != tid {
		return store.ErrNotFound
	}
	for _, o := range m.Folders {
		if o.ID != id && o.TenantID == tid && sameParent(o.ParentID, parent) && strings.EqualFold(o.Name, f.Name) {
			return store.ErrConflict
		}
	}
	oldPath, oldLen := f.Path, len(f.Ancestors)+1
	if anc == nil {
		anc = []string{}
	}
	f.ParentID, f.Ancestors, f.Path, f.UpdatedAt = parent, anc, path, m.Now()
	if by != "" {
		f.UpdatedBy = &by
	}
	m.Folders[id] = f
	newPrefix := append(append([]string{}, anc...), id)
	for k, o := range m.Folders {
		if o.TenantID == tid && contains(o.Ancestors, id) {
			o.Ancestors = append(append([]string{}, newPrefix...), o.Ancestors[oldLen:]...)
			o.Path = path + strings.TrimPrefix(o.Path, oldPath)
			m.Folders[k] = o
		}
	}
	return nil
}

func (m *Store) DeleteFolder(_ context.Context, tid, id string) error {
	if err := m.fail("DeleteFolder"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.Folders[id]
	if !ok || f.TenantID != tid {
		return store.ErrNotFound
	}
	for _, s := range m.Secrets {
		if s.TenantID == tid && s.FolderID != nil && (*s.FolderID == id || m.underLocked(*s.FolderID, id)) {
			return store.ErrConflict // RESTRICT
		}
	}
	for k, o := range m.Folders {
		if o.TenantID == tid && contains(o.Ancestors, id) {
			delete(m.Folders, k)
		}
	}
	delete(m.Folders, id)
	return nil
}

func (m *Store) underLocked(folderID, ancestor string) bool {
	f, ok := m.Folders[folderID]
	return ok && contains(f.Ancestors, ancestor)
}

func (m *Store) CountFolderContents(_ context.Context, tid, id string) (int, int, error) {
	if err := m.fail("CountFolderContents"); err != nil {
		return 0, 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var nf, ns int
	for _, f := range m.Folders {
		if f.TenantID == tid && f.ParentID != nil && *f.ParentID == id {
			nf++
		}
	}
	for _, s := range m.Secrets {
		if s.TenantID == tid && s.FolderID != nil && *s.FolderID == id {
			ns++
		}
	}
	return nf, ns, nil
}

// ---------------------------------------------------------------- secrets

func (m *Store) withPath(s store.Secret) store.Secret {
	s.FolderPath = ""
	if s.FolderID != nil {
		if f, ok := m.Folders[*s.FolderID]; ok {
			s.FolderPath = f.Path
		}
	}
	if len(s.Metadata) == 0 {
		s.Metadata = []byte("{}")
	}
	return s
}

func (m *Store) InsertSecret(_ context.Context, s store.Secret) error {
	if err := m.fail("InsertSecret"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.FolderID != nil {
		if f, ok := m.Folders[*s.FolderID]; !ok || f.TenantID != s.TenantID {
			return store.ErrNotFound
		}
	}
	stamp(&s.CreatedAt, &s.UpdatedAt, m.Now())
	if s.UpdatedBy == nil {
		s.UpdatedBy = s.CreatedBy
	}
	if len(s.Metadata) == 0 {
		s.Metadata = []byte("{}")
	}
	m.Secrets[s.ID] = s
	return nil
}

func (m *Store) GetSecret(_ context.Context, tid, id string) (store.Secret, error) {
	if err := m.fail("GetSecret"); err != nil {
		return store.Secret{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.Secrets[id]
	if !ok || s.TenantID != tid || s.DeletedAt != nil {
		return store.Secret{}, store.ErrNotFound
	}
	return m.withPath(s), nil
}

func sortSecrets(out []store.Secret) {
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if a != b {
			return a < b
		}
		return out[i].ID < out[j].ID
	})
}

func (m *Store) live(tid string, keep func(store.Secret) bool) []store.Secret {
	var out []store.Secret
	for _, s := range m.Secrets {
		if s.TenantID == tid && s.DeletedAt == nil && keep(s) {
			out = append(out, m.withPath(s))
		}
	}
	sortSecrets(out)
	return out
}

func (m *Store) SecretsInFolder(_ context.Context, tid string, folder *string, afterName, afterID string, limit int) ([]store.Secret, error) {
	if err := m.fail("SecretsInFolder"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	all := m.live(tid, func(s store.Secret) bool {
		if !sameParent(s.FolderID, folder) {
			return false
		}
		ln, la := strings.ToLower(s.Name), strings.ToLower(afterName)
		return ln > la || (ln == la && s.ID > afterID)
	})
	if len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

func (m *Store) SecretsByIDs(_ context.Context, tid string, ids []string) ([]store.Secret, error) {
	if err := m.fail("SecretsByIDs"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.live(tid, func(s store.Secret) bool { return contains(ids, s.ID) }), nil
}

func (m *Store) SecretsInFolders(_ context.Context, tid string, ids []string) ([]store.Secret, error) {
	if err := m.fail("SecretsInFolders"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.live(tid, func(s store.Secret) bool { return s.FolderID != nil && contains(ids, *s.FolderID) }), nil
}

func (m *Store) AllSecrets(_ context.Context, tid string, limit int) ([]store.Secret, error) {
	if err := m.fail("AllSecrets"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.live(tid, func(store.Secret) bool { return true })
	sort.SliceStable(out, func(i, j int) bool { return out[i].FolderPath < out[j].FolderPath })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Store) SearchSecrets(_ context.Context, tid, q string, sids, fids []string, root bool, limit int) ([]store.Secret, error) {
	if err := m.fail("SearchSecrets"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	lq := strings.ToLower(q)
	out := m.live(tid, func(s store.Secret) bool {
		s = m.withPath(s)
		text := strings.ToLower(s.Name + " " + s.Username + " " + s.HostURL + " " + s.Description)
		if !strings.Contains(text, lq) && !strings.Contains(strings.ToLower(s.FolderPath), lq) {
			return false
		}
		return contains(sids, s.ID) || (s.FolderID != nil && contains(fids, *s.FolderID)) || (root && s.FolderID == nil)
	})
	sort.SliceStable(out, func(i, j int) bool {
		a, b := strings.Contains(strings.ToLower(out[i].Name), lq), strings.Contains(strings.ToLower(out[j].Name), lq)
		return a && !b
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Store) mutateSecret(op, tid, id string, fn func(*store.Secret)) error {
	if err := m.fail(op); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.Secrets[id]
	if !ok || s.TenantID != tid || s.DeletedAt != nil {
		return store.ErrNotFound
	}
	fn(&s)
	s.UpdatedAt = m.Now()
	m.Secrets[id] = s
	return nil
}

func (m *Store) UpdateSecret(_ context.Context, in store.Secret) error {
	return m.mutateSecret("UpdateSecret", in.TenantID, in.ID, func(s *store.Secret) {
		s.Name, s.Username, s.HostURL, s.Description, s.Metadata, s.UpdatedBy = in.Name, in.Username, in.HostURL, in.Description, in.Metadata, in.UpdatedBy
		if len(s.Metadata) == 0 {
			s.Metadata = []byte("{}")
		}
	})
}

func (m *Store) SetSecretVersion(_ context.Context, tid, id string, v int, by *string) error {
	return m.mutateSecret("SetSecretVersion", tid, id, func(s *store.Secret) { s.CurrentVersion, s.UpdatedBy = v, by })
}

func (m *Store) SetSecretTOTP(_ context.Context, tid, id string, has bool, by *string) error {
	return m.mutateSecret("SetSecretTOTP", tid, id, func(s *store.Secret) { s.HasTOTP, s.UpdatedBy = has, by })
}

func (m *Store) MoveSecret(_ context.Context, tid, id string, folder *string, by *string) error {
	return m.mutateSecret("MoveSecret", tid, id, func(s *store.Secret) { s.FolderID, s.UpdatedBy = folder, by })
}

func (m *Store) SoftDeleteSecret(_ context.Context, tid, id string) error {
	return m.mutateSecret("SoftDeleteSecret", tid, id, func(s *store.Secret) { now := m.Now(); s.DeletedAt = &now })
}

func (m *Store) HardDeleteSecret(_ context.Context, tid, id string) error {
	if err := m.fail("HardDeleteSecret"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.Secrets[id]; ok && s.TenantID == tid {
		delete(m.Secrets, id)
		delete(m.Versions, id)
		for k, g := range m.Grants {
			if g.ResourceType == "secret" && g.ResourceID == id {
				delete(m.Grants, k)
			}
		}
		for k, sh := range m.Shares {
			if sh.SecretID == id {
				delete(m.Shares, k)
			}
		}
	}
	return nil
}

func (m *Store) SoftDeletedSecrets(_ context.Context, tid string) ([]store.Secret, error) {
	if err := m.fail("SoftDeletedSecrets"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Secret
	for _, s := range m.Secrets {
		if s.TenantID == tid && s.DeletedAt != nil {
			out = append(out, m.withPath(s))
		}
	}
	sortSecrets(out)
	return out, nil
}

func (m *Store) RecentSecrets(_ context.Context, since time.Time, limit int) ([]store.Secret, error) {
	if err := m.fail("RecentSecrets"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Secret
	for _, s := range m.Secrets {
		if s.DeletedAt == nil && !s.UpdatedAt.Before(since) {
			out = append(out, m.withPath(s))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.Before(out[j].UpdatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Store) PendingSecrets(_ context.Context, olderThan time.Time, limit int) ([]store.Secret, error) {
	if err := m.fail("PendingSecrets"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Secret
	for _, s := range m.Secrets {
		if s.DeletedAt != nil || (s.CurrentVersion == 0 && s.CreatedAt.Before(olderThan)) {
			out = append(out, m.withPath(s))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Store) InsertVersion(_ context.Context, v store.SecretVersion) error {
	if err := m.fail("InsertVersion"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.Versions[v.SecretID] {
		if o.Version == v.Version {
			return nil // ON CONFLICT DO NOTHING
		}
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = m.Now()
	}
	m.Versions[v.SecretID] = append(m.Versions[v.SecretID], v)
	return nil
}

func (m *Store) VersionsOf(_ context.Context, tid, sid string) ([]store.SecretVersion, error) {
	if err := m.fail("VersionsOf"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.SecretVersion
	for _, v := range m.Versions[sid] {
		if v.TenantID == tid {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	return out, nil
}

func (m *Store) GetVersion(_ context.Context, tid, sid string, version int) (store.SecretVersion, error) {
	if err := m.fail("GetVersion"); err != nil {
		return store.SecretVersion{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.Versions[sid] {
		if v.TenantID == tid && v.Version == version {
			return v, nil
		}
	}
	return store.SecretVersion{}, store.ErrNotFound
}

// ---------------------------------------------------------------- grants

func (m *Store) UpsertGrant(_ context.Context, g store.Grant) (store.Grant, error) {
	if err := m.fail("UpsertGrant"); err != nil {
		return store.Grant{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, o := range m.Grants {
		if o.TenantID == g.TenantID && o.ResourceType == g.ResourceType && o.ResourceID == g.ResourceID && o.SubjectType == g.SubjectType && o.SubjectID == g.SubjectID {
			if g.GrantedAt.IsZero() {
				g.GrantedAt = m.Now()
			}
			o.Relation, o.GrantedBy, o.GrantedAt, o.ExpiresAt = g.Relation, g.GrantedBy, g.GrantedAt, g.ExpiresAt
			m.Grants[k] = o
			return o, nil
		}
	}
	if g.GrantedAt.IsZero() {
		g.GrantedAt = m.Now()
	}
	m.Grants[g.ID] = g
	return g, nil
}

func (m *Store) GetGrant(_ context.Context, tid, id string) (store.Grant, error) {
	if err := m.fail("GetGrant"); err != nil {
		return store.Grant{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.Grants[id]
	if !ok || g.TenantID != tid {
		return store.Grant{}, store.ErrNotFound
	}
	return g, nil
}

func (m *Store) DeleteGrant(_ context.Context, tid, id string) error {
	if err := m.fail("DeleteGrant"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.Grants[id]
	if !ok || g.TenantID != tid {
		return store.ErrNotFound
	}
	delete(m.Grants, id)
	return nil
}

func sortGrants(out []store.Grant) {
	sort.Slice(out, func(i, j int) bool {
		if !out[i].GrantedAt.Equal(out[j].GrantedAt) {
			return out[i].GrantedAt.Before(out[j].GrantedAt)
		}
		return out[i].ID < out[j].ID
	})
}

func (m *Store) GrantsOnResources(_ context.Context, tid string, ids []string) ([]store.Grant, error) {
	if err := m.fail("GrantsOnResources"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Grant
	for _, g := range m.Grants {
		if g.TenantID == tid && contains(ids, g.ResourceID) {
			out = append(out, g)
		}
	}
	sortGrants(out)
	return out, nil
}

func (m *Store) GrantsForSubjects(_ context.Context, tid, uid string, roles []string, now time.Time) ([]store.Grant, error) {
	if err := m.fail("GrantsForSubjects"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Grant
	for _, g := range m.Grants {
		if g.TenantID != tid || (g.ExpiresAt != nil && !g.ExpiresAt.After(now)) {
			continue
		}
		switch g.SubjectType {
		case "user":
			if g.SubjectID != uid {
				continue
			}
		case "role":
			if !contains(roles, g.SubjectID) {
				continue
			}
		}
		out = append(out, g)
	}
	sortGrants(out)
	return out, nil
}

func (m *Store) DeleteGrantsOfResource(_ context.Context, tid, rtype, rid string) error {
	if err := m.fail("DeleteGrantsOfResource"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, g := range m.Grants {
		if g.TenantID == tid && g.ResourceType == rtype && g.ResourceID == rid {
			delete(m.Grants, k)
		}
	}
	return nil
}

// ---------------------------------------------------------------- shares

func (m *Store) InsertShare(_ context.Context, s store.Share) error {
	if err := m.fail("InsertShare"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.Shares {
		if o.TokenHash == s.TokenHash {
			return store.ErrConflict
		}
	}
	s.Opens, s.State, s.CreatedAt = 0, "active", m.Now()
	m.Shares[s.ID] = s
	return nil
}

func (m *Store) ShareByTokenHash(_ context.Context, hash string) (store.Share, error) {
	if err := m.fail("ShareByTokenHash"); err != nil {
		return store.Share{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.Shares {
		if s.TokenHash == hash {
			return s, nil
		}
	}
	return store.Share{}, store.ErrNotFound
}

func (m *Store) GetShare(_ context.Context, tid, id string) (store.Share, error) {
	if err := m.fail("GetShare"); err != nil {
		return store.Share{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.Shares[id]
	if !ok || s.TenantID != tid {
		return store.Share{}, store.ErrNotFound
	}
	return s, nil
}

func (m *Store) SharesOfSecret(_ context.Context, tid, sid, by string) ([]store.Share, error) {
	if err := m.fail("SharesOfSecret"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Share
	for _, s := range m.Shares {
		if s.TenantID == tid && s.SecretID == sid && s.CreatedBy == by {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

func (m *Store) ConsumeShareOpen(_ context.Context, id string) (store.Share, error) {
	if err := m.fail("ConsumeShareOpen"); err != nil {
		return store.Share{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.Shares[id]
	if !ok || s.State != "active" || s.Opens >= s.MaxOpens || !s.ExpiresAt.After(m.Now()) {
		return store.Share{}, store.ErrNotFound
	}
	s.Opens++
	if s.Opens >= s.MaxOpens {
		s.State = "consumed"
	}
	m.Shares[id] = s
	return s, nil
}

func (m *Store) SetShareState(_ context.Context, tid, id, state string) error {
	if err := m.fail("SetShareState"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.Shares[id]
	if !ok || s.TenantID != tid || s.State != "active" {
		return store.ErrNotFound
	}
	s.State = state
	m.Shares[id] = s
	return nil
}

func (m *Store) ExpireShares(_ context.Context, now time.Time) (int64, error) {
	if err := m.fail("ExpireShares"); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for k, s := range m.Shares {
		if s.State == "active" && !s.ExpiresAt.After(now) {
			s.State = "expired"
			m.Shares[k] = s
			n++
		}
	}
	return n, nil
}

// ---------------------------------------------------------------- audit & stats

func (m *Store) InsertAuditRows(_ context.Context, rows []store.AuditRow) error {
	if err := m.fail("InsertAuditRows"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Audit = append(m.Audit, rows...)
	return nil
}

func (m *Store) QueryAudit(_ context.Context, tid, et, actor string, from, to, cursor time.Time, limit int) ([]store.AuditRow, error) {
	if err := m.fail("QueryAudit"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.AuditRow
	for _, r := range m.Audit {
		if r.TenantID != tid || (et != "" && r.EventType != et) || (actor != "" && r.ActorID != actor) || r.TS.Before(from) || r.TS.After(to) || (!cursor.IsZero() && !r.TS.Before(cursor)) {
			continue
		}
		// Same resolution as store.QueryAudit: existing secrets and folders by name,
		// shares by the shared secret's name.
		switch r.SubjectKind {
		case "secret":
			if s, ok := m.Secrets[r.SubjectID]; ok && s.TenantID == tid {
				r.SubjectName = s.Name
			}
		case "folder":
			if f, ok := m.Folders[r.SubjectID]; ok && f.TenantID == tid {
				r.SubjectName = f.Path
			}
		case "share":
			var d struct {
				SecretID string `json:"secret_id"`
			}
			if json.Unmarshal(r.Details, &d) == nil {
				if s, ok := m.Secrets[d.SecretID]; ok && s.TenantID == tid {
					r.SubjectName = s.Name
				}
			}
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS.After(out[j].TS) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// AuditEvents returns the events of a type (test helper).
func (m *Store) AuditEvents(tid, et string) []store.AuditRow {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.AuditRow
	for _, r := range m.Audit {
		if r.TenantID == tid && (et == "" || r.EventType == et) {
			out = append(out, r)
		}
	}
	return out
}

func (m *Store) TenantStats(_ context.Context, tid string, now time.Time) (store.Stats, error) {
	if err := m.fail("TenantStats"); err != nil {
		return store.Stats{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st := store.Stats{Grants: map[string]int64{}, Shares: map[string]int64{}}
	for _, s := range m.Secrets {
		if s.TenantID == tid && s.DeletedAt == nil {
			st.Secrets++
			if s.HasTOTP {
				st.SecretsWithTOTP++
			}
		}
	}
	for _, f := range m.Folders {
		if f.TenantID == tid {
			st.Folders++
		}
	}
	for _, vs := range m.Versions {
		for _, v := range vs {
			if v.TenantID == tid {
				st.Versions++
			}
		}
	}
	for _, g := range m.Grants {
		if g.TenantID == tid {
			st.Grants[g.Relation]++
		}
	}
	for _, s := range m.Shares {
		if s.TenantID == tid {
			st.Shares[s.State]++
		}
	}
	for _, r := range m.Audit {
		if r.TenantID == tid && !r.TS.Before(now.Add(-24*time.Hour)) {
			st.Operations24h++
		}
	}
	return st, nil
}

var _ repo.Store = (*Store)(nil)
