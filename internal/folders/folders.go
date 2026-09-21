// Package folders manages the folder tree: creation under a writable parent,
// rename, move (no cycles), delete (recursive on request) and readable tree
// views. Permissions come from authz; every change is audited.
package folders

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/go-freya/freya/services/warden/internal/audit"
	"github.com/go-freya/freya/services/warden/internal/authz"
	"github.com/go-freya/freya/services/warden/internal/repo"
	"github.com/go-freya/freya/services/warden/internal/store"
)

// Limits.
const (
	NameMax = 100
	TreeMax = 10000
)

// Errors.
var (
	ErrInvalidName = errors.New("folders: invalid name")
	ErrConflict    = errors.New("folders: conflict")
	ErrNotEmpty    = errors.New("folders: not empty")
	ErrCycle       = errors.New("folders: move would create a cycle")
	ErrNotFound    = authz.ErrNotFound
	ErrForbidden   = authz.ErrForbidden
)

// SecretDeleter removes the secrets of a deleted subtree (the secrets
// service destroys their material).
type SecretDeleter interface {
	DeleteMany(ctx context.Context, s authz.Subjects, ids []string) error
}

// Service is the folder service.
type Service struct {
	st      repo.Store
	az      *authz.Authz
	audit   *audit.Writer
	secrets SecretDeleter
	now     func() time.Time
}

// New wires the service.
func New(st repo.Store, az *authz.Authz, aw *audit.Writer, secrets SecretDeleter) *Service {
	return &Service{st: st, az: az, audit: aw, secrets: secrets, now: time.Now}
}

// View is a folder as returned to clients.
type View struct {
	ID          string            `json:"id"`
	ParentID    *string           `json:"parent_id"`
	Name        string            `json:"name"`
	Path        string            `json:"path"`
	SecretCount int               `json:"secret_count"`
	CreatedBy   string            `json:"created_by,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Permissions authz.Permissions `json:"permissions"`
}

// Node is a tree node.
type Node struct {
	Folder   View    `json:"folder"`
	Children []*Node `json:"children"`
}

func view(f store.Folder, p authz.Permissions, secrets int) View {
	v := View{ID: f.ID, ParentID: f.ParentID, Name: f.Name, Path: f.Path, SecretCount: secrets, CreatedAt: f.CreatedAt, UpdatedAt: f.UpdatedAt, Permissions: p}
	if f.CreatedBy != nil {
		v.CreatedBy = *f.CreatedBy
	}
	return v
}

// ValidName checks the name rules: 1..100 characters, no control characters,
// no slash, not blank.
func ValidName(name string) bool {
	if name == "" || len(name) > NameMax || strings.TrimSpace(name) == "" {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == '/' {
			return false
		}
	}
	return true
}

func mapErr(err error) error {
	switch {
	case errors.Is(err, store.ErrConflict):
		return ErrConflict
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	}
	return err
}

// Create makes a folder; write on the parent is required (root folders need
// only the API permission). The creator becomes owner.
func (s *Service) Create(ctx context.Context, subj authz.Subjects, parentID *string, name string) (View, error) {
	if !ValidName(name) {
		return View{}, ErrInvalidName
	}
	var ancestors []string
	path := "/" + name
	if parentID != nil {
		if _, err := s.az.Require(ctx, subj, authz.Folder, *parentID, authz.Write); err != nil {
			return View{}, err
		}
		parent, err := s.st.GetFolder(ctx, subj.TenantID, *parentID)
		if err != nil {
			return View{}, mapErr(err)
		}
		ancestors = append(append([]string{}, parent.Ancestors...), parent.ID)
		path = parent.Path + "/" + name
	}
	by := subj.UserID
	f := store.Folder{ID: store.NewID(), TenantID: subj.TenantID, ParentID: parentID, Name: name, Path: path, Ancestors: ancestors, CreatedBy: &by, UpdatedBy: &by}
	err := s.st.Atomic(ctx, subj.TenantID, func(tx repo.Store) error {
		if err := tx.InsertFolder(ctx, f); err != nil {
			return err
		}
		return authz.New(tx, nil).GrantOwner(ctx, subj.TenantID, authz.Folder, f.ID, subj.UserID)
	})
	if err != nil {
		return View{}, mapErr(err)
	}
	s.emit(audit.Event{Type: audit.FolderCreated, TenantID: subj.TenantID, ActorKind: "user", ActorID: subj.UserID, SubjectKind: "folder", SubjectID: f.ID, Outcome: "ok",
		Details: map[string]any{"parent_id": strp(parentID)}})
	stored, err := s.st.GetFolder(ctx, subj.TenantID, f.ID)
	if err != nil {
		return View{}, mapErr(err)
	}
	return view(stored, authz.Of(authz.Owner), 0), nil
}

// Get returns a folder the caller may read.
func (s *Service) Get(ctx context.Context, subj authz.Subjects, id string) (View, error) {
	d, err := s.az.Require(ctx, subj, authz.Folder, id, authz.Read)
	if err != nil {
		return View{}, err
	}
	f, err := s.st.GetFolder(ctx, subj.TenantID, id)
	if err != nil {
		return View{}, mapErr(err)
	}
	_, n, err := s.st.CountFolderContents(ctx, subj.TenantID, id)
	if err != nil {
		return View{}, err
	}
	return view(f, d.Permissions, n), nil
}

// Children lists the readable children of a folder (root when nil). Under a
// readable parent every child is readable (inheritance); at the root each
// folder is checked on its own.
func (s *Service) Children(ctx context.Context, subj authz.Subjects, parentID *string) ([]View, error) {
	var inherited *authz.Permissions
	if parentID != nil {
		d, err := s.az.Require(ctx, subj, authz.Folder, *parentID, authz.Read)
		if err != nil {
			return nil, err
		}
		inherited = &d.Permissions
	}
	kids, err := s.st.FolderChildren(ctx, subj.TenantID, parentID)
	if err != nil {
		return nil, err
	}
	out := []View{}
	for _, f := range kids {
		p, err := s.az.PermissionsOn(ctx, subj, authz.Folder, f.ID)
		if err != nil {
			return nil, err
		}
		if inherited != nil {
			p = unionP(p, *inherited)
		}
		if !p.Read {
			continue
		}
		_, n, err := s.st.CountFolderContents(ctx, subj.TenantID, f.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, view(f, p, n))
	}
	return out, nil
}

func unionP(a, b authz.Permissions) authz.Permissions {
	return authz.Permissions{Read: a.Read || b.Read, Write: a.Write || b.Write, Delete: a.Delete || b.Delete, Share: a.Share || b.Share}
}

// Tree returns the readable forest: a folder appears when the caller holds
// read on it or on an ancestor; subtrees under a readable folder are
// complete. Bounded to TreeMax folders.
func (s *Service) Tree(ctx context.Context, subj authz.Subjects) ([]*Node, error) {
	all, err := s.st.AllFolders(ctx, subj.TenantID, TreeMax)
	if err != nil {
		return nil, err
	}
	grants, err := s.st.GrantsForSubjects(ctx, subj.TenantID, subj.UserID, subj.Roles, s.now())
	if err != nil {
		return nil, err
	}
	direct := map[string]authz.Permissions{}
	for _, g := range grants {
		if g.ResourceType == authz.Folder {
			direct[g.ResourceID] = unionP(direct[g.ResourceID], authz.Of(g.Relation))
		}
	}
	// AllFolders is ordered by path, so parents precede children.
	nodes := map[string]*Node{}
	perms := map[string]authz.Permissions{}
	var roots []*Node
	for _, f := range all {
		p := direct[f.ID]
		if f.ParentID != nil {
			p = unionP(p, perms[*f.ParentID])
		}
		perms[f.ID] = p
		if !p.Read {
			continue
		}
		n := &Node{Folder: view(f, p, 0), Children: []*Node{}}
		nodes[f.ID] = n
		if f.ParentID != nil {
			if parent, ok := nodes[*f.ParentID]; ok {
				parent.Children = append(parent.Children, n)
				continue
			}
		}
		roots = append(roots, n)
	}
	if roots == nil {
		roots = []*Node{}
	}
	return roots, nil
}

// Rename changes the name; write on the folder is required.
func (s *Service) Rename(ctx context.Context, subj authz.Subjects, id, name string) (View, error) {
	if !ValidName(name) {
		return View{}, ErrInvalidName
	}
	if _, err := s.az.Require(ctx, subj, authz.Folder, id, authz.Write); err != nil {
		return View{}, err
	}
	if err := s.st.RenameFolder(ctx, subj.TenantID, id, name, subj.UserID); err != nil {
		return View{}, mapErr(err)
	}
	s.emit(audit.Event{Type: audit.FolderUpdated, TenantID: subj.TenantID, ActorKind: "user", ActorID: subj.UserID, SubjectKind: "folder", SubjectID: id, Outcome: "ok", Details: map[string]any{"fields": []string{"name"}}})
	return s.Get(ctx, subj, id)
}

// Move re-parents a folder (nil = root); write on the folder and on the new
// parent are required; cycles are refused.
func (s *Service) Move(ctx context.Context, subj authz.Subjects, id string, newParent *string) (View, error) {
	if _, err := s.az.Require(ctx, subj, authz.Folder, id, authz.Write); err != nil {
		return View{}, err
	}
	f, err := s.st.GetFolder(ctx, subj.TenantID, id)
	if err != nil {
		return View{}, mapErr(err)
	}
	var ancestors []string
	path := "/" + f.Name
	if newParent != nil {
		if *newParent == id {
			return View{}, ErrCycle
		}
		if _, err := s.az.Require(ctx, subj, authz.Folder, *newParent, authz.Write); err != nil {
			return View{}, err
		}
		parent, err := s.st.GetFolder(ctx, subj.TenantID, *newParent)
		if err != nil {
			return View{}, mapErr(err)
		}
		for _, anc := range parent.Ancestors {
			if anc == id {
				return View{}, ErrCycle
			}
		}
		ancestors = append(append([]string{}, parent.Ancestors...), parent.ID)
		path = parent.Path + "/" + f.Name
	}
	if err := s.st.MoveFolder(ctx, subj.TenantID, id, newParent, ancestors, path, subj.UserID); err != nil {
		return View{}, mapErr(err)
	}
	s.emit(audit.Event{Type: audit.FolderMoved, TenantID: subj.TenantID, ActorKind: "user", ActorID: subj.UserID, SubjectKind: "folder", SubjectID: id, Outcome: "ok",
		Details: map[string]any{"from": strp(f.ParentID), "to": strp(newParent)}})
	return s.Get(ctx, subj, id)
}

// Delete removes a folder; delete on the folder is required. A non-empty
// folder needs recursive, which removes every subfolder and secret below.
func (s *Service) Delete(ctx context.Context, subj authz.Subjects, id string, recursive bool) error {
	if _, err := s.az.Require(ctx, subj, authz.Folder, id, authz.Delete); err != nil {
		return err
	}
	sub, err := s.st.FolderSubtree(ctx, subj.TenantID, id)
	if err != nil {
		return err
	}
	if len(sub) == 0 {
		return ErrNotFound
	}
	ids := make([]string, 0, len(sub))
	for _, f := range sub {
		ids = append(ids, f.ID)
	}
	secrets, err := s.st.SecretsInFolders(ctx, subj.TenantID, ids)
	if err != nil {
		return err
	}
	if !recursive && (len(sub) > 1 || len(secrets) > 0) {
		return ErrNotEmpty
	}
	if len(secrets) > 0 {
		sids := make([]string, 0, len(secrets))
		for _, sec := range secrets {
			sids = append(sids, sec.ID)
		}
		if err := s.secrets.DeleteMany(ctx, subj, sids); err != nil {
			return err
		}
	}
	err = s.st.Atomic(ctx, subj.TenantID, func(tx repo.Store) error {
		for _, fid := range ids {
			if err := tx.DeleteGrantsOfResource(ctx, subj.TenantID, authz.Folder, fid); err != nil {
				return err
			}
		}
		return tx.DeleteFolder(ctx, subj.TenantID, id)
	})
	if err != nil {
		return mapErr(err)
	}
	s.emit(audit.Event{Type: audit.FolderDeleted, TenantID: subj.TenantID, ActorKind: "user", ActorID: subj.UserID, SubjectKind: "folder", SubjectID: id, Outcome: "ok",
		Details: map[string]any{"folders": len(sub), "secrets": len(secrets), "recursive": recursive}})
	return nil
}

func strp(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (s *Service) emit(e audit.Event) {
	if s.audit != nil {
		_ = s.audit.Emit(e)
	}
}
