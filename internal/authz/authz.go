// Package authz decides access to folders and secrets with Zanzibar-style
// relation tuples: grants of owner/editor/viewer/sharer on a folder or secret
// to a user, a role or the whole tenant, optionally expiring, inherited down
// the folder tree. Every decision is computed from the caller's verified
// subjects (user id, effective roles, tenant) and the grants on the resource
// and its ancestors.
package authz

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra-warden/v4/internal/audit"
	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
)

// Relations (data-model.md) and permissions.
const (
	Owner  = "owner"
	Editor = "editor"
	Viewer = "viewer"
	Sharer = "sharer"

	Read   = "read"
	Write  = "write"
	Delete = "delete"
	Share  = "share"
)

// Resource and subject types.
const (
	Folder = "folder"
	Secret = "secret"

	SubjectUser   = "user"
	SubjectRole   = "role"
	SubjectTenant = "tenant"
)

// Errors.
var (
	ErrForbidden = errors.New("authz: forbidden")
	ErrNotFound  = errors.New("authz: resource not found")
	ErrInput     = errors.New("authz: invalid input")
)

// Store is the persistence authz reads and writes (repo.Store satisfies it).
type Store interface {
	GetFolder(ctx context.Context, tenantID, id string) (store.Folder, error)
	GetSecret(ctx context.Context, tenantID, id string) (store.Secret, error)
	FolderSubtree(ctx context.Context, tenantID, id string) ([]store.Folder, error)
	SecretsInFolders(ctx context.Context, tenantID string, folderIDs []string) ([]store.Secret, error)
	SecretsByIDs(ctx context.Context, tenantID string, ids []string) ([]store.Secret, error)
	UpsertGrant(ctx context.Context, g store.Grant) (store.Grant, error)
	GetGrant(ctx context.Context, tenantID, id string) (store.Grant, error)
	DeleteGrant(ctx context.Context, tenantID, id string) error
	GrantsOnResources(ctx context.Context, tenantID string, resourceIDs []string) ([]store.Grant, error)
	GrantsForSubjects(ctx context.Context, tenantID, userID string, roles []string, now time.Time) ([]store.Grant, error)
}

// Subjects is the caller as seen by the grant tables.
type Subjects struct {
	TenantID string
	UserID   string
	Roles    []string
}

// SubjectsOf derives the subjects from a verified platform identity (the
// roles are effective: direct and through groups, feature 004).
func SubjectsOf(id authclient.Identity) Subjects {
	return Subjects{TenantID: id.TenantID, UserID: id.UserID, Roles: append([]string(nil), id.Roles...)}
}

// Permissions are the derived booleans of a relation set.
type Permissions struct {
	Read   bool `json:"read"`
	Write  bool `json:"write"`
	Delete bool `json:"delete"`
	Share  bool `json:"share"`
}

// Has reports one permission.
func (p Permissions) Has(perm string) bool {
	switch perm {
	case Read:
		return p.Read
	case Write:
		return p.Write
	case Delete:
		return p.Delete
	case Share:
		return p.Share
	}
	return false
}

// Of returns the permissions a relation carries.
func Of(relation string) Permissions {
	switch relation {
	case Owner:
		return Permissions{Read: true, Write: true, Delete: true, Share: true}
	case Editor:
		return Permissions{Read: true, Write: true}
	case Viewer:
		return Permissions{Read: true}
	case Sharer:
		return Permissions{Read: true, Share: true}
	}
	return Permissions{}
}

// rank orders relations for "strongest" reporting and granter bounds.
func rank(relation string) int {
	switch relation {
	case Owner:
		return 4
	case Editor:
		return 3
	case Sharer:
		return 2
	case Viewer:
		return 1
	}
	return 0
}

// ValidRelation / ValidPermission / ValidResourceType / ValidSubjectType.
func ValidRelation(r string) bool     { return rank(r) > 0 }
func ValidPermission(p string) bool   { return p == Read || p == Write || p == Delete || p == Share }
func ValidResourceType(t string) bool { return t == Folder || t == Secret }
func ValidSubjectType(t string) bool {
	return t == SubjectUser || t == SubjectRole || t == SubjectTenant
}

// Source explains where a permission comes from.
type Source struct {
	GrantID      string     `json:"grant_id"`
	ResourceType string     `json:"resource_type"`
	ResourceID   string     `json:"resource_id"`
	SubjectType  string     `json:"subject_type"`
	SubjectID    string     `json:"subject_id,omitempty"`
	Relation     string     `json:"relation"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Inherited    bool       `json:"inherited"`
}

// Decision is the outcome of a check.
type Decision struct {
	Allowed     bool        `json:"allowed"`
	Relation    string      `json:"relation,omitempty"` // strongest relation held
	Permissions Permissions `json:"permissions"`
	Sources     []Source    `json:"sources,omitempty"`
}

// Authz evaluates and manages grants.
type Authz struct {
	st    Store
	audit *audit.Writer
	now   func() time.Time
}

// New wires the evaluator.
func New(st Store, aw *audit.Writer) *Authz {
	return &Authz{st: st, audit: aw, now: time.Now}
}

// SetClock injects the clock (tests).
func (a *Authz) SetClock(now func() time.Time) { a.now = now }

// resource is a located resource with its ancestor chain (root-first) and,
// for secrets, the folder it lives in.
type resource struct {
	Type      string
	ID        string
	Name      string
	Path      string
	Ancestors []string // folder ids, root first; for a secret its folder is last
}

// locate loads the resource in the caller's tenant; anything outside is not found.
func (a *Authz) locate(ctx context.Context, tenantID, resourceType, resourceID string) (resource, error) {
	switch resourceType {
	case Folder:
		f, err := a.st.GetFolder(ctx, tenantID, resourceID)
		if err != nil {
			return resource{}, notFound(err)
		}
		return resource{Type: Folder, ID: f.ID, Name: f.Name, Path: f.Path, Ancestors: append([]string(nil), f.Ancestors...)}, nil
	case Secret:
		s, err := a.st.GetSecret(ctx, tenantID, resourceID)
		if err != nil {
			return resource{}, notFound(err)
		}
		r := resource{Type: Secret, ID: s.ID, Name: s.Name, Path: s.FolderPath}
		if s.FolderID != nil {
			f, err := a.st.GetFolder(ctx, tenantID, *s.FolderID)
			if err != nil {
				return resource{}, notFound(err)
			}
			r.Ancestors = append(append([]string(nil), f.Ancestors...), f.ID)
		}
		return r, nil
	}
	return resource{}, ErrInput
}

func notFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// matches reports whether a grant applies to the subjects at now.
func matches(g store.Grant, s Subjects, now time.Time) bool {
	if g.ExpiresAt != nil && !g.ExpiresAt.After(now) {
		return false
	}
	switch g.SubjectType {
	case SubjectUser:
		return g.SubjectID == s.UserID
	case SubjectRole:
		for _, r := range s.Roles {
			if r == g.SubjectID {
				return true
			}
		}
		return false
	case SubjectTenant:
		return true
	}
	return false
}

// evaluate computes the decision for subjects on a located resource.
func (a *Authz) evaluate(ctx context.Context, s Subjects, r resource) (Decision, error) {
	ids := append(append([]string(nil), r.Ancestors...), r.ID)
	grants, err := a.st.GrantsOnResources(ctx, s.TenantID, ids)
	if err != nil {
		return Decision{}, err
	}
	now := a.now()
	d := Decision{}
	for _, g := range grants {
		if !matches(g, s, now) {
			continue
		}
		p := Of(g.Relation)
		d.Permissions = union(d.Permissions, p)
		if rank(g.Relation) > rank(d.Relation) {
			d.Relation = g.Relation
		}
		d.Sources = append(d.Sources, Source{GrantID: g.ID, ResourceType: g.ResourceType, ResourceID: g.ResourceID, SubjectType: g.SubjectType, SubjectID: g.SubjectID,
			Relation: g.Relation, ExpiresAt: g.ExpiresAt, Inherited: g.ResourceID != r.ID})
	}
	sort.Slice(d.Sources, func(i, j int) bool { return rank(d.Sources[i].Relation) > rank(d.Sources[j].Relation) })
	return d, nil
}

func union(a, b Permissions) Permissions {
	return Permissions{Read: a.Read || b.Read, Write: a.Write || b.Write, Delete: a.Delete || b.Delete, Share: a.Share || b.Share}
}

// Check answers whether the subjects hold permission on the resource. A
// resource outside the tenant is ErrNotFound; a refusal is audited.
func (a *Authz) Check(ctx context.Context, s Subjects, resourceType, resourceID, permission string) (Decision, error) {
	if !ValidPermission(permission) || !ValidResourceType(resourceType) {
		return Decision{}, ErrInput
	}
	r, err := a.locate(ctx, s.TenantID, resourceType, resourceID)
	if err != nil {
		return Decision{}, err
	}
	d, err := a.evaluate(ctx, s, r)
	if err != nil {
		return Decision{}, err
	}
	d.Allowed = d.Permissions.Has(permission)
	if !d.Allowed {
		a.emit(audit.Event{Type: audit.AccessRefused, TenantID: s.TenantID, ActorKind: "user", ActorID: s.UserID, SubjectKind: resourceType, SubjectID: resourceID,
			Outcome: "refused", Reason: "no_" + permission, Details: map[string]any{"permission": permission}})
	}
	return d, nil
}

// Require is Check that returns ErrForbidden when not allowed.
func (a *Authz) Require(ctx context.Context, s Subjects, resourceType, resourceID, permission string) (Decision, error) {
	d, err := a.Check(ctx, s, resourceType, resourceID, permission)
	if err != nil {
		return d, err
	}
	if !d.Allowed {
		return d, ErrForbidden
	}
	return d, nil
}

// PermissionsOn returns the permissions the subjects hold on a resource
// without auditing (listing decoration).
func (a *Authz) PermissionsOn(ctx context.Context, s Subjects, resourceType, resourceID string) (Permissions, error) {
	r, err := a.locate(ctx, s.TenantID, resourceType, resourceID)
	if err != nil {
		return Permissions{}, err
	}
	d, err := a.evaluate(ctx, s, r)
	return d.Permissions, err
}

// GrantOwner records the creator-owner grant of a new resource.
func (a *Authz) GrantOwner(ctx context.Context, tenantID, resourceType, resourceID, userID string) error {
	by := userID
	_, err := a.st.UpsertGrant(ctx, store.Grant{ID: store.NewID(), TenantID: tenantID, ResourceType: resourceType, ResourceID: resourceID,
		SubjectType: SubjectUser, SubjectID: userID, Relation: Owner, GrantedBy: &by})
	return err
}

func (a *Authz) emit(e audit.Event) {
	if a.audit != nil {
		_ = a.audit.Emit(e)
	}
}
