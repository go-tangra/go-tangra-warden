package authz

import (
	"context"
	"sort"
	"time"

	"github.com/go-freya/freya/services/warden/internal/audit"
	"github.com/go-freya/freya/services/warden/internal/store"
)

// GrantInput is a grant request.
type GrantInput struct {
	ResourceType string
	ResourceID   string
	SubjectType  string
	SubjectID    string
	Relation     string
	ExpiresAt    *time.Time
}

// GrantView is a grant as returned to clients.
type GrantView struct {
	ID           string     `json:"id"`
	ResourceType string     `json:"resource_type"`
	ResourceID   string     `json:"resource_id"`
	SubjectType  string     `json:"subject_type"`
	SubjectID    string     `json:"subject_id,omitempty"`
	Relation     string     `json:"relation"`
	GrantedBy    string     `json:"granted_by,omitempty"`
	GrantedAt    time.Time  `json:"granted_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Inherited    bool       `json:"inherited"`
	Expired      bool       `json:"expired"`
}

func (a *Authz) view(g store.Grant, onID string) GrantView {
	v := GrantView{ID: g.ID, ResourceType: g.ResourceType, ResourceID: g.ResourceID, SubjectType: g.SubjectType, SubjectID: g.SubjectID, Relation: g.Relation,
		GrantedAt: g.GrantedAt, ExpiresAt: g.ExpiresAt, Inherited: g.ResourceID != onID}
	if g.GrantedBy != nil {
		v.GrantedBy = *g.GrantedBy
	}
	if g.ExpiresAt != nil && !g.ExpiresAt.After(a.now()) {
		v.Expired = true
	}
	return v
}

// validate checks the shape of a grant request.
func (in GrantInput) validate(now time.Time) error {
	if !ValidResourceType(in.ResourceType) || !ValidSubjectType(in.SubjectType) || !ValidRelation(in.Relation) || in.ResourceID == "" {
		return ErrInput
	}
	switch in.SubjectType {
	case SubjectTenant:
		if in.SubjectID != "" {
			return ErrInput
		}
	default:
		if in.SubjectID == "" || len(in.SubjectID) > 128 {
			return ErrInput
		}
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(now) {
		return ErrInput
	}
	return nil
}

// Grant creates or replaces a grant. The granter needs share on the resource
// and may not hand out a relation above the strongest one they hold there.
func (a *Authz) Grant(ctx context.Context, s Subjects, in GrantInput) (GrantView, error) {
	if err := in.validate(a.now()); err != nil {
		return GrantView{}, err
	}
	d, err := a.Check(ctx, s, in.ResourceType, in.ResourceID, Share)
	if err != nil {
		return GrantView{}, err
	}
	if !d.Allowed {
		return GrantView{}, ErrForbidden
	}
	if rank(in.Relation) > rank(d.Relation) {
		a.emit(audit.Event{Type: audit.AccessRefused, TenantID: s.TenantID, ActorKind: "user", ActorID: s.UserID, SubjectKind: in.ResourceType, SubjectID: in.ResourceID,
			Outcome: "refused", Reason: "relation_above_granter", Details: map[string]any{"relation": in.Relation, "held": d.Relation}})
		return GrantView{}, ErrForbidden
	}
	by := s.UserID
	g, err := a.st.UpsertGrant(ctx, store.Grant{ID: store.NewID(), TenantID: s.TenantID, ResourceType: in.ResourceType, ResourceID: in.ResourceID,
		SubjectType: in.SubjectType, SubjectID: in.SubjectID, Relation: in.Relation, GrantedBy: &by, ExpiresAt: in.ExpiresAt})
	if err != nil {
		return GrantView{}, err
	}
	a.emit(audit.Event{Type: audit.GrantCreated, TenantID: s.TenantID, ActorKind: "user", ActorID: s.UserID, SubjectKind: "grant", SubjectID: g.ID, Outcome: "ok",
		Details: map[string]any{"resource_type": g.ResourceType, "resource_id": g.ResourceID, "subject_type": g.SubjectType, "subject_id": g.SubjectID, "relation": g.Relation, "expires": g.ExpiresAt != nil}})
	return a.view(g, in.ResourceID), nil
}

// Revoke deletes a grant; the caller needs share on its resource.
func (a *Authz) Revoke(ctx context.Context, s Subjects, grantID string) error {
	g, err := a.st.GetGrant(ctx, s.TenantID, grantID)
	if err != nil {
		return notFound(err)
	}
	d, err := a.Check(ctx, s, g.ResourceType, g.ResourceID, Share)
	if err != nil {
		return err
	}
	if !d.Allowed {
		return ErrForbidden
	}
	if err := a.st.DeleteGrant(ctx, s.TenantID, grantID); err != nil {
		return notFound(err)
	}
	a.emit(audit.Event{Type: audit.GrantRevoked, TenantID: s.TenantID, ActorKind: "user", ActorID: s.UserID, SubjectKind: "grant", SubjectID: g.ID, Outcome: "ok",
		Details: map[string]any{"resource_type": g.ResourceType, "resource_id": g.ResourceID, "subject_type": g.SubjectType, "subject_id": g.SubjectID, "relation": g.Relation}})
	return nil
}

// ListGrants returns the grants on a resource and its ancestors (inherited
// flagged); the caller needs share on the resource.
func (a *Authz) ListGrants(ctx context.Context, s Subjects, resourceType, resourceID string) ([]GrantView, error) {
	if !ValidResourceType(resourceType) {
		return nil, ErrInput
	}
	r, err := a.locate(ctx, s.TenantID, resourceType, resourceID)
	if err != nil {
		return nil, err
	}
	d, err := a.evaluate(ctx, s, r)
	if err != nil {
		return nil, err
	}
	if !d.Permissions.Share {
		a.emit(audit.Event{Type: audit.AccessRefused, TenantID: s.TenantID, ActorKind: "user", ActorID: s.UserID, SubjectKind: resourceType, SubjectID: resourceID, Outcome: "refused", Reason: "no_share"})
		return nil, ErrForbidden
	}
	grants, err := a.st.GrantsOnResources(ctx, s.TenantID, append(append([]string(nil), r.Ancestors...), r.ID))
	if err != nil {
		return nil, err
	}
	out := make([]GrantView, 0, len(grants))
	for _, g := range grants {
		out = append(out, a.view(g, resourceID))
	}
	return out, nil
}

// Effective explains the caller's own permissions on a resource with every
// contributing grant; readable by anyone (the answer is about themselves).
func (a *Authz) Effective(ctx context.Context, s Subjects, resourceType, resourceID string) (Decision, error) {
	if !ValidResourceType(resourceType) {
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
	d.Allowed = d.Permissions.Read
	if d.Sources == nil {
		d.Sources = []Source{}
	}
	return d, nil
}

// Accessible is one resource the caller can use.
type Accessible struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Name         string `json:"name"`
	Path         string `json:"path"`
	Relation     string `json:"relation"`
	Source       Source `json:"source"`
}

// AccessibleResources lists every folder and secret on which the subjects
// hold permission, expanded down the tree, strongest relation first source,
// sorted by path then name, paged by an opaque cursor "<type>:<id>".
func (a *Authz) AccessibleResources(ctx context.Context, s Subjects, permission, cursor string, limit int) ([]Accessible, string, error) {
	if !ValidPermission(permission) {
		return nil, "", ErrInput
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	grants, err := a.st.GrantsForSubjects(ctx, s.TenantID, s.UserID, s.Roles, a.now())
	if err != nil {
		return nil, "", err
	}
	// Direct relation per resource (strongest), then inherit into subtrees.
	type key struct{ rtype, id string }
	type held struct {
		relation string
		src      Source
	}
	direct := map[key]held{}
	for _, g := range grants {
		if !Of(g.Relation).Has(permission) {
			continue
		}
		k := key{g.ResourceType, g.ResourceID}
		if h, ok := direct[k]; !ok || rank(g.Relation) > rank(h.relation) {
			direct[k] = held{g.Relation, Source{GrantID: g.ID, ResourceType: g.ResourceType, ResourceID: g.ResourceID, SubjectType: g.SubjectType, SubjectID: g.SubjectID, Relation: g.Relation, ExpiresAt: g.ExpiresAt}}
		}
	}
	best := map[key]Accessible{}
	consider := func(rtype, id, name, path string, h held, inherited bool) {
		k := key{rtype, id}
		src := h.src
		src.Inherited = inherited
		if cur, ok := best[k]; !ok || rank(h.relation) > rank(cur.Relation) {
			best[k] = Accessible{ResourceType: rtype, ResourceID: id, Name: name, Path: path, Relation: h.relation, Source: src}
		}
	}
	var secretIDs []string
	for k, h := range direct {
		if k.rtype == Secret {
			secretIDs = append(secretIDs, k.id)
			continue
		}
		sub, err := a.st.FolderSubtree(ctx, s.TenantID, k.id)
		if err != nil {
			return nil, "", err
		}
		for _, f := range sub {
			consider(Folder, f.ID, f.Name, f.Path, h, f.ID != k.id)
		}
		secrets, err := a.st.SecretsInFolders(ctx, s.TenantID, subtreeIDs(sub))
		if err != nil {
			return nil, "", err
		}
		for _, sec := range secrets {
			consider(Secret, sec.ID, sec.Name, sec.FolderPath, h, true)
		}
	}
	if len(secretIDs) > 0 {
		secrets, err := a.st.SecretsByIDs(ctx, s.TenantID, secretIDs)
		if err != nil {
			return nil, "", err
		}
		for _, sec := range secrets {
			consider(Secret, sec.ID, sec.Name, sec.FolderPath, direct[key{Secret, sec.ID}], false)
		}
	}
	all := make([]Accessible, 0, len(best))
	for _, v := range best {
		all = append(all, v)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Path != all[j].Path {
			return all[i].Path < all[j].Path
		}
		if all[i].ResourceType != all[j].ResourceType {
			return all[i].ResourceType < all[j].ResourceType // folder before secret
		}
		if all[i].Name != all[j].Name {
			return all[i].Name < all[j].Name
		}
		return all[i].ResourceID < all[j].ResourceID
	})
	start := 0
	if cursor != "" {
		for i, v := range all {
			if v.ResourceType+":"+v.ResourceID == cursor {
				start = i + 1
				break
			}
		}
	}
	end := start + limit
	next := ""
	if end < len(all) {
		next = all[end-1].ResourceType + ":" + all[end-1].ResourceID
	} else {
		end = len(all)
	}
	return all[start:end], next, nil
}

func subtreeIDs(fs []store.Folder) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}
