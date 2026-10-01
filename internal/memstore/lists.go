package memstore

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/go-tangra/go-tangra/v4/listquery"

	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
)

// List-contract pages (go-tangra specs/032-server-side-tables): the same
// filters and visibility as the SQL pages, sorted by the store.*List fields
// with the same semantics (listquery.SortSlice) and windowed with the total.

// visible mirrors the SQL scope predicate: a direct grant on the secret, or a
// grant on its folder or any ancestor of it. Callers hold m.mu.
func (m *Store) visible(s store.Secret, scope store.SecretScope) bool {
	if contains(scope.SecretIDs, s.ID) {
		return true
	}
	if s.FolderID == nil {
		return false
	}
	f, ok := m.Folders[*s.FolderID]
	if !ok || f.TenantID != s.TenantID {
		return false
	}
	if contains(scope.FolderIDs, f.ID) {
		return true
	}
	for _, a := range f.Ancestors {
		if contains(scope.FolderIDs, a) {
			return true
		}
	}
	return false
}

func secretKey(s store.Secret, field string) any {
	switch field {
	case "updated_at":
		return s.UpdatedAt
	case "created_at":
		return s.CreatedAt
	default:
		return s.Name
	}
}

func secretID(s store.Secret) string { return s.ID }

// PageSecretsInFolder implements repo.Store.
func (m *Store) PageSecretsInFolder(_ context.Context, tid string, folder *string, scope store.SecretScope, req listquery.Request) ([]store.Secret, int, listquery.Request, error) {
	req = store.ListRequest(req, store.SecretList)
	if err := m.fail("PageSecretsInFolder"); err != nil {
		return nil, 0, req, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	all := m.live(tid, func(s store.Secret) bool { return sameParent(s.FolderID, folder) && m.visible(s, scope) })
	listquery.SortSlice(all, req, secretKey, secretID)
	pg, total, applied := listquery.Window(all, req)
	return append([]store.Secret{}, pg...), total, applied, nil
}

// PageSearchSecrets implements repo.Store.
func (m *Store) PageSearchSecrets(_ context.Context, tid, q string, scope store.SecretScope, req listquery.Request) ([]store.Secret, int, listquery.Request, error) {
	req = store.ListRequest(req, store.SecretSearchList)
	if err := m.fail("PageSearchSecrets"); err != nil {
		return nil, 0, req, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	lq := strings.ToLower(q)
	all := m.live(tid, func(s store.Secret) bool {
		s = m.withPath(s)
		text := strings.ToLower(s.Name + " " + s.Username + " " + s.HostURL + " " + s.Description)
		return (strings.Contains(text, lq) || strings.Contains(strings.ToLower(s.FolderPath), lq)) && m.visible(s, scope)
	})
	if req.Sort == "relevance" {
		// store.SearchOrderBy: relevance, then name ascending, then id ascending.
		rel := func(s store.Secret) int {
			if strings.Contains(strings.ToLower(s.Name), lq) {
				return 1
			}
			return 0
		}
		sort.SliceStable(all, func(i, j int) bool {
			a, b := rel(all[i]), rel(all[j])
			if a != b {
				if req.Order == listquery.Asc {
					return a < b
				}
				return a > b
			}
			na, nb := strings.ToLower(all[i].Name), strings.ToLower(all[j].Name)
			if na != nb {
				return na < nb
			}
			return all[i].ID < all[j].ID
		})
	} else {
		listquery.SortSlice(all, req, secretKey, secretID)
	}
	pg, total, applied := listquery.Window(all, req)
	return append([]store.Secret{}, pg...), total, applied, nil
}

// PageSharesOfSecret implements repo.Store.
func (m *Store) PageSharesOfSecret(_ context.Context, tid, sid, by string, req listquery.Request) ([]store.Share, int, listquery.Request, error) {
	req = store.ListRequest(req, store.ShareList)
	if err := m.fail("PageSharesOfSecret"); err != nil {
		return nil, 0, req, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []store.Share
	for _, s := range m.Shares {
		if s.TenantID == tid && s.SecretID == sid && s.CreatedBy == by {
			all = append(all, s)
		}
	}
	listquery.SortSlice(all, req, func(s store.Share, field string) any {
		if field == "expires_at" {
			return s.ExpiresAt
		}
		return s.CreatedAt
	}, func(s store.Share) string { return s.ID })
	pg, total, applied := listquery.Window(all, req)
	return append([]store.Share{}, pg...), total, applied, nil
}

// PageAudit implements repo.Store.
func (m *Store) PageAudit(_ context.Context, tid string, f store.AuditQuery, req listquery.Request) ([]store.AuditRow, int, listquery.Request, error) {
	req = store.ListRequest(req, store.AuditList)
	if err := m.fail("PageAudit"); err != nil {
		return nil, 0, req, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []store.AuditRow
	for _, r := range m.Audit {
		if r.TenantID != tid || (f.EventType != "" && r.EventType != f.EventType) || (f.ActorID != "" && r.ActorID != f.ActorID) || r.TS.Before(f.From) || r.TS.After(f.To) {
			continue
		}
		all = append(all, m.resolveSubject(tid, r))
	}
	listquery.SortSlice(all, req, func(r store.AuditRow, _ string) any { return r.TS }, func(r store.AuditRow) string {
		return strings.Join([]string{r.EventType, r.ActorKind, r.ActorID, r.SubjectKind, r.SubjectID, r.Outcome, r.Reason, r.CorrelationID, string(r.Details)}, "\x00")
	})
	pg, total, applied := listquery.Window(all, req)
	return append([]store.AuditRow{}, pg...), total, applied, nil
}

// resolveSubject fills SubjectName like store.QueryAudit: existing secrets
// and folders by name / path, shares by the shared secret's name. Callers
// hold m.mu.
func (m *Store) resolveSubject(tid string, r store.AuditRow) store.AuditRow {
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
	return r
}
