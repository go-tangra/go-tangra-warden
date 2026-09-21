package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-freya/freya/services/warden/internal/authz"
)

// RegisterGrants mounts the grant and access routes (contracts §permissions).
func (s *Server) RegisterGrants(d StoryDeps) {
	s.MustHandle("GET", "/api/warden/v1/grants", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		q := r.URL.Query()
		out, err := d.Authz.ListGrants(r.Context(), subj, q.Get("resource_type"), q.Get("resource_id"))
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": out})
	})
	s.MustHandle("POST", "/api/warden/v1/grants", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			ResourceType string     `json:"resource_type"`
			ResourceID   string     `json:"resource_id"`
			SubjectType  string     `json:"subject_type"`
			SubjectID    string     `json:"subject_id"`
			Relation     string     `json:"relation"`
			ExpiresAt    *time.Time `json:"expires_at"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Authz.Grant(r.Context(), subj, authz.GrantInput{ResourceType: in.ResourceType, ResourceID: in.ResourceID, SubjectType: in.SubjectType, SubjectID: in.SubjectID, Relation: in.Relation, ExpiresAt: in.ExpiresAt})
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusCreated, out)
	})
	s.MustHandle("POST", "/api/warden/v1/grants/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Authz.Revoke(r.Context(), subj, r.PathValue("id")); err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	s.MustHandle("GET", "/api/warden/v1/access/check", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		q := r.URL.Query()
		dec, err := d.Authz.Check(r.Context(), subj, q.Get("resource_type"), q.Get("resource_id"), q.Get("permission"))
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"allowed": dec.Allowed, "relation": dec.Relation})
	})
	s.MustHandle("GET", "/api/warden/v1/access/effective", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		q := r.URL.Query()
		dec, err := d.Authz.Effective(r.Context(), subj, q.Get("resource_type"), q.Get("resource_id"))
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"permissions": dec.Permissions, "relation": dec.Relation, "grants": dec.Sources})
	})
	s.MustHandle("GET", "/api/warden/v1/access/resources", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		q := r.URL.Query()
		perm := q.Get("permission")
		if perm == "" {
			perm = authz.Read
		}
		limit, _ := strconv.Atoi(q.Get("limit"))
		items, next, err := d.Authz.AccessibleResources(r.Context(), subj, perm, q.Get("cursor"), limit)
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		if items == nil {
			items = []authz.Accessible{}
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next": next})
	})
}
