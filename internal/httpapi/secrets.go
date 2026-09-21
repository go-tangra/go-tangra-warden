package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-freya/freya/services/warden/internal/secrets"
)

// RegisterSecrets mounts the secret routes (contracts §secrets).
func (s *Server) RegisterSecrets(d StoryDeps) {
	s.MustHandle("GET", "/api/warden/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		q := r.URL.Query()
		var folder *string
		if f := q.Get("folder_id"); f != "" {
			folder = &f
		}
		limit, _ := strconv.Atoi(q.Get("limit"))
		page, err := d.Secrets.List(r.Context(), subj, folder, q.Get("cursor"), limit)
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, page)
	})
	s.MustHandle("POST", "/api/warden/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			FolderID    *string         `json:"folder_id"`
			Name        string          `json:"name"`
			Username    string          `json:"username"`
			HostURL     string          `json:"host_url"`
			Description string          `json:"description"`
			Metadata    json.RawMessage `json:"metadata"`
			Password    string          `json:"password"`
			TOTP        string          `json:"totp"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Secrets.Create(r.Context(), subj, secrets.Input{FolderID: in.FolderID, Name: in.Name, Username: in.Username, HostURL: in.HostURL, Description: in.Description, Metadata: in.Metadata, Password: in.Password, TOTP: in.TOTP})
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusCreated, out)
	})
	s.MustHandle("GET", "/api/warden/v1/secrets/search", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		page, err := d.Secrets.Search(r.Context(), subj, q.Get("q"), q.Get("cursor"), limit)
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, page)
	})
	s.MustHandle("GET", "/api/warden/v1/secrets/{id}", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Secrets.Get(r.Context(), subj, r.PathValue("id"))
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("PUT", "/api/warden/v1/secrets/{id}", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			Name        *string         `json:"name"`
			Username    *string         `json:"username"`
			HostURL     *string         `json:"host_url"`
			Description *string         `json:"description"`
			Metadata    json.RawMessage `json:"metadata"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Secrets.Update(r.Context(), subj, r.PathValue("id"), secrets.Patch{Name: in.Name, Username: in.Username, HostURL: in.HostURL, Description: in.Description, Metadata: in.Metadata})
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("POST", "/api/warden/v1/secrets/{id}/remove", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Secrets.Delete(r.Context(), subj, r.PathValue("id")); err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	s.MustHandle("POST", "/api/warden/v1/secrets/{id}/move", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			FolderID *string `json:"folder_id"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Secrets.Move(r.Context(), subj, r.PathValue("id"), in.FolderID)
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("GET", "/api/warden/v1/secrets/{id}/password", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		version, _ := strconv.Atoi(r.URL.Query().Get("version"))
		out, err := d.Secrets.Reveal(r.Context(), subj, r.PathValue("id"), version)
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("PUT", "/api/warden/v1/secrets/{id}/password", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			Password string `json:"password"`
			Comment  string `json:"comment"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		v, err := d.Secrets.UpdatePassword(r.Context(), subj, r.PathValue("id"), in.Password, in.Comment)
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"version": v})
	})
	s.MustHandle("GET", "/api/warden/v1/secrets/{id}/versions", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Secrets.Versions(r.Context(), subj, r.PathValue("id"))
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": out})
	})
	s.MustHandle("POST", "/api/warden/v1/secrets/{id}/versions/{version}/restore", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			Comment string `json:"comment"`
		}
		if r.ContentLength != 0 {
			if err := DecodeJSON(r, &in, 0); err != nil {
				Fail(w, r, nil, err)
				return
			}
		}
		version, _ := strconv.Atoi(r.PathValue("version"))
		v, err := d.Secrets.Restore(r.Context(), subj, r.PathValue("id"), version, in.Comment)
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"version": v})
	})
	s.MustHandle("GET", "/api/warden/v1/secrets/{id}/totp", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Secrets.TOTPCode(r.Context(), subj, r.PathValue("id"))
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("PUT", "/api/warden/v1/secrets/{id}/totp", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			TOTP string `json:"totp"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Secrets.SetTOTP(r.Context(), subj, r.PathValue("id"), in.TOTP); err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	s.MustHandle("DELETE", "/api/warden/v1/secrets/{id}/totp", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Secrets.RemoveTOTP(r.Context(), subj, r.PathValue("id")); err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
