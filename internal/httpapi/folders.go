package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-freya/freya/services/warden/internal/authz"
	"github.com/go-freya/freya/services/warden/internal/folders"
	"github.com/go-freya/freya/services/warden/internal/secrets"
)

// StoryDeps are the services behind the folder and secret routes.
type StoryDeps struct {
	Folders *folders.Service
	Secrets *secrets.Service
	Authz   *authz.Authz
}

// subjects derives the authz subjects from the verified caller.
func subjects(r *http.Request) (authz.Subjects, error) {
	id, err := Caller(r)
	if err != nil {
		return authz.Subjects{}, err
	}
	return authz.SubjectsOf(id), nil
}

// domainError maps service errors to refusals.
func domainError(err error) error {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, authz.ErrNotFound), errors.Is(err, secrets.ErrNoTOTP):
		return ErrNotFound
	case errors.Is(err, authz.ErrInput), errors.Is(err, folders.ErrInvalidName), errors.Is(err, secrets.ErrInvalid), errors.Is(err, secrets.ErrInvalidTOTP):
		return ErrValidation
	case errors.Is(err, folders.ErrConflict), errors.Is(err, folders.ErrNotEmpty), errors.Is(err, folders.ErrCycle):
		return ErrConflict
	}
	return err
}

// RegisterFolders mounts the folder routes.
func (s *Server) RegisterFolders(d StoryDeps) {
	s.MustHandle("GET", "/api/warden/v1/folders", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var parent *string
		if p := r.URL.Query().Get("parent_id"); p != "" {
			parent = &p
		}
		out, err := d.Folders.Children(r.Context(), subj, parent)
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": out})
	})
	s.MustHandle("POST", "/api/warden/v1/folders", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			ParentID *string `json:"parent_id"`
			Name     string  `json:"name"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Folders.Create(r.Context(), subj, in.ParentID, in.Name)
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusCreated, out)
	})
	s.MustHandle("GET", "/api/warden/v1/folders/tree", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Folders.Tree(r.Context(), subj)
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": out})
	})
	s.MustHandle("GET", "/api/warden/v1/folders/{id}", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Folders.Get(r.Context(), subj, r.PathValue("id"))
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("PUT", "/api/warden/v1/folders/{id}", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			Name string `json:"name"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Folders.Rename(r.Context(), subj, r.PathValue("id"), in.Name)
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("POST", "/api/warden/v1/folders/{id}/move", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			ParentID *string `json:"parent_id"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Folders.Move(r.Context(), subj, r.PathValue("id"), in.ParentID)
		if err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("POST", "/api/warden/v1/folders/{id}/remove", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			Recursive bool `json:"recursive"`
		}
		if r.ContentLength != 0 {
			if err := DecodeJSON(r, &in, 0); err != nil {
				Fail(w, r, nil, err)
				return
			}
		}
		if err := d.Folders.Delete(r.Context(), subj, r.PathValue("id"), in.Recursive); err != nil {
			Fail(w, r, s.rt.Logger(), domainError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
