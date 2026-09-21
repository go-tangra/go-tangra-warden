package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-freya/freya/services/warden/internal/transfer"
	"github.com/go-freya/freya/services/warden/internal/vault"
)

// TransferDeps are the services behind the transfer and backup routes.
type TransferDeps struct {
	Transfer *transfer.Service
	Vault    vault.Store
	MaxBytes int64 // document limit (config limits_warden.transfer_max_bytes)
}

func transferError(err error) error {
	switch {
	case errors.Is(err, transfer.ErrTooLarge):
		return ErrBodyTooLarge
	case errors.Is(err, transfer.ErrMalformed):
		return ErrMalformed
	case errors.Is(err, transfer.ErrInvalid), errors.Is(err, transfer.ErrTooDeep):
		return ErrValidation
	}
	return domainError(err)
}

// readDocument reads a bounded upload body.
func readDocument(r *http.Request, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = transfer.MaxBytes
	}
	if r.ContentLength > limit {
		return nil, ErrBodyTooLarge
	}
	data, err := transfer.ReadBounded(r.Body, limit)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) || errors.Is(err, transfer.ErrTooLarge) {
			return nil, ErrBodyTooLarge
		}
		return nil, ErrMalformed
	}
	return data, nil
}

// streamJSON encodes a large document straight to the response.
func streamJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", "attachment")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

// RegisterTransfer mounts the Bitwarden and backup routes (contracts §transfer & backup).
func (s *Server) RegisterTransfer(d TransferDeps) {
	folderParam := func(r *http.Request) *string {
		if f := r.URL.Query().Get("folder_id"); f != "" {
			return &f
		}
		return nil
	}
	s.MustHandle("POST", "/api/warden/v1/transfer/bitwarden/validate", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		data, err := readDocument(r, d.MaxBytes)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		rep, err := d.Transfer.ValidateBitwarden(r.Context(), subj, data, folderParam(r))
		if err != nil {
			Fail(w, r, s.rt.Logger(), transferError(err))
			return
		}
		WriteJSON(w, http.StatusOK, rep)
	})
	s.MustHandle("POST", "/api/warden/v1/transfer/bitwarden/import", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		data, err := readDocument(r, d.MaxBytes)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		rep, err := d.Transfer.ImportBitwarden(r.Context(), subj, data, folderParam(r), transfer.Strategy(r.URL.Query().Get("duplicates")))
		if err != nil {
			Fail(w, r, s.rt.Logger(), transferError(err))
			return
		}
		WriteJSON(w, http.StatusOK, rep)
	})
	s.MustHandle("POST", "/api/warden/v1/transfer/bitwarden/export", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		doc, err := d.Transfer.ExportBitwarden(r.Context(), subj, folderParam(r))
		if err != nil {
			Fail(w, r, s.rt.Logger(), transferError(err))
			return
		}
		streamJSON(w, doc)
	})
	s.MustHandle("POST", "/api/warden/v1/backup/export", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		b, err := d.Transfer.ExportBackup(r.Context(), subj, r.URL.Query().Get("include_material") == "true", d.Vault)
		if err != nil {
			Fail(w, r, s.rt.Logger(), transferError(err))
			return
		}
		streamJSON(w, b)
	})
	s.MustHandle("POST", "/api/warden/v1/backup/import", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		data, err := readDocument(r, d.MaxBytes)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		rep, err := d.Transfer.ImportBackup(r.Context(), subj, data, d.Vault)
		if err != nil {
			Fail(w, r, s.rt.Logger(), transferError(err))
			return
		}
		WriteJSON(w, http.StatusOK, rep)
	})
}
