package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-tangra/go-tangra-warden/v4/internal/audit"
	"github.com/go-tangra/go-tangra-warden/v4/internal/generator"
	"github.com/go-tangra/go-tangra-warden/v4/internal/stats"
	"github.com/go-tangra/go-tangra-warden/v4/internal/vault"
)

// OpsDeps are the services behind the generator, statistics, audit and
// health routes.
type OpsDeps struct {
	Generator *generator.Generator
	Stats     *stats.Service
	Audit     audit.Querier
	Health    func(ctx context.Context) (db string, v vault.Health)
	Version   string
}

// RegisterOps mounts the utility routes (contracts §utilities).
func (s *Server) RegisterOps(d OpsDeps) {
	s.MustHandle("POST", "/api/warden/v1/generate", func(w http.ResponseWriter, r *http.Request) {
		if _, err := subjects(r); err != nil {
			Fail(w, r, nil, err)
			return
		}
		in := struct {
			Length  *int  `json:"length"`
			Lower   *bool `json:"lower"`
			Upper   *bool `json:"upper"`
			Digits  *bool `json:"digits"`
			Symbols *bool `json:"symbols"`
		}{}
		if r.ContentLength != 0 {
			if err := DecodeJSON(r, &in, 0); err != nil {
				Fail(w, r, nil, err)
				return
			}
		}
		o := generator.Default()
		if in.Length != nil {
			o.Length = *in.Length
		}
		if in.Lower != nil {
			o.Lower = *in.Lower
		}
		if in.Upper != nil {
			o.Upper = *in.Upper
		}
		if in.Digits != nil {
			o.Digits = *in.Digits
		}
		if in.Symbols != nil {
			o.Symbols = *in.Symbols
		}
		p, err := d.Generator.Generate(o)
		if err != nil {
			if errors.Is(err, generator.ErrLength) || errors.Is(err, generator.ErrNoClass) {
				Fail(w, r, nil, ErrValidation)
				return
			}
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		// Not audited, not logged: the value is the caller's to keep.
		WriteJSON(w, http.StatusOK, map[string]any{"password": p, "length": o.Length})
	})
	s.MustHandle("GET", "/api/warden/v1/stats", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		v, err := d.Stats.ForTenant(r.Context(), subj.TenantID)
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		WriteJSON(w, http.StatusOK, v)
	})
	s.MustHandle("GET", "/api/warden/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		q := r.URL.Query()
		f := audit.Filter{EventType: q.Get("event_type"), ActorID: q.Get("actor_id"), Cursor: q.Get("cursor")}
		if v := q.Get("from"); v != "" {
			f.From, _ = time.Parse(time.RFC3339, v)
		}
		if v := q.Get("to"); v != "" {
			f.To, _ = time.Parse(time.RFC3339, v)
		}
		page, err := audit.Query(r.Context(), d.Audit, subj.TenantID, f)
		if err != nil {
			if errors.Is(err, audit.ErrFilter) {
				Fail(w, r, nil, ErrValidation)
				return
			}
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		WriteJSON(w, http.StatusOK, page)
	})
	s.MustHandle("GET", "/api/warden/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if _, err := subjects(r); err != nil {
			Fail(w, r, nil, err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		db, v := d.Health(ctx)
		status := "ok"
		if db != "ok" || v != vault.HealthOK {
			status = "degraded"
		}
		WriteJSON(w, http.StatusOK, map[string]any{"status": status, "db": db, "vault": v, "version": d.Version})
	})
}
