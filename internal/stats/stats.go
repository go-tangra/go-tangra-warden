// Package stats computes per-tenant counts for the statistics route.
package stats

import (
	"context"
	"time"

	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
)

// Store reads the counts.
type Store interface {
	TenantStats(ctx context.Context, tenantID string, now time.Time) (store.Stats, error)
}

// View is the statistics document (contracts §Stats).
type View struct {
	Secrets         int64            `json:"secrets"`
	SecretsWithTOTP int64            `json:"secrets_with_totp"`
	Folders         int64            `json:"folders"`
	Versions        int64            `json:"versions"`
	Grants          map[string]int64 `json:"grants"`
	Shares          map[string]int64 `json:"shares"`
	Operations24h   int64            `json:"operations_24h"`
}

// Service computes statistics.
type Service struct {
	st  Store
	now func() time.Time
}

// New wires the service.
func New(st Store) *Service { return &Service{st: st, now: time.Now} }

// SetClock injects the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// ForTenant returns the counts of one tenant.
func (s *Service) ForTenant(ctx context.Context, tenantID string) (View, error) {
	st, err := s.st.TenantStats(ctx, tenantID, s.now())
	if err != nil {
		return View{}, err
	}
	v := View{Secrets: st.Secrets, SecretsWithTOTP: st.SecretsWithTOTP, Folders: st.Folders, Versions: st.Versions, Grants: st.Grants, Shares: st.Shares, Operations24h: st.Operations24h}
	if v.Grants == nil {
		v.Grants = map[string]int64{}
	}
	if v.Shares == nil {
		v.Shares = map[string]int64{}
	}
	return v, nil
}
