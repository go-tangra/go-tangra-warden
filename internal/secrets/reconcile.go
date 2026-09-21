package secrets

import (
	"context"
	"time"

	"github.com/go-freya/freya/services/warden/internal/audit"
	"github.com/go-freya/freya/services/warden/internal/store"
)

// ReconcileGrace is how long a fresh row may sit at version 0 before the
// reconciler treats it as an interrupted write.
const ReconcileGrace = 2 * time.Minute

// Report counts what one Reconcile pass settled.
type Report struct {
	Deleted  int `json:"deleted"`  // hidden rows whose material was destroyed
	Repaired int `json:"repaired"` // version-0 rows that had vault material
	Orphans  int `json:"orphans"`  // version-0 rows without material (removed)
	Failed   int `json:"failed"`
}

// Reconcile settles interrupted two-phase writes and deletions: hidden rows
// are destroyed in the vault and removed; rows at version 0 older than the
// grace period either adopt the versions the vault holds or are removed.
func (s *Service) Reconcile(ctx context.Context) (Report, error) {
	var r Report
	rows, err := s.st.PendingSecrets(ctx, s.now().Add(-ReconcileGrace), 500)
	if err != nil {
		return r, err
	}
	for _, sec := range rows {
		if sec.DeletedAt != nil {
			if err := s.vault.DeleteSecret(ctx, sec.TenantID, sec.ID); err != nil {
				r.Failed++
				continue
			}
			if err := s.st.HardDeleteSecret(ctx, sec.TenantID, sec.ID); err != nil {
				r.Failed++
				continue
			}
			r.Deleted++
			s.emit(audit.Event{Type: audit.SecretDeleted, TenantID: sec.TenantID, ActorKind: "system", SubjectKind: "secret", SubjectID: sec.ID, Outcome: "ok", Reason: "reconciled"})
			continue
		}
		versions, err := s.vault.Versions(ctx, sec.TenantID, sec.ID)
		if err != nil {
			r.Failed++
			continue
		}
		if len(versions) == 0 {
			if err := s.st.HardDeleteSecret(ctx, sec.TenantID, sec.ID); err != nil {
				r.Failed++
				continue
			}
			r.Orphans++
			s.emit(audit.Event{Type: audit.SecretDeleted, TenantID: sec.TenantID, ActorKind: "system", SubjectKind: "secret", SubjectID: sec.ID, Outcome: "ok", Reason: "orphan"})
			continue
		}
		latest := 0
		failed := false
		for _, v := range versions {
			if v > latest {
				latest = v
			}
			if err := s.st.InsertVersion(ctx, store.SecretVersion{SecretID: sec.ID, TenantID: sec.TenantID, Version: v, Checksum: "", Source: "reconcile", CreatedBy: sec.CreatedBy}); err != nil {
				failed = true
				break
			}
		}
		if failed {
			r.Failed++
			continue
		}
		if err := s.st.SetSecretVersion(ctx, sec.TenantID, sec.ID, latest, sec.CreatedBy); err != nil {
			r.Failed++
			continue
		}
		r.Repaired++
		s.emit(audit.Event{Type: audit.SecretCreated, TenantID: sec.TenantID, ActorKind: "system", SubjectKind: "secret", SubjectID: sec.ID, Outcome: "ok", Reason: "reconciled", Details: map[string]any{"version": latest}})
	}
	return r, nil
}

// RunReconciler runs Reconcile every interval until ctx ends.
func (s *Service) RunReconciler(ctx context.Context, interval time.Duration, onError func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.Reconcile(ctx); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}
