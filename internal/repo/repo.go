// Package repo declares the persistence the services depend on. The database
// binding (repodb) runs every call in a tenant-scoped transaction under RLS;
// the in-memory double (memstore) applies the same tenant argument checks so
// unit tests observe identical semantics.
package repo

import (
	"context"
	"time"

	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
)

// Folders is the folder tree persistence.
type Folders interface {
	InsertFolder(ctx context.Context, f store.Folder) error
	GetFolder(ctx context.Context, tenantID, id string) (store.Folder, error)
	FolderChildren(ctx context.Context, tenantID string, parentID *string) ([]store.Folder, error)
	AllFolders(ctx context.Context, tenantID string, limit int) ([]store.Folder, error)
	FolderSubtree(ctx context.Context, tenantID, id string) ([]store.Folder, error)
	RenameFolder(ctx context.Context, tenantID, id, name, updatedBy string) error
	MoveFolder(ctx context.Context, tenantID, id string, newParent *string, newAncestors []string, newPath, updatedBy string) error
	DeleteFolder(ctx context.Context, tenantID, id string) error
	CountFolderContents(ctx context.Context, tenantID, id string) (folders, secrets int, err error)
}

// Secrets is the secret metadata persistence (never material).
type Secrets interface {
	InsertSecret(ctx context.Context, s store.Secret) error
	GetSecret(ctx context.Context, tenantID, id string) (store.Secret, error)
	SecretsInFolder(ctx context.Context, tenantID string, folderID *string, afterName, afterID string, limit int) ([]store.Secret, error)
	SecretsByIDs(ctx context.Context, tenantID string, ids []string) ([]store.Secret, error)
	SecretsInFolders(ctx context.Context, tenantID string, folderIDs []string) ([]store.Secret, error)
	AllSecrets(ctx context.Context, tenantID string, limit int) ([]store.Secret, error)
	SearchSecrets(ctx context.Context, tenantID, q string, secretIDs, folderIDs []string, includeRoot bool, limit int) ([]store.Secret, error)
	UpdateSecret(ctx context.Context, s store.Secret) error
	SetSecretVersion(ctx context.Context, tenantID, id string, version int, updatedBy *string) error
	SetSecretTOTP(ctx context.Context, tenantID, id string, has bool, updatedBy *string) error
	MoveSecret(ctx context.Context, tenantID, id string, folderID *string, updatedBy *string) error
	SoftDeleteSecret(ctx context.Context, tenantID, id string) error
	HardDeleteSecret(ctx context.Context, tenantID, id string) error
	SoftDeletedSecrets(ctx context.Context, tenantID string) ([]store.Secret, error)
	RecentSecrets(ctx context.Context, since time.Time, limit int) ([]store.Secret, error)      // system scope
	PendingSecrets(ctx context.Context, olderThan time.Time, limit int) ([]store.Secret, error) // system scope: soft-deleted or never committed
	InsertVersion(ctx context.Context, v store.SecretVersion) error
	VersionsOf(ctx context.Context, tenantID, secretID string) ([]store.SecretVersion, error)
	GetVersion(ctx context.Context, tenantID, secretID string, version int) (store.SecretVersion, error)
}

// Grants is the relation-tuple persistence.
type Grants interface {
	UpsertGrant(ctx context.Context, g store.Grant) (store.Grant, error)
	GetGrant(ctx context.Context, tenantID, id string) (store.Grant, error)
	DeleteGrant(ctx context.Context, tenantID, id string) error
	GrantsOnResources(ctx context.Context, tenantID string, resourceIDs []string) ([]store.Grant, error)
	GrantsForSubjects(ctx context.Context, tenantID, userID string, roles []string, now time.Time) ([]store.Grant, error)
	DeleteGrantsOfResource(ctx context.Context, tenantID, resourceType, resourceID string) error
}

// Shares is the external-share persistence.
type Shares interface {
	InsertShare(ctx context.Context, s store.Share) error
	ShareByTokenHash(ctx context.Context, hash string) (store.Share, error) // system scope
	GetShare(ctx context.Context, tenantID, id string) (store.Share, error)
	SharesOfSecret(ctx context.Context, tenantID, secretID, createdBy string) ([]store.Share, error)
	ConsumeShareOpen(ctx context.Context, id string) (store.Share, error) // system scope
	SetShareState(ctx context.Context, tenantID, id, state string) error
	ExpireShares(ctx context.Context, now time.Time) (int64, error) // system scope
}

// Audit is the audit persistence.
type Audit interface {
	InsertAuditRows(ctx context.Context, rows []store.AuditRow) error
	QueryAudit(ctx context.Context, tenantID, eventType, actorID string, from, to, cursor time.Time, limit int) ([]store.AuditRow, error)
}

// Stats reads the per-tenant counts.
type Stats interface {
	TenantStats(ctx context.Context, tenantID string, now time.Time) (store.Stats, error)
}

// Store is everything, plus Atomic: fn runs against a Store whose writes are
// committed together or not at all (one transaction in the database; a
// snapshot rollback in memory).
type Store interface {
	Folders
	Secrets
	Grants
	Shares
	Audit
	Stats
	Atomic(ctx context.Context, tenantID string, fn func(Store) error) error
}
