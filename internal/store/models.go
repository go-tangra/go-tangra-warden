package store

import "time"

// Folder row. Ancestors are every ancestor id root-first; Path is the
// display path ("/Infra/Databases").
type Folder struct {
	ID, TenantID         string
	ParentID             *string
	Name, Path           string
	Ancestors            []string
	CreatedBy, UpdatedBy *string
	CreatedAt, UpdatedAt time.Time
}

// Secret row: metadata and the Vault reference, never the material.
type Secret struct {
	ID, TenantID         string
	FolderID             *string
	Name, Username       string
	HostURL, Description string
	Metadata             []byte // JSON object, <= 16 KiB
	VaultPath            string
	CurrentVersion       int
	HasTOTP              bool
	CreatedBy, UpdatedBy *string
	CreatedAt, UpdatedAt time.Time
	DeletedAt            *time.Time // set while the vault destroy is pending
	FolderPath           string     // joined for display; empty at root
}

// SecretVersion row: one KV v2 version.
type SecretVersion struct {
	SecretID, TenantID string
	Version            int
	Comment, Checksum  string
	Source             string
	MaterialMissing    bool
	CreatedBy          *string
	CreatedAt          time.Time
}

// Grant row.
type Grant struct {
	ID, TenantID             string
	ResourceType, ResourceID string // folder | secret
	SubjectType, SubjectID   string // user | role | tenant ('' for tenant)
	Relation                 string // owner | editor | viewer | sharer
	GrantedBy                *string
	GrantedAt                time.Time
	ExpiresAt                *time.Time
}

// Share row.
type Share struct {
	ID, TenantID, SecretID string
	TokenHash              string
	RecipientEmail         string
	Message                string
	MaxOpens, Opens        int
	ExpiresAt              time.Time
	CIDR, Region           *string
	State                  string // active | consumed | expired | cancelled
	CreatedBy              string
	CreatedAt              time.Time
}

// AuditRow is one persisted audit event.
type AuditRow struct {
	TS                     time.Time
	TenantID, EventType    string
	ActorKind, ActorID     string
	SubjectKind, SubjectID string
	Outcome, Reason        string
	CorrelationID          string
	Details                []byte
	// SubjectName is filled on read for secrets (name) and folders (path)
	// that still exist; the writer leaves it empty.
	SubjectName string
}

// Stats are per-tenant counts.
type Stats struct {
	Secrets, SecretsWithTOTP, Folders, Versions int64
	Grants                                      map[string]int64
	Shares                                      map[string]int64
	Operations24h                               int64
}

// ResourceRef names a resource with its display data (accessible listings).
type ResourceRef struct {
	ResourceType, ResourceID string
	Name, Path               string
}
