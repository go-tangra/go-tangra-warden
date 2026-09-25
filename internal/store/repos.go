package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------- folders

const folderCols = "id, tenant_id, parent_id, name, path, ancestors, created_by, updated_by, created_at, updated_at"

func scanFolder(r pgx.Row) (Folder, error) {
	var f Folder
	err := r.Scan(&f.ID, &f.TenantID, &f.ParentID, &f.Name, &f.Path, &f.Ancestors, &f.CreatedBy, &f.UpdatedBy, &f.CreatedAt, &f.UpdatedAt)
	return f, notFound(err)
}

func scanFolders(rows pgx.Rows) ([]Folder, error) {
	defer rows.Close()
	var out []Folder
	for rows.Next() {
		f, err := scanFolder(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// InsertFolder creates a folder; a sibling name clash is ErrConflict. Zero
// timestamps mean now(); a nil UpdatedBy means CreatedBy (a migration passes
// the original values).
func InsertFolder(ctx context.Context, tx pgx.Tx, f Folder) error {
	_, err := tx.Exec(ctx, `INSERT INTO folders (id, tenant_id, parent_id, name, path, ancestors, created_by, updated_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7::uuid,coalesce($8::uuid,$7::uuid),coalesce($9::timestamptz,now()),coalesce($10::timestamptz,$9::timestamptz,now()))`,
		f.ID, f.TenantID, f.ParentID, f.Name, f.Path, nonNil(f.Ancestors), f.CreatedBy, f.UpdatedBy, nullTime(f.CreatedAt), nullTime(f.UpdatedAt))
	return conflict(err)
}

// GetFolder by tenant + id.
func GetFolder(ctx context.Context, tx pgx.Tx, tenantID, id string) (Folder, error) {
	return scanFolder(tx.QueryRow(ctx, "SELECT "+folderCols+" FROM folders WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

// FolderChildren lists the direct children of parent (nil = root level).
func FolderChildren(ctx context.Context, tx pgx.Tx, tenantID string, parentID *string) ([]Folder, error) {
	rows, err := tx.Query(ctx, "SELECT "+folderCols+" FROM folders WHERE tenant_id = $1 AND parent_id IS NOT DISTINCT FROM $2 ORDER BY lower(name)", tenantID, parentID)
	if err != nil {
		return nil, err
	}
	return scanFolders(rows)
}

// AllFolders lists every folder of the tenant (tree building; bounded by the caller).
func AllFolders(ctx context.Context, tx pgx.Tx, tenantID string, limit int) ([]Folder, error) {
	rows, err := tx.Query(ctx, "SELECT "+folderCols+" FROM folders WHERE tenant_id = $1 ORDER BY path LIMIT $2", tenantID, limit)
	if err != nil {
		return nil, err
	}
	return scanFolders(rows)
}

// FolderSubtree lists the folder and every descendant.
func FolderSubtree(ctx context.Context, tx pgx.Tx, tenantID, id string) ([]Folder, error) {
	rows, err := tx.Query(ctx, "SELECT "+folderCols+" FROM folders WHERE tenant_id = $1 AND (id = $2 OR $2::uuid = ANY(ancestors)) ORDER BY path", tenantID, id)
	if err != nil {
		return nil, err
	}
	return scanFolders(rows)
}

// RenameFolder updates the name and rewrites paths of the subtree.
func RenameFolder(ctx context.Context, tx pgx.Tx, tenantID, id, name, updatedBy string) error {
	f, err := GetFolder(ctx, tx, tenantID, id)
	if err != nil {
		return err
	}
	newPath := parentPath(f.Path) + "/" + name
	ct, err := tx.Exec(ctx, "UPDATE folders SET name = $3, path = $4, updated_by = NULLIF($5,'')::uuid, updated_at = now() WHERE tenant_id = $1 AND id = $2", tenantID, id, name, newPath, updatedBy)
	if err != nil {
		return conflict(err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	_, err = tx.Exec(ctx, "UPDATE folders SET path = $3 || substr(path, length($4) + 1) WHERE tenant_id = $1 AND $2::uuid = ANY(ancestors)", tenantID, id, newPath, f.Path)
	return err
}

// MoveFolder re-parents a folder and rewrites ancestors and paths of the subtree.
func MoveFolder(ctx context.Context, tx pgx.Tx, tenantID, id string, newParent *string, newAncestors []string, newPath, updatedBy string) error {
	f, err := GetFolder(ctx, tx, tenantID, id)
	if err != nil {
		return err
	}
	ct, err := tx.Exec(ctx, "UPDATE folders SET parent_id = $3, ancestors = $4, path = $5, updated_by = NULLIF($6,'')::uuid, updated_at = now() WHERE tenant_id = $1 AND id = $2",
		tenantID, id, newParent, nonNil(newAncestors), newPath, updatedBy)
	if err != nil {
		return conflict(err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	// Descendants: replace the old ancestor prefix (f.Ancestors + f.ID) with the new one and rewrite the path prefix.
	oldPrefix := append(append([]string{}, f.Ancestors...), f.ID)
	newPrefix := append(append([]string{}, newAncestors...), f.ID)
	_, err = tx.Exec(ctx, `UPDATE folders SET
		ancestors = $3::uuid[] || ancestors[array_length($4::uuid[], 1) + 1 : array_length(ancestors, 1)],
		path = $5 || substr(path, length($6) + 1)
		WHERE tenant_id = $1 AND $2::uuid = ANY(ancestors)`, tenantID, id, newPrefix, oldPrefix, newPath, f.Path)
	return err
}

// DeleteFolder removes a folder; descendants cascade, secrets must be gone (RESTRICT).
func DeleteFolder(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, "DELETE FROM folders WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// CountFolderContents counts direct subfolders and (live) secrets.
func CountFolderContents(ctx context.Context, tx pgx.Tx, tenantID, id string) (folders, secrets int, err error) {
	err = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM folders WHERE tenant_id = $1 AND parent_id = $2),
		(SELECT count(*) FROM secrets WHERE tenant_id = $1 AND folder_id = $2)`, tenantID, id).Scan(&folders, &secrets)
	return
}

func parentPath(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return ""
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ---------------------------------------------------------------- secrets

// Column lists of the secrets table (metadata only: the material lives in the vault).
const (
	secretCols = "s.id, s.tenant_id, s.folder_id, s.name, s.username, s.host_url, s.description, s.metadata, s.vault_path, s.current_version, s.has_totp, s.created_by, s.updated_by, s.created_at, s.updated_at, s.deleted_at, coalesce(f.path, '')" // #nosec G101 -- column names, not credentials
	secretFrom = " FROM secrets s LEFT JOIN folders f ON f.id = s.folder_id "                                                                                                                                                                         // #nosec G101 -- SQL fragment
)

func scanSecret(r pgx.Row) (Secret, error) {
	var s Secret
	err := r.Scan(&s.ID, &s.TenantID, &s.FolderID, &s.Name, &s.Username, &s.HostURL, &s.Description, &s.Metadata, &s.VaultPath, &s.CurrentVersion, &s.HasTOTP,
		&s.CreatedBy, &s.UpdatedBy, &s.CreatedAt, &s.UpdatedAt, &s.DeletedAt, &s.FolderPath)
	return s, notFound(err)
}

func scanSecrets(rows pgx.Rows) ([]Secret, error) {
	defer rows.Close()
	var out []Secret
	for rows.Next() {
		s, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// InsertSecret creates the metadata row (version 0 until the first material
// write commits). Zero timestamps mean now(); a nil UpdatedBy means CreatedBy.
func InsertSecret(ctx context.Context, tx pgx.Tx, s Secret) error {
	_, err := tx.Exec(ctx, `INSERT INTO secrets (id, tenant_id, folder_id, name, username, host_url, description, metadata, vault_path, current_version, has_totp, created_by, updated_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::uuid,coalesce($13::uuid,$12::uuid),coalesce($14::timestamptz,now()),coalesce($15::timestamptz,$14::timestamptz,now()))`,
		s.ID, s.TenantID, s.FolderID, s.Name, s.Username, s.HostURL, s.Description, jsonOrEmpty(s.Metadata), s.VaultPath, s.CurrentVersion, s.HasTOTP, s.CreatedBy,
		s.UpdatedBy, nullTime(s.CreatedAt), nullTime(s.UpdatedAt))
	return err
}

func jsonOrEmpty(b []byte) []byte {
	if len(b) == 0 {
		return []byte("{}")
	}
	return b
}

// GetSecret by tenant + id (live rows only).
func GetSecret(ctx context.Context, tx pgx.Tx, tenantID, id string) (Secret, error) {
	return scanSecret(tx.QueryRow(ctx, "SELECT "+secretCols+secretFrom+"WHERE s.tenant_id = $1 AND s.id = $2 AND s.deleted_at IS NULL", tenantID, id))
}

// SecretsInFolder pages the live secrets of a folder (nil = root) after cursor (name, id).
func SecretsInFolder(ctx context.Context, tx pgx.Tx, tenantID string, folderID *string, afterName, afterID string, limit int) ([]Secret, error) {
	rows, err := tx.Query(ctx, "SELECT "+secretCols+secretFrom+`WHERE s.tenant_id = $1 AND s.folder_id IS NOT DISTINCT FROM $2 AND s.deleted_at IS NULL
		AND (lower(s.name), s.id::text) > (lower($3), $4) ORDER BY lower(s.name), s.id LIMIT $5`, tenantID, folderID, afterName, afterID, limit)
	if err != nil {
		return nil, err
	}
	return scanSecrets(rows)
}

// SecretsByIDs loads live secrets by id (accessible listings).
func SecretsByIDs(ctx context.Context, tx pgx.Tx, tenantID string, ids []string) ([]Secret, error) {
	rows, err := tx.Query(ctx, "SELECT "+secretCols+secretFrom+"WHERE s.tenant_id = $1 AND s.id = ANY($2::uuid[]) AND s.deleted_at IS NULL ORDER BY lower(s.name)", tenantID, ids)
	if err != nil {
		return nil, err
	}
	return scanSecrets(rows)
}

// SecretsInFolders lists live secrets under any of the folders (nil entries not supported; root handled by the caller).
func SecretsInFolders(ctx context.Context, tx pgx.Tx, tenantID string, folderIDs []string) ([]Secret, error) {
	rows, err := tx.Query(ctx, "SELECT "+secretCols+secretFrom+"WHERE s.tenant_id = $1 AND s.folder_id = ANY($2::uuid[]) AND s.deleted_at IS NULL ORDER BY lower(s.name)", tenantID, folderIDs)
	if err != nil {
		return nil, err
	}
	return scanSecrets(rows)
}

// AllSecrets lists every live secret of the tenant ordered by folder path and name (backups).
func AllSecrets(ctx context.Context, tx pgx.Tx, tenantID string, limit int) ([]Secret, error) {
	rows, err := tx.Query(ctx, "SELECT "+secretCols+secretFrom+"WHERE s.tenant_id = $1 AND s.deleted_at IS NULL ORDER BY coalesce(f.path, ''), lower(s.name), s.id LIMIT $2", tenantID, limit)
	if err != nil {
		return nil, err
	}
	return scanSecrets(rows)
}

// SearchSecrets matches the generated search column and folder paths, limited
// to the given accessible secret ids / folder ids (either list may be empty).
func SearchSecrets(ctx context.Context, tx pgx.Tx, tenantID, q string, secretIDs, folderIDs []string, includeRoot bool, limit int) ([]Secret, error) {
	rows, err := tx.Query(ctx, "SELECT "+secretCols+secretFrom+`WHERE s.tenant_id = $1 AND s.deleted_at IS NULL
		AND (s.search LIKE '%' || lower($2) || '%' OR lower(coalesce(f.path,'')) LIKE '%' || lower($2) || '%')
		AND (s.id = ANY($3::uuid[]) OR s.folder_id = ANY($4::uuid[]) OR ($5 AND s.folder_id IS NULL))
		ORDER BY (lower(s.name) LIKE '%' || lower($2) || '%') DESC, lower(s.name) LIMIT $6`, tenantID, q, nonNil(secretIDs), nonNil(folderIDs), includeRoot, limit)
	if err != nil {
		return nil, err
	}
	return scanSecrets(rows)
}

// UpdateSecret writes the metadata fields.
func UpdateSecret(ctx context.Context, tx pgx.Tx, s Secret) error {
	ct, err := tx.Exec(ctx, `UPDATE secrets SET name = $3, username = $4, host_url = $5, description = $6, metadata = $7, updated_by = $8, updated_at = now()
		WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, s.TenantID, s.ID, s.Name, s.Username, s.HostURL, s.Description, jsonOrEmpty(s.Metadata), s.UpdatedBy)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SetSecretVersion records the committed current version.
func SetSecretVersion(ctx context.Context, tx pgx.Tx, tenantID, id string, version int, updatedBy *string) error {
	ct, err := tx.Exec(ctx, "UPDATE secrets SET current_version = $3, updated_by = $4, updated_at = now() WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL", tenantID, id, version, updatedBy)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SetSecretTOTP flags the seed presence.
func SetSecretTOTP(ctx context.Context, tx pgx.Tx, tenantID, id string, has bool, updatedBy *string) error {
	ct, err := tx.Exec(ctx, "UPDATE secrets SET has_totp = $3, updated_by = $4, updated_at = now() WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL", tenantID, id, has, updatedBy)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// MoveSecret changes the folder.
func MoveSecret(ctx context.Context, tx pgx.Tx, tenantID, id string, folderID *string, updatedBy *string) error {
	ct, err := tx.Exec(ctx, "UPDATE secrets SET folder_id = $3, updated_by = $4, updated_at = now() WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL", tenantID, id, folderID, updatedBy)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SoftDeleteSecret hides the row until the vault destroy succeeds.
func SoftDeleteSecret(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, "UPDATE secrets SET deleted_at = now() WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL", tenantID, id)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// HardDeleteSecret removes the row and its versions/shares/grants.
func HardDeleteSecret(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	if _, err := tx.Exec(ctx, "DELETE FROM grants WHERE tenant_id = $1 AND resource_type = 'secret' AND resource_id = $2", tenantID, id); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "DELETE FROM secrets WHERE tenant_id = $1 AND id = $2", tenantID, id)
	return err
}

// SoftDeletedSecrets lists rows awaiting vault destruction (reconciler).
func SoftDeletedSecrets(ctx context.Context, tx pgx.Tx, tenantID string) ([]Secret, error) {
	rows, err := tx.Query(ctx, "SELECT "+secretCols+secretFrom+"WHERE s.tenant_id = $1 AND s.deleted_at IS NOT NULL", tenantID)
	if err != nil {
		return nil, err
	}
	return scanSecrets(rows)
}

// RecentSecrets lists live secrets touched since t (reconciler).
func RecentSecrets(ctx context.Context, tx pgx.Tx, since time.Time, limit int) ([]Secret, error) {
	rows, err := tx.Query(ctx, "SELECT "+secretCols+secretFrom+"WHERE s.updated_at >= $1 AND s.deleted_at IS NULL ORDER BY s.updated_at LIMIT $2", since, limit)
	if err != nil {
		return nil, err
	}
	return scanSecrets(rows)
}

// PendingSecrets lists rows the reconciler must settle: soft-deleted ones and
// rows whose first material write never committed (version 0, older than t).
func PendingSecrets(ctx context.Context, tx pgx.Tx, olderThan time.Time, limit int) ([]Secret, error) {
	rows, err := tx.Query(ctx, "SELECT "+secretCols+secretFrom+"WHERE s.deleted_at IS NOT NULL OR (s.current_version = 0 AND s.created_at < $1) ORDER BY s.created_at LIMIT $2", olderThan, limit)
	if err != nil {
		return nil, err
	}
	return scanSecrets(rows)
}

// ---------------------------------------------------------------- versions

// InsertVersion records one version (idempotent per number); a zero
// CreatedAt means now().
func InsertVersion(ctx context.Context, tx pgx.Tx, v SecretVersion) error {
	_, err := tx.Exec(ctx, `INSERT INTO secret_versions (secret_id, tenant_id, version, comment, checksum, source, material_missing, created_by, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,coalesce($9::timestamptz,now())) ON CONFLICT (secret_id, version) DO NOTHING`,
		v.SecretID, v.TenantID, v.Version, v.Comment, v.Checksum, v.Source, v.MaterialMissing, v.CreatedBy, nullTime(v.CreatedAt))
	return err
}

func scanVersions(rows pgx.Rows) ([]SecretVersion, error) {
	defer rows.Close()
	var out []SecretVersion
	for rows.Next() {
		var v SecretVersion
		if err := rows.Scan(&v.SecretID, &v.TenantID, &v.Version, &v.Comment, &v.Checksum, &v.Source, &v.MaterialMissing, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// VersionsOf lists versions newest first.
func VersionsOf(ctx context.Context, tx pgx.Tx, tenantID, secretID string) ([]SecretVersion, error) {
	rows, err := tx.Query(ctx, `SELECT secret_id, tenant_id, version, comment, checksum, source, material_missing, created_by, created_at
		FROM secret_versions WHERE tenant_id = $1 AND secret_id = $2 ORDER BY version DESC`, tenantID, secretID)
	if err != nil {
		return nil, err
	}
	return scanVersions(rows)
}

// GetVersion returns one version row.
func GetVersion(ctx context.Context, tx pgx.Tx, tenantID, secretID string, version int) (SecretVersion, error) {
	var v SecretVersion
	err := tx.QueryRow(ctx, `SELECT secret_id, tenant_id, version, comment, checksum, source, material_missing, created_by, created_at
		FROM secret_versions WHERE tenant_id = $1 AND secret_id = $2 AND version = $3`, tenantID, secretID, version).
		Scan(&v.SecretID, &v.TenantID, &v.Version, &v.Comment, &v.Checksum, &v.Source, &v.MaterialMissing, &v.CreatedBy, &v.CreatedAt)
	return v, notFound(err)
}

// ---------------------------------------------------------------- grants

const grantCols = "id, tenant_id, resource_type, resource_id, subject_type, subject_id, relation, granted_by, granted_at, expires_at"

func scanGrant(r pgx.Row) (Grant, error) {
	var g Grant
	err := r.Scan(&g.ID, &g.TenantID, &g.ResourceType, &g.ResourceID, &g.SubjectType, &g.SubjectID, &g.Relation, &g.GrantedBy, &g.GrantedAt, &g.ExpiresAt)
	return g, notFound(err)
}

func scanGrants(rows pgx.Rows) ([]Grant, error) {
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// UpsertGrant creates or replaces the grant for (resource, subject); a zero
// GrantedAt means now().
func UpsertGrant(ctx context.Context, tx pgx.Tx, g Grant) (Grant, error) {
	return scanGrant(tx.QueryRow(ctx, `INSERT INTO grants (id, tenant_id, resource_type, resource_id, subject_type, subject_id, relation, granted_by, expires_at, granted_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,coalesce($10::timestamptz,now()))
		ON CONFLICT (tenant_id, resource_type, resource_id, subject_type, subject_id) DO UPDATE SET relation = EXCLUDED.relation, granted_by = EXCLUDED.granted_by, granted_at = EXCLUDED.granted_at, expires_at = EXCLUDED.expires_at
		RETURNING `+grantCols, g.ID, g.TenantID, g.ResourceType, g.ResourceID, g.SubjectType, g.SubjectID, g.Relation, g.GrantedBy, g.ExpiresAt, nullTime(g.GrantedAt)))
}

// GetGrant by id.
func GetGrant(ctx context.Context, tx pgx.Tx, tenantID, id string) (Grant, error) {
	return scanGrant(tx.QueryRow(ctx, "SELECT "+grantCols+" FROM grants WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

// DeleteGrant revokes.
func DeleteGrant(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, "DELETE FROM grants WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// GrantsOnResources lists grants on any of the resource ids (a resource and its ancestors).
func GrantsOnResources(ctx context.Context, tx pgx.Tx, tenantID string, resourceIDs []string) ([]Grant, error) {
	rows, err := tx.Query(ctx, "SELECT "+grantCols+" FROM grants WHERE tenant_id = $1 AND resource_id = ANY($2::uuid[]) ORDER BY granted_at", tenantID, nonNil(resourceIDs))
	if err != nil {
		return nil, err
	}
	return scanGrants(rows)
}

// GrantsForSubjects lists unexpired grants held by any of the subjects
// (user id, role slugs, tenant).
func GrantsForSubjects(ctx context.Context, tx pgx.Tx, tenantID, userID string, roles []string, now time.Time) ([]Grant, error) {
	rows, err := tx.Query(ctx, "SELECT "+grantCols+` FROM grants WHERE tenant_id = $1
		AND ((subject_type = 'user' AND subject_id = $2) OR (subject_type = 'role' AND subject_id = ANY($3::text[])) OR subject_type = 'tenant')
		AND (expires_at IS NULL OR expires_at > $4) ORDER BY granted_at`, tenantID, userID, nonNil(roles), now)
	if err != nil {
		return nil, err
	}
	return scanGrants(rows)
}

// DeleteGrantsOfResource removes every grant on a resource (folder deletion).
func DeleteGrantsOfResource(ctx context.Context, tx pgx.Tx, tenantID, resourceType, resourceID string) error {
	_, err := tx.Exec(ctx, "DELETE FROM grants WHERE tenant_id = $1 AND resource_type = $2 AND resource_id = $3", tenantID, resourceType, resourceID)
	return err
}

// ---------------------------------------------------------------- shares

const shareCols = "id, tenant_id, secret_id, token_hash, recipient_email, message, max_opens, opens, expires_at, cidr, region, state, created_by, created_at"

func scanShare(r pgx.Row) (Share, error) {
	var s Share
	err := r.Scan(&s.ID, &s.TenantID, &s.SecretID, &s.TokenHash, &s.RecipientEmail, &s.Message, &s.MaxOpens, &s.Opens, &s.ExpiresAt, &s.CIDR, &s.Region, &s.State, &s.CreatedBy, &s.CreatedAt)
	return s, notFound(err)
}

func InsertShare(ctx context.Context, tx pgx.Tx, s Share) error {
	_, err := tx.Exec(ctx, `INSERT INTO shares (id, tenant_id, secret_id, token_hash, recipient_email, message, max_opens, opens, expires_at, cidr, region, state, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,0,$8,$9,$10,'active',$11)`, s.ID, s.TenantID, s.SecretID, s.TokenHash, s.RecipientEmail, s.Message, s.MaxOpens, s.ExpiresAt, s.CIDR, s.Region, s.CreatedBy)
	return err
}

// ShareByTokenHash is a system-scope lookup (the recipient is anonymous).
func ShareByTokenHash(ctx context.Context, tx pgx.Tx, hash string) (Share, error) {
	return scanShare(tx.QueryRow(ctx, "SELECT "+shareCols+" FROM shares WHERE token_hash = $1", hash))
}

func GetShare(ctx context.Context, tx pgx.Tx, tenantID, id string) (Share, error) {
	return scanShare(tx.QueryRow(ctx, "SELECT "+shareCols+" FROM shares WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

// SharesOfSecret lists shares of a secret created by a user, newest first.
func SharesOfSecret(ctx context.Context, tx pgx.Tx, tenantID, secretID, createdBy string) ([]Share, error) {
	rows, err := tx.Query(ctx, "SELECT "+shareCols+" FROM shares WHERE tenant_id = $1 AND secret_id = $2 AND created_by = $3 ORDER BY created_at DESC", tenantID, secretID, createdBy)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Share
	for rows.Next() {
		s, err := scanShare(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ConsumeShareOpen increments opens atomically and returns the updated row;
// ErrNotFound when the share is not active or its budget is exhausted.
func ConsumeShareOpen(ctx context.Context, tx pgx.Tx, id string) (Share, error) {
	return scanShare(tx.QueryRow(ctx, `UPDATE shares SET opens = opens + 1, state = CASE WHEN opens + 1 >= max_opens THEN 'consumed' ELSE state END
		WHERE id = $1 AND state = 'active' AND opens < max_opens AND expires_at > now() RETURNING `+shareCols, id))
}

// SetShareState transitions a share (cancel, expire).
func SetShareState(ctx context.Context, tx pgx.Tx, tenantID, id, state string) error {
	ct, err := tx.Exec(ctx, "UPDATE shares SET state = $3 WHERE tenant_id = $1 AND id = $2 AND state = 'active'", tenantID, id, state)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ExpireShares marks expired active shares (sweeper, system scope).
func ExpireShares(ctx context.Context, tx pgx.Tx, now time.Time) (int64, error) {
	ct, err := tx.Exec(ctx, "UPDATE shares SET state = 'expired' WHERE state = 'active' AND expires_at <= $1", now)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// ---------------------------------------------------------------- audit & stats

// InsertAuditRows writes a batch.
func InsertAuditRows(ctx context.Context, tx pgx.Tx, rows []AuditRow) error {
	for _, r := range rows {
		if _, err := tx.Exec(ctx, `INSERT INTO warden_audit_events (ts, tenant_id, event_type, actor_kind, actor_id, subject_kind, subject_id, outcome, reason, correlation_id, details)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, r.TS, r.TenantID, r.EventType, r.ActorKind, r.ActorID, r.SubjectKind, r.SubjectID, r.Outcome, r.Reason, r.CorrelationID, jsonOrEmpty(r.Details)); err != nil {
			return err
		}
	}
	return nil
}

// QueryAudit pages events newest first; cursor = ts of the last row seen.
// Subjects that still exist are resolved to a name: secrets by name, folders
// by path, shares by the name of the shared secret (details.secret_id). Ids
// are only cast when they look like UUIDs: refused requests may carry
// arbitrary ids.
func QueryAudit(ctx context.Context, tx pgx.Tx, tenantID, eventType, actorID string, from, to, cursor time.Time, limit int) ([]AuditRow, error) {
	rows, err := tx.Query(ctx, `SELECT a.ts, a.tenant_id, a.event_type, a.actor_kind, a.actor_id, a.subject_kind, a.subject_id, a.outcome, a.reason, a.correlation_id, a.details,
		COALESCE(CASE
			WHEN a.subject_kind = 'share' AND (a.details->>'secret_id') ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
				THEN (SELECT s.name FROM secrets s WHERE s.tenant_id = a.tenant_id AND s.id = (a.details->>'secret_id')::uuid)
			WHEN a.subject_id !~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' THEN NULL
			WHEN a.subject_kind = 'secret' THEN (SELECT s.name FROM secrets s WHERE s.tenant_id = a.tenant_id AND s.id = a.subject_id::uuid)
			WHEN a.subject_kind = 'folder' THEN (SELECT f.path FROM folders f WHERE f.tenant_id = a.tenant_id AND f.id = a.subject_id::uuid) END, '')
		FROM warden_audit_events a WHERE a.tenant_id = $1 AND ($2 = '' OR a.event_type = $2) AND ($3 = '' OR a.actor_id = $3)
		AND a.ts >= $4 AND a.ts <= $5 AND ($6::timestamptz IS NULL OR a.ts < $6) ORDER BY a.ts DESC LIMIT $7`,
		tenantID, eventType, actorID, from, to, nullTime(cursor), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(&r.TS, &r.TenantID, &r.EventType, &r.ActorKind, &r.ActorID, &r.SubjectKind, &r.SubjectID, &r.Outcome, &r.Reason, &r.CorrelationID, &r.Details, &r.SubjectName); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// TenantStats computes the per-tenant counts.
func TenantStats(ctx context.Context, tx pgx.Tx, tenantID string, now time.Time) (Stats, error) {
	st := Stats{Grants: map[string]int64{}, Shares: map[string]int64{}}
	if err := tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM secrets WHERE tenant_id = $1 AND deleted_at IS NULL),
		(SELECT count(*) FROM secrets WHERE tenant_id = $1 AND deleted_at IS NULL AND has_totp),
		(SELECT count(*) FROM folders WHERE tenant_id = $1),
		(SELECT count(*) FROM secret_versions WHERE tenant_id = $1),
		(SELECT count(*) FROM warden_audit_events WHERE tenant_id = $1 AND ts >= $2)`, tenantID, now.Add(-24*time.Hour)).
		Scan(&st.Secrets, &st.SecretsWithTOTP, &st.Folders, &st.Versions, &st.Operations24h); err != nil {
		return st, err
	}
	rows, err := tx.Query(ctx, "SELECT relation, count(*) FROM grants WHERE tenant_id = $1 GROUP BY relation", tenantID)
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			return st, err
		}
		st.Grants[k] = n
	}
	rows.Close()
	rows, err = tx.Query(ctx, "SELECT state, count(*) FROM shares WHERE tenant_id = $1 GROUP BY state", tenantID)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return st, err
		}
		st.Shares[k] = n
	}
	return st, rows.Err()
}
