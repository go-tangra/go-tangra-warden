package service

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-common/backup"
	"github.com/go-tangra/go-tangra-common/grpcx"

	wardenV1 "github.com/go-tangra/go-tangra-warden/gen/go/warden/service/v1"
	"github.com/go-tangra/go-tangra-warden/internal/data/ent"
	"github.com/go-tangra/go-tangra-warden/internal/data/ent/folder"
	"github.com/go-tangra/go-tangra-warden/internal/data/ent/permission"
	"github.com/go-tangra/go-tangra-warden/internal/data/ent/secret"
	"github.com/go-tangra/go-tangra-warden/internal/data/ent/secretversion"
	"github.com/go-tangra/go-tangra-warden/pkg/vault"
)

const (
	backupModule        = "warden"
	backupSchemaVersion = 2 // v2: added has_totp field to secrets
)

// Migration registry — bump backupSchemaVersion and add a migration here
// whenever the schema changes in a way that affects backup data.
var backupMigrations = func() *backup.MigrationRegistry {
	r := backup.NewMigrationRegistry(backupModule)
	// v1 → v2: added has_totp boolean field to secrets
	r.Register(1, func(entities map[string]json.RawMessage) error {
		return backup.MigrateAddField(entities, "secrets", "has_totp", false)
	})
	return r
}()

// BackupService exports and imports Warden data including DB entities and
// optionally Vault passwords and TOTP secrets.
type BackupService struct {
	wardenV1.UnimplementedBackupServiceServer

	log       *log.Helper
	entClient *entCrud.EntClient[*ent.Client]
	kvStore   *vault.KVStore
}

func NewBackupService(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client], kvStore *vault.KVStore) *BackupService {
	return &BackupService{
		log:       ctx.NewLoggerHelper("warden/service/backup"),
		entClient: entClient,
		kvStore:   kvStore,
	}
}

// ExportBackup exports all warden entities as a gzipped archive.
func (s *BackupService) ExportBackup(ctx context.Context, req *wardenV1.ExportBackupRequest) (*wardenV1.ExportBackupResponse, error) {
	if !grpcx.IsPlatformAdmin(ctx) {
		return nil, wardenV1.ErrorAccessDenied("only platform admins can export backups")
	}

	tenantID := grpcx.GetTenantIDFromContext(ctx)
	full := false

	if req.TenantId != nil && *req.TenantId == 0 {
		full = true
		tenantID = 0
	} else if req.TenantId != nil && *req.TenantId != 0 {
		tenantID = *req.TenantId
	}

	client := s.entClient.Client()
	a := backup.NewArchive(backupModule, backupSchemaVersion, tenantID, full)

	// Export folders
	folderQuery := client.Folder.Query()
	if !full {
		folderQuery = folderQuery.Where(folder.TenantID(tenantID))
	}
	folders, err := folderQuery.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("export folders: %w", err)
	}
	if err := backup.SetEntities(a, "folders", folders); err != nil {
		return nil, fmt.Errorf("set folders: %w", err)
	}

	// Export secrets
	secretQuery := client.Secret.Query()
	if !full {
		secretQuery = secretQuery.Where(secret.TenantID(tenantID))
	}
	secrets, err := secretQuery.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("export secrets: %w", err)
	}
	if err := backup.SetEntities(a, "secrets", secrets); err != nil {
		return nil, fmt.Errorf("set secrets: %w", err)
	}

	// Export secret versions
	versionQuery := client.SecretVersion.Query()
	if !full {
		versionQuery = versionQuery.Where(secretversion.HasSecretWith(secret.TenantID(tenantID)))
	}
	versions, err := versionQuery.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("export secret versions: %w", err)
	}
	if err := backup.SetEntities(a, "secretVersions", versions); err != nil {
		return nil, fmt.Errorf("set secret versions: %w", err)
	}

	// Export permissions
	permQuery := client.Permission.Query()
	if !full {
		permQuery = permQuery.Where(permission.TenantID(tenantID))
	}
	permissions, err := permQuery.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("export permissions: %w", err)
	}
	if err := backup.SetEntities(a, "permissions", permissions); err != nil {
		return nil, fmt.Errorf("set permissions: %w", err)
	}

	// Export passwords and TOTP from Vault (optional)
	if req.GetIncludeSecrets() {
		passwords := make(map[string]string, len(secrets))
		totpSecrets := make(map[string]string)

		for _, sec := range secrets {
			// Password
			pw, _, pwErr := s.kvStore.GetPassword(ctx, sec.VaultPath)
			if pwErr != nil {
				s.log.Warnf("failed to get password for secret %s: %v", sec.ID, pwErr)
			} else {
				passwords[sec.ID] = pw
			}

			// TOTP
			if sec.HasTotp {
				tid := tenantID
				if full && sec.TenantID != nil {
					tid = *sec.TenantID
				}
				totpPath := s.kvStore.BuildTotpPath(tid, sec.ID)
				totpURL, totpErr := s.kvStore.GetTotpURL(ctx, totpPath)
				if totpErr != nil {
					s.log.Warnf("failed to get TOTP for secret %s: %v", sec.ID, totpErr)
				} else {
					totpSecrets[sec.ID] = totpURL
				}
			}
		}

		if err := backup.SetExtra(a, "secretPasswords", passwords); err != nil {
			return nil, fmt.Errorf("set passwords: %w", err)
		}
		if len(totpSecrets) > 0 {
			if err := backup.SetExtra(a, "totpSecrets", totpSecrets); err != nil {
				return nil, fmt.Errorf("set TOTP secrets: %w", err)
			}
		}
	}

	// Pack (JSON + gzip)
	data, err := backup.Pack(a)
	if err != nil {
		return nil, fmt.Errorf("pack backup: %w", err)
	}

	s.log.Infof("exported backup: module=%s tenant=%d full=%v entities=%v", backupModule, tenantID, full, a.Manifest.EntityCounts)

	return &wardenV1.ExportBackupResponse{
		Data:          data,
		Module:        backupModule,
		Version:       fmt.Sprintf("%d", backupSchemaVersion),
		ExportedAt:    timestamppb.New(a.Manifest.ExportedAt),
		TenantId:      tenantID,
		EntityCounts:  a.Manifest.EntityCounts,
		SchemaVersion: int32(backupSchemaVersion),
	}, nil
}

// ImportBackup restores warden entities from a gzipped archive.
func (s *BackupService) ImportBackup(ctx context.Context, req *wardenV1.ImportBackupRequest) (*wardenV1.ImportBackupResponse, error) {
	if !grpcx.IsPlatformAdmin(ctx) {
		return nil, wardenV1.ErrorAccessDenied("only platform admins can import backups")
	}

	tenantID := grpcx.GetTenantIDFromContext(ctx)
	mode := mapRestoreMode(req.GetMode())

	// Unpack
	a, err := backup.Unpack(req.GetData())
	if err != nil {
		return nil, fmt.Errorf("unpack backup: %w", err)
	}

	// Validate
	if err := backup.Validate(a, backupModule, backupSchemaVersion); err != nil {
		return nil, err
	}

	// Full backups require platform admin
	if a.Manifest.FullBackup && !grpcx.IsPlatformAdmin(ctx) {
		return nil, wardenV1.ErrorAccessDenied("only platform admins can restore full backups")
	}

	// Run migrations
	sourceVersion := a.Manifest.SchemaVersion
	applied, err := backupMigrations.RunMigrations(a, backupSchemaVersion)
	if err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	if a.Manifest.FullBackup {
		tenantID = 0
	}

	client := s.entClient.Client()
	result := backup.NewRestoreResult(sourceVersion, backupSchemaVersion, applied)

	// Load extras
	secretPasswords, _ := backup.GetExtra[map[string]string](a, "secretPasswords")
	totpSecrets, _ := backup.GetExtra[map[string]string](a, "totpSecrets")

	// Import in FK dependency order
	s.importFolders(ctx, client, a, tenantID, a.Manifest.FullBackup, mode, result)
	s.importSecrets(ctx, client, a, secretPasswords, totpSecrets, tenantID, a.Manifest.FullBackup, mode, result)
	s.importSecretVersions(ctx, client, a, tenantID, a.Manifest.FullBackup, mode, result)
	s.importPermissions(ctx, client, a, tenantID, a.Manifest.FullBackup, mode, result)

	s.log.Infof("imported backup: module=%s tenant=%d migrations=%d results=%d",
		backupModule, tenantID, applied, len(result.Results))

	// Convert to proto
	protoResults := make([]*wardenV1.EntityImportResult, len(result.Results))
	for i, r := range result.Results {
		protoResults[i] = &wardenV1.EntityImportResult{
			EntityType: r.EntityType,
			Total:      r.Total,
			Created:    r.Created,
			Updated:    r.Updated,
			Skipped:    r.Skipped,
			Failed:     r.Failed,
		}
	}

	return &wardenV1.ImportBackupResponse{
		Success:           result.Success,
		Results:           protoResults,
		Warnings:          result.Warnings,
		SourceVersion:     int32(result.SourceVersion),
		TargetVersion:     int32(result.TargetVersion),
		MigrationsApplied: int32(result.MigrationsApplied),
	}, nil
}

func mapRestoreMode(m wardenV1.RestoreMode) backup.RestoreMode {
	if m == wardenV1.RestoreMode_RESTORE_MODE_OVERWRITE {
		return backup.RestoreModeOverwrite
	}
	return backup.RestoreModeSkip
}

// topologicalSortByParentID sorts items so parents come before children.
func topologicalSortByParentID[T any](items []T, getID func(T) string, getParentID func(T) string) []T {
	idSet := make(map[string]bool, len(items))
	for _, item := range items {
		idSet[getID(item)] = true
	}

	childMap := make(map[string][]T)
	var roots []T
	for _, item := range items {
		pid := getParentID(item)
		if pid == "" || !idSet[pid] {
			roots = append(roots, item)
		} else {
			childMap[pid] = append(childMap[pid], item)
		}
	}

	sorted := make([]T, 0, len(items))
	var walk func([]T)
	walk = func(nodes []T) {
		for _, n := range nodes {
			sorted = append(sorted, n)
			if children, ok := childMap[getID(n)]; ok {
				walk(children)
			}
		}
	}
	walk(roots)
	return sorted
}

// --- Import helpers ---

func (s *BackupService) importFolders(ctx context.Context, client *ent.Client, a *backup.Archive, tenantID uint32, full bool, mode backup.RestoreMode, result *backup.RestoreResult) {
	folders, err := backup.GetEntities[ent.Folder](a, "folders")
	if err != nil {
		result.AddWarning(fmt.Sprintf("folders: unmarshal error: %v", err))
		return
	}
	if len(folders) == 0 {
		return
	}

	er := backup.EntityResult{EntityType: "folders", Total: int64(len(folders))}

	sorted := topologicalSortByParentID(folders,
		func(e ent.Folder) string { return e.ID },
		func(e ent.Folder) string {
			if e.ParentID == nil {
				return ""
			}
			return *e.ParentID
		},
	)

	// Build maps for path recalculation
	folderNames := make(map[string]string, len(sorted))
	folderParents := make(map[string]*string, len(sorted))
	for _, e := range sorted {
		folderNames[e.ID] = e.Name
		folderParents[e.ID] = e.ParentID
	}

	var recalculatePath func(id string, depth int) (string, int32)
	recalculatePath = func(id string, depth int) (string, int32) {
		if depth > 50 {
			return "/" + folderNames[id], int32(depth)
		}
		parentID := folderParents[id]
		if parentID == nil || *parentID == "" {
			return "/" + folderNames[id], 0
		}
		parentPath, parentDepth := recalculatePath(*parentID, depth+1)
		return parentPath + "/" + folderNames[id], parentDepth + 1
	}

	for _, e := range sorted {
		tid := tenantID
		if full && e.TenantID != nil {
			tid = *e.TenantID
		}

		path, calculatedDepth := recalculatePath(e.ID, 0)

		existing, getErr := client.Folder.Query().Where(folder.IDEQ(e.ID), folder.TenantIDEQ(tid)).Only(ctx)
		if getErr != nil && !ent.IsNotFound(getErr) {
			result.AddWarning(fmt.Sprintf("folders: lookup %s: %v", e.ID, getErr))
			er.Failed++
			continue
		}

		if existing != nil {
			if mode == backup.RestoreModeSkip {
				er.Skipped++
				continue
			}
			_, err := client.Folder.UpdateOneID(e.ID).
				SetNillableParentID(e.ParentID).
				SetName(e.Name).
				SetPath(path).
				SetDescription(e.Description).
				SetDepth(calculatedDepth).
				SetNillableCreateBy(e.CreateBy).
				Save(ctx)
			if err != nil {
				result.AddWarning(fmt.Sprintf("folders: update %s: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Updated++
		} else {
			_, err := client.Folder.Create().
				SetID(e.ID).
				SetNillableTenantID(&tid).
				SetNillableParentID(e.ParentID).
				SetName(e.Name).
				SetPath(path).
				SetDescription(e.Description).
				SetDepth(calculatedDepth).
				SetNillableCreateBy(e.CreateBy).
				SetNillableCreateTime(e.CreateTime).
				Save(ctx)
			if err != nil {
				result.AddWarning(fmt.Sprintf("folders: create %s: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Created++
		}
	}

	result.AddResult(er)
}

func (s *BackupService) importSecrets(ctx context.Context, client *ent.Client, a *backup.Archive, secretPasswords, totpSecrets map[string]string, tenantID uint32, full bool, mode backup.RestoreMode, result *backup.RestoreResult) {
	secrets, err := backup.GetEntities[ent.Secret](a, "secrets")
	if err != nil {
		result.AddWarning(fmt.Sprintf("secrets: unmarshal error: %v", err))
		return
	}
	if len(secrets) == 0 {
		return
	}

	er := backup.EntityResult{EntityType: "secrets", Total: int64(len(secrets))}
	pwResult := backup.EntityResult{EntityType: "secretPasswords"}
	totpResult := backup.EntityResult{EntityType: "totpSecrets"}

	for _, e := range secrets {
		tid := tenantID
		if full && e.TenantID != nil {
			tid = *e.TenantID
		}

		vaultPath := s.kvStore.BuildPath(tid, e.ID)

		existing, getErr := client.Secret.Query().Where(secret.IDEQ(e.ID), secret.TenantIDEQ(tid)).Only(ctx)
		if getErr != nil && !ent.IsNotFound(getErr) {
			result.AddWarning(fmt.Sprintf("secrets: lookup %s: %v", e.ID, getErr))
			er.Failed++
			continue
		}

		if existing != nil {
			if mode == backup.RestoreModeSkip {
				er.Skipped++
				continue
			}
			_, err := client.Secret.UpdateOneID(e.ID).
				SetNillableFolderID(e.FolderID).
				SetName(e.Name).
				SetUsername(e.Username).
				SetHostURL(e.HostURL).
				SetVaultPath(vaultPath).
				SetCurrentVersion(e.CurrentVersion).
				SetMetadata(e.Metadata).
				SetDescription(e.Description).
				SetStatus(e.Status).
				SetHasTotp(e.HasTotp).
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				Save(ctx)
			if err != nil {
				result.AddWarning(fmt.Sprintf("secrets: update %s: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Updated++
		} else {
			_, err := client.Secret.Create().
				SetID(e.ID).
				SetNillableTenantID(&tid).
				SetNillableFolderID(e.FolderID).
				SetName(e.Name).
				SetUsername(e.Username).
				SetHostURL(e.HostURL).
				SetVaultPath(vaultPath).
				SetCurrentVersion(e.CurrentVersion).
				SetMetadata(e.Metadata).
				SetDescription(e.Description).
				SetStatus(e.Status).
				SetHasTotp(e.HasTotp).
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				SetNillableCreateTime(e.CreateTime).
				Save(ctx)
			if err != nil {
				result.AddWarning(fmt.Sprintf("secrets: create %s: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Created++
		}

		// Restore password to Vault
		if pw, ok := secretPasswords[e.ID]; ok && pw != "" {
			pwResult.Total++
			if _, pwErr := s.kvStore.StorePassword(ctx, vaultPath, pw, nil); pwErr != nil {
				result.AddWarning(fmt.Sprintf("secretPasswords: store %s: %v", e.ID, pwErr))
				pwResult.Failed++
			} else {
				pwResult.Created++
			}
		}

		// Restore TOTP to Vault
		if totpURL, ok := totpSecrets[e.ID]; ok && totpURL != "" {
			totpResult.Total++
			totpPath := s.kvStore.BuildTotpPath(tid, e.ID)
			if totpErr := s.kvStore.StoreTotpURL(ctx, totpPath, totpURL); totpErr != nil {
				result.AddWarning(fmt.Sprintf("totpSecrets: store %s: %v", e.ID, totpErr))
				totpResult.Failed++
			} else {
				totpResult.Created++
			}
		}
	}

	result.AddResult(er)
	if pwResult.Total > 0 {
		result.AddResult(pwResult)
	}
	if totpResult.Total > 0 {
		result.AddResult(totpResult)
	}
}

func (s *BackupService) importSecretVersions(ctx context.Context, client *ent.Client, a *backup.Archive, tenantID uint32, full bool, mode backup.RestoreMode, result *backup.RestoreResult) {
	versions, err := backup.GetEntities[ent.SecretVersion](a, "secretVersions")
	if err != nil {
		result.AddWarning(fmt.Sprintf("secretVersions: unmarshal error: %v", err))
		return
	}
	if len(versions) == 0 {
		return
	}

	er := backup.EntityResult{EntityType: "secretVersions", Total: int64(len(versions))}

	for _, e := range versions {
		// Look up parent secret for canonical VaultPath
		parentSecret, _ := client.Secret.Query().Where(secret.IDEQ(e.SecretID)).Only(ctx)
		vaultPath := e.VaultPath
		if parentSecret != nil {
			vaultPath = parentSecret.VaultPath
		}

		existing, getErr := client.SecretVersion.Query().Where(
			secretversion.IDEQ(e.ID),
		).Only(ctx)
		if getErr != nil && !ent.IsNotFound(getErr) {
			result.AddWarning(fmt.Sprintf("secretVersions: lookup %d: %v", e.ID, getErr))
			er.Failed++
			continue
		}

		if existing != nil {
			if mode == backup.RestoreModeSkip {
				er.Skipped++
				continue
			}
			_, err := client.SecretVersion.UpdateOneID(e.ID).
				SetSecretID(e.SecretID).
				SetVersionNumber(e.VersionNumber).
				SetVaultPath(vaultPath).
				SetComment(e.Comment).
				SetChecksum(e.Checksum).
				SetNillableCreateBy(e.CreateBy).
				Save(ctx)
			if err != nil {
				result.AddWarning(fmt.Sprintf("secretVersions: update %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Updated++
		} else {
			_, err := client.SecretVersion.Create().
				SetSecretID(e.SecretID).
				SetVersionNumber(e.VersionNumber).
				SetVaultPath(vaultPath).
				SetComment(e.Comment).
				SetChecksum(e.Checksum).
				SetNillableCreateBy(e.CreateBy).
				SetNillableCreateTime(e.CreateTime).
				Save(ctx)
			if err != nil {
				result.AddWarning(fmt.Sprintf("secretVersions: create %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Created++
		}
	}

	result.AddResult(er)
}

func (s *BackupService) importPermissions(ctx context.Context, client *ent.Client, a *backup.Archive, tenantID uint32, full bool, mode backup.RestoreMode, result *backup.RestoreResult) {
	permissions, err := backup.GetEntities[ent.Permission](a, "permissions")
	if err != nil {
		result.AddWarning(fmt.Sprintf("permissions: unmarshal error: %v", err))
		return
	}
	if len(permissions) == 0 {
		return
	}

	er := backup.EntityResult{EntityType: "permissions", Total: int64(len(permissions))}

	for _, e := range permissions {
		tid := tenantID
		if full && e.TenantID != nil {
			tid = *e.TenantID
		}

		existing, getErr := client.Permission.Query().Where(permission.IDEQ(e.ID), permission.TenantIDEQ(tid)).Only(ctx)
		if getErr != nil && !ent.IsNotFound(getErr) {
			result.AddWarning(fmt.Sprintf("permissions: lookup %d: %v", e.ID, getErr))
			er.Failed++
			continue
		}

		if existing != nil {
			if mode == backup.RestoreModeSkip {
				er.Skipped++
				continue
			}
			_, err := client.Permission.UpdateOneID(e.ID).
				SetResourceType(e.ResourceType).
				SetResourceID(e.ResourceID).
				SetRelation(e.Relation).
				SetSubjectType(e.SubjectType).
				SetSubjectID(e.SubjectID).
				SetNillableGrantedBy(e.GrantedBy).
				SetNillableExpiresAt(e.ExpiresAt).
				Save(ctx)
			if err != nil {
				result.AddWarning(fmt.Sprintf("permissions: update %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Updated++
		} else {
			_, err := client.Permission.Create().
				SetNillableTenantID(&tid).
				SetResourceType(e.ResourceType).
				SetResourceID(e.ResourceID).
				SetRelation(e.Relation).
				SetSubjectType(e.SubjectType).
				SetSubjectID(e.SubjectID).
				SetNillableGrantedBy(e.GrantedBy).
				SetNillableExpiresAt(e.ExpiresAt).
				SetNillableCreateTime(e.CreateTime).
				Save(ctx)
			if err != nil {
				result.AddWarning(fmt.Sprintf("permissions: create %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Created++
		}
	}

	result.AddResult(er)
}
