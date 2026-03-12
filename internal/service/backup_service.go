package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	entCrud "github.com/tx7do/go-crud/entgo"

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
	backupModule  = "warden"
	backupVersion = "1.0"
)

// BackupService exports and imports Warden data including DB metadata and
// optionally Vault passwords.
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

type backupData struct {
	Module     string         `json:"module"`
	Version    string         `json:"version"`
	ExportedAt time.Time      `json:"exportedAt"`
	TenantID   uint32         `json:"tenantId"`
	FullBackup bool           `json:"fullBackup"`
	Data       backupEntities `json:"data"`
}

type backupEntities struct {
	Folders         []json.RawMessage `json:"folders,omitempty"`
	Secrets         []json.RawMessage `json:"secrets,omitempty"`
	SecretVersions  []json.RawMessage `json:"secretVersions,omitempty"`
	Permissions     []json.RawMessage `json:"permissions,omitempty"`
	SecretPasswords map[string]string `json:"secretPasswords,omitempty"` // secretID -> password
}

func marshalEntities[T any](entities []*T) ([]json.RawMessage, error) {
	result := make([]json.RawMessage, 0, len(entities))
	for _, e := range entities {
		b, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		result = append(result, b)
	}
	return result, nil
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

	result := make([]T, 0, len(items))
	var walk func([]T)
	walk = func(nodes []T) {
		for _, n := range nodes {
			result = append(result, n)
			if children, ok := childMap[getID(n)]; ok {
				walk(children)
			}
		}
	}
	walk(roots)
	return result
}

func (s *BackupService) ExportBackup(ctx context.Context, req *wardenV1.ExportBackupRequest) (*wardenV1.ExportBackupResponse, error) {
	// Only platform admins can export backups
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
	now := time.Now()

	folders, err := s.exportFolders(ctx, client, tenantID, full)
	if err != nil {
		s.log.Errorf("export folders failed: %v", err)
		return nil, wardenV1.ErrorInternalServerError("export backup failed")
	}
	secrets, err := s.exportSecrets(ctx, client, tenantID, full)
	if err != nil {
		s.log.Errorf("export secrets failed: %v", err)
		return nil, wardenV1.ErrorInternalServerError("export backup failed")
	}
	secretVersions, err := s.exportSecretVersions(ctx, client, tenantID, full)
	if err != nil {
		s.log.Errorf("export secret versions failed: %v", err)
		return nil, wardenV1.ErrorInternalServerError("export backup failed")
	}
	permissions, err := s.exportPermissions(ctx, client, tenantID, full)
	if err != nil {
		s.log.Errorf("export permissions failed: %v", err)
		return nil, wardenV1.ErrorInternalServerError("export backup failed")
	}

	var secretPasswords map[string]string
	if req.GetIncludeSecrets() {
		secretPasswords, err = s.exportSecretPasswords(ctx, client, tenantID, full)
		if err != nil {
			s.log.Errorf("export secret passwords failed: %v", err)
			return nil, wardenV1.ErrorInternalServerError("export backup failed")
		}
	}

	backup := backupData{
		Module:     backupModule,
		Version:    backupVersion,
		ExportedAt: now,
		TenantID:   tenantID,
		FullBackup: full,
		Data: backupEntities{
			Folders:         folders,
			Secrets:         secrets,
			SecretVersions:  secretVersions,
			Permissions:     permissions,
			SecretPasswords: secretPasswords,
		},
	}

	data, err := json.Marshal(backup)
	if err != nil {
		s.log.Errorf("marshal backup failed: %v", err)
		return nil, wardenV1.ErrorInternalServerError("export backup failed")
	}

	entityCounts := map[string]int64{
		"folders":         int64(len(folders)),
		"secrets":         int64(len(secrets)),
		"secretVersions":  int64(len(secretVersions)),
		"permissions":     int64(len(permissions)),
		"secretPasswords": int64(len(secretPasswords)),
	}

	s.log.Infof("exported backup: module=%s tenant=%d full=%v entities=%v", backupModule, tenantID, full, entityCounts)

	return &wardenV1.ExportBackupResponse{
		Data:         data,
		Module:       backupModule,
		Version:      backupVersion,
		ExportedAt:   timestamppb.New(now),
		TenantId:     tenantID,
		EntityCounts: entityCounts,
	}, nil
}

func (s *BackupService) ImportBackup(ctx context.Context, req *wardenV1.ImportBackupRequest) (*wardenV1.ImportBackupResponse, error) {
	// Only platform admins can import backups
	if !grpcx.IsPlatformAdmin(ctx) {
		return nil, wardenV1.ErrorAccessDenied("only platform admins can import backups")
	}

	tenantID := grpcx.GetTenantIDFromContext(ctx)
	isPlatformAdmin := grpcx.IsPlatformAdmin(ctx)
	mode := req.GetMode()

	var backup backupData
	if err := json.Unmarshal(req.GetData(), &backup); err != nil {
		s.log.Errorf("unmarshal backup data failed: %v", err)
		return nil, wardenV1.ErrorInvalidFormat("invalid backup data format")
	}

	if backup.Module != backupModule {
		return nil, wardenV1.ErrorInvalidFormat("backup module mismatch: expected %s, got %s", backupModule, backup.Module)
	}
	if backup.Version != backupVersion {
		return nil, wardenV1.ErrorInvalidFormat("backup version mismatch: expected %s, got %s", backupVersion, backup.Version)
	}

	// For full backups, only platform admins can restore
	if backup.FullBackup && !isPlatformAdmin {
		return nil, wardenV1.ErrorAccessDenied("only platform admins can restore full backups")
	}

	// Non-platform admins always restore to their own tenant
	if !isPlatformAdmin || !backup.FullBackup {
		tenantID = grpcx.GetTenantIDFromContext(ctx)
	} else {
		tenantID = 0 // Signal for full backup restore -- each entity carries its own tenant_id
	}

	client := s.entClient.Client()
	var results []*wardenV1.EntityImportResult
	var warnings []string

	// Import in FK dependency order: folders -> secrets -> secretVersions -> permissions

	if len(backup.Data.Folders) > 0 {
		result, w := s.importFolders(ctx, client, backup.Data.Folders, tenantID, backup.FullBackup, mode)
		if result != nil {
			results = append(results, result)
		}
		warnings = append(warnings, w...)
	}

	if len(backup.Data.Secrets) > 0 {
		secretResults, w := s.importSecrets(ctx, client, backup.Data.Secrets, backup.Data.SecretPasswords, tenantID, backup.FullBackup, mode)
		results = append(results, secretResults...)
		warnings = append(warnings, w...)
	}

	if len(backup.Data.SecretVersions) > 0 {
		result, w := s.importSecretVersions(ctx, client, backup.Data.SecretVersions, tenantID, backup.FullBackup, mode)
		if result != nil {
			results = append(results, result)
		}
		warnings = append(warnings, w...)
	}

	if len(backup.Data.Permissions) > 0 {
		result, w := s.importPermissions(ctx, client, backup.Data.Permissions, tenantID, backup.FullBackup, mode)
		if result != nil {
			results = append(results, result)
		}
		warnings = append(warnings, w...)
	}

	s.log.Infof("imported backup: module=%s tenant=%d mode=%v results=%d warnings=%d", backupModule, tenantID, mode, len(results), len(warnings))

	return &wardenV1.ImportBackupResponse{
		Success:  true,
		Results:  results,
		Warnings: warnings,
	}, nil
}

// --- Export helpers ---

func (s *BackupService) exportFolders(ctx context.Context, client *ent.Client, tenantID uint32, full bool) ([]json.RawMessage, error) {
	query := client.Folder.Query()
	if !full {
		query = query.Where(folder.TenantID(tenantID))
	}
	entities, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	return marshalEntities(entities)
}

func (s *BackupService) exportSecrets(ctx context.Context, client *ent.Client, tenantID uint32, full bool) ([]json.RawMessage, error) {
	query := client.Secret.Query()
	if !full {
		query = query.Where(secret.TenantID(tenantID))
	}
	entities, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	return marshalEntities(entities)
}

func (s *BackupService) exportSecretVersions(ctx context.Context, client *ent.Client, tenantID uint32, full bool) ([]json.RawMessage, error) {
	query := client.SecretVersion.Query()
	if !full {
		// SecretVersion has no TenantID -- filter via parent Secret
		query = query.Where(secretversion.HasSecretWith(secret.TenantID(tenantID)))
	}
	entities, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	return marshalEntities(entities)
}

func (s *BackupService) exportPermissions(ctx context.Context, client *ent.Client, tenantID uint32, full bool) ([]json.RawMessage, error) {
	query := client.Permission.Query()
	if !full {
		query = query.Where(permission.TenantID(tenantID))
	}
	entities, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	return marshalEntities(entities)
}

func (s *BackupService) exportSecretPasswords(ctx context.Context, client *ent.Client, tenantID uint32, full bool) (map[string]string, error) {
	query := client.Secret.Query()
	if !full {
		query = query.Where(secret.TenantID(tenantID))
	}
	secrets, err := query.All(ctx)
	if err != nil {
		return nil, err
	}

	passwords := make(map[string]string, len(secrets))
	for _, sec := range secrets {
		pw, _, err := s.kvStore.GetPassword(ctx, sec.VaultPath)
		if err != nil {
			s.log.Warnf("failed to get password for secret %s: %v", sec.ID, err)
			continue
		}
		passwords[sec.ID] = pw
	}
	return passwords, nil
}

// --- Import helpers ---

func (s *BackupService) importFolders(ctx context.Context, client *ent.Client, items []json.RawMessage, tenantID uint32, full bool, mode wardenV1.RestoreMode) (*wardenV1.EntityImportResult, []string) {
	result := &wardenV1.EntityImportResult{EntityType: "folders", Total: int64(len(items))}
	var warnings []string

	var entities []*ent.Folder
	for _, raw := range items {
		var e ent.Folder
		if err := json.Unmarshal(raw, &e); err != nil {
			warnings = append(warnings, fmt.Sprintf("folders: unmarshal error: %v", err))
			result.Failed++
			continue
		}
		entities = append(entities, &e)
	}

	// Topological sort for self-referential parent_id
	sorted := topologicalSortByParentID(entities,
		func(e *ent.Folder) string { return e.ID },
		func(e *ent.Folder) string {
			if e.ParentID == nil {
				return ""
			}
			return *e.ParentID
		},
	)

	// Build a map of folder ID -> name for path recalculation
	folderNames := make(map[string]string, len(sorted))
	folderParents := make(map[string]*string, len(sorted))
	for _, e := range sorted {
		folderNames[e.ID] = e.Name
		folderParents[e.ID] = e.ParentID
	}

	// recalculatePath rebuilds the materialized path from the parent chain
	var recalculatePath func(id string, depth int) (string, int32)
	recalculatePath = func(id string, depth int) (string, int32) {
		if depth > 50 { // prevent infinite recursion from circular refs
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

		// Recalculate path and depth from parent hierarchy (never trust backup data)
		path, calculatedDepth := recalculatePath(e.ID, 0)

		existing, _ := client.Folder.Query().Where(folder.IDEQ(e.ID), folder.TenantIDEQ(tid)).Only(ctx)
		if existing != nil {
			if mode == wardenV1.RestoreMode_RESTORE_MODE_SKIP {
				result.Skipped++
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
				warnings = append(warnings, fmt.Sprintf("folders: update %s failed", e.ID))
				result.Failed++
				continue
			}
			result.Updated++
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
				warnings = append(warnings, fmt.Sprintf("folders: create %s failed", e.ID))
				result.Failed++
				continue
			}
			result.Created++
		}
	}

	return result, warnings
}

func (s *BackupService) importSecrets(ctx context.Context, client *ent.Client, items []json.RawMessage, secretPasswords map[string]string, tenantID uint32, full bool, mode wardenV1.RestoreMode) ([]*wardenV1.EntityImportResult, []string) {
	result := &wardenV1.EntityImportResult{EntityType: "secrets", Total: int64(len(items))}
	pwResult := &wardenV1.EntityImportResult{EntityType: "secretPasswords"}
	var warnings []string

	for _, raw := range items {
		var e ent.Secret
		if err := json.Unmarshal(raw, &e); err != nil {
			warnings = append(warnings, fmt.Sprintf("secrets: unmarshal error: %v", err))
			result.Failed++
			continue
		}

		tid := tenantID
		if full && e.TenantID != nil {
			tid = *e.TenantID
		}

		// Always regenerate VaultPath — never trust backup data
		vaultPath := s.kvStore.BuildPath(tid, e.ID)

		existing, _ := client.Secret.Query().Where(secret.IDEQ(e.ID), secret.TenantIDEQ(tid)).Only(ctx)
		if existing != nil {
			if mode == wardenV1.RestoreMode_RESTORE_MODE_SKIP {
				result.Skipped++
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
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("secrets: update %s failed", e.ID))
				result.Failed++
				continue
			}
			result.Updated++
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
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				SetNillableCreateTime(e.CreateTime).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("secrets: create %s failed", e.ID))
				result.Failed++
				continue
			}
			result.Created++
		}

		// Restore password to Vault using server-generated path
		if pw, ok := secretPasswords[e.ID]; ok && pw != "" {
			pwResult.Total++
			_, err := s.kvStore.StorePassword(ctx, vaultPath, pw, nil)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("secretPasswords: store %s failed", e.ID))
				pwResult.Failed++
			} else {
				pwResult.Created++
			}
		}
	}

	importResults := []*wardenV1.EntityImportResult{result}
	if pwResult.Total > 0 {
		importResults = append(importResults, pwResult)
	}
	return importResults, warnings
}

func (s *BackupService) importSecretVersions(ctx context.Context, client *ent.Client, items []json.RawMessage, tenantID uint32, full bool, mode wardenV1.RestoreMode) (*wardenV1.EntityImportResult, []string) {
	result := &wardenV1.EntityImportResult{EntityType: "secretVersions", Total: int64(len(items))}
	var warnings []string

	for _, raw := range items {
		var e ent.SecretVersion
		if err := json.Unmarshal(raw, &e); err != nil {
			warnings = append(warnings, fmt.Sprintf("secretVersions: unmarshal error: %v", err))
			result.Failed++
			continue
		}

		// Look up the parent secret to get the correct VaultPath (tenant-scoped)
		parentSecret, _ := client.Secret.Query().Where(secret.IDEQ(e.SecretID), secret.TenantIDEQ(tenantID)).Only(ctx)
		vaultPath := e.VaultPath
		if parentSecret != nil {
			vaultPath = parentSecret.VaultPath // use the DB's canonical path
		}

		existing, _ := client.SecretVersion.Query().Where(
			secretversion.IDEQ(e.ID),
			secretversion.HasSecretWith(secret.TenantIDEQ(tenantID)),
		).Only(ctx)
		if existing != nil {
			if mode == wardenV1.RestoreMode_RESTORE_MODE_SKIP {
				result.Skipped++
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
				warnings = append(warnings, fmt.Sprintf("secretVersions: update %d failed", e.ID))
				result.Failed++
				continue
			}
			result.Updated++
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
				warnings = append(warnings, fmt.Sprintf("secretVersions: create %d failed", e.ID))
				result.Failed++
				continue
			}
			result.Created++
		}
	}

	return result, warnings
}

func (s *BackupService) importPermissions(ctx context.Context, client *ent.Client, items []json.RawMessage, tenantID uint32, full bool, mode wardenV1.RestoreMode) (*wardenV1.EntityImportResult, []string) {
	result := &wardenV1.EntityImportResult{EntityType: "permissions", Total: int64(len(items))}
	var warnings []string

	for _, raw := range items {
		var e ent.Permission
		if err := json.Unmarshal(raw, &e); err != nil {
			warnings = append(warnings, fmt.Sprintf("permissions: unmarshal error: %v", err))
			result.Failed++
			continue
		}

		tid := tenantID
		if full && e.TenantID != nil {
			tid = *e.TenantID
		}

		existing, _ := client.Permission.Query().Where(permission.IDEQ(e.ID), permission.TenantIDEQ(tid)).Only(ctx)
		if existing != nil {
			if mode == wardenV1.RestoreMode_RESTORE_MODE_SKIP {
				result.Skipped++
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
				warnings = append(warnings, fmt.Sprintf("permissions: update %d failed", e.ID))
				result.Failed++
				continue
			}
			result.Updated++
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
				warnings = append(warnings, fmt.Sprintf("permissions: create %d failed", e.ID))
				result.Failed++
				continue
			}
			result.Created++
		}
	}

	return result, warnings
}
