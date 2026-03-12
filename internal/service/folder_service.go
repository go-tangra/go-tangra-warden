package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/go-tangra/go-tangra-warden/internal/authz"
	"github.com/go-tangra/go-tangra-warden/internal/data"
	"github.com/go-tangra/go-tangra-warden/internal/metrics"
	"github.com/go-tangra/go-tangra-warden/pkg/vault"

	wardenV1 "github.com/go-tangra/go-tangra-warden/gen/go/warden/service/v1"
)

type FolderService struct {
	wardenV1.UnimplementedWardenFolderServiceServer

	log         *log.Helper
	folderRepo  *data.FolderRepo
	secretRepo  *data.SecretRepo
	versionRepo *data.SecretVersionRepo
	permRepo    *data.PermissionRepo
	kvStore     *vault.KVStore
	checker     *authz.Checker
	metrics     *metrics.Collector
}

func NewFolderService(
	ctx *bootstrap.Context,
	folderRepo *data.FolderRepo,
	secretRepo *data.SecretRepo,
	versionRepo *data.SecretVersionRepo,
	permRepo *data.PermissionRepo,
	kvStore *vault.KVStore,
	checker *authz.Checker,
	metrics *metrics.Collector,
) *FolderService {
	return &FolderService{
		log:         ctx.NewLoggerHelper("warden/service/folder"),
		folderRepo:  folderRepo,
		secretRepo:  secretRepo,
		versionRepo: versionRepo,
		permRepo:    permRepo,
		kvStore:     kvStore,
		checker:     checker,
		metrics:     metrics,
	}
}

// CreateFolder creates a new folder
func (s *FolderService) CreateFolder(ctx context.Context, req *wardenV1.CreateFolderRequest) (*wardenV1.CreateFolderResponse, error) {
	// Get tenant and user from context
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission on parent folder (if specified)
	if req.ParentId != nil && *req.ParentId != "" {
		if err := s.checker.CanWriteFolder(ctx, tenantID, userID, *req.ParentId); err != nil {
			return nil, wardenV1.ErrorAccessDenied("no permission to create folder in this location")
		}
	}

	// Create folder
	createdBy := getUserIDAsUint32(ctx)
	folder, err := s.folderRepo.Create(ctx, tenantID, req.ParentId, req.Name, req.Description, createdBy)
	if err != nil {
		return nil, err
	}

	// Grant owner permission to creator
	if createdBy != nil {
		_, err = s.permRepo.Create(ctx, tenantID, string(authz.ResourceTypeFolder), folder.ID, string(authz.RelationOwner), string(authz.SubjectTypeUser), userID, createdBy, nil)
		if err != nil {
			s.log.Warnf("failed to grant owner permission: %v", err)
		}
	}

	s.metrics.FolderCreated()

	s.log.Infof("Folder created: id=%s parent=%v user=%s", folder.ID, req.ParentId, userID)

	return &wardenV1.CreateFolderResponse{
		Folder: s.folderRepo.ToProto(folder),
	}, nil
}

// GetFolder gets a folder by ID
func (s *FolderService) GetFolder(ctx context.Context, req *wardenV1.GetFolderRequest) (*wardenV1.GetFolderResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission
	if err := s.checker.CanReadFolder(ctx, tenantID, userID, req.Id); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to access this folder")
	}

	folder, err := s.folderRepo.GetByIDAndTenant(ctx, tenantID, req.Id)
	if err != nil {
		return nil, err
	}
	if folder == nil {
		return nil, wardenV1.ErrorFolderNotFound("folder not found")
	}

	var folderProto *wardenV1.Folder
	if req.IncludeCounts {
		folderProto, err = s.folderRepo.ToProtoWithCounts(ctx, tenantID, folder)
		if err != nil {
			return nil, err
		}
	} else {
		folderProto = s.folderRepo.ToProto(folder)
	}

	return &wardenV1.GetFolderResponse{
		Folder: folderProto,
	}, nil
}

// ListFolders lists folders
func (s *FolderService) ListFolders(ctx context.Context, req *wardenV1.ListFoldersRequest) (*wardenV1.ListFoldersResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// If parent is specified, check permission on parent
	if req.ParentId != nil && *req.ParentId != "" {
		if err := s.checker.CanReadFolder(ctx, tenantID, userID, *req.ParentId); err != nil {
			return nil, wardenV1.ErrorAccessDenied("no permission to access this folder")
		}
	}

	page := uint32(1)
	if req.Page != nil {
		page = *req.Page
	}
	pageSize := uint32(20)
	if req.PageSize != nil {
		pageSize = *req.PageSize
	}

	folders, _, err := s.folderRepo.List(ctx, tenantID, req.ParentId, req.NameFilter, page, pageSize)
	if err != nil {
		return nil, err
	}

	// Filter folders by permission
	accessibleFolders := make([]*wardenV1.Folder, 0, len(folders))
	for _, folder := range folders {
		if err := s.checker.CanReadFolder(ctx, tenantID, userID, folder.ID); err == nil {
			accessibleFolders = append(accessibleFolders, s.folderRepo.ToProto(folder))
		}
	}

	return &wardenV1.ListFoldersResponse{
		Folders: accessibleFolders,
		Total:   uint32(len(accessibleFolders)),
	}, nil
}

// UpdateFolder updates folder metadata
func (s *FolderService) UpdateFolder(ctx context.Context, req *wardenV1.UpdateFolderRequest) (*wardenV1.UpdateFolderResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission
	if err := s.checker.CanWriteFolder(ctx, tenantID, userID, req.Id); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to modify this folder")
	}

	folder, err := s.folderRepo.Update(ctx, tenantID, req.Id, req.Name, req.Description)
	if err != nil {
		return nil, err
	}

	s.log.Infof("Folder updated: id=%s user=%s", req.Id, userID)

	return &wardenV1.UpdateFolderResponse{
		Folder: s.folderRepo.ToProto(folder),
	}, nil
}

// DeleteFolder deletes a folder
func (s *FolderService) DeleteFolder(ctx context.Context, req *wardenV1.DeleteFolderRequest) (*emptypb.Empty, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission
	if err := s.checker.CanDeleteFolder(ctx, tenantID, userID, req.Id); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to delete this folder")
	}

	// When force-deleting, clean up Vault data, permissions, and version records
	// for all secrets and descendant folders before the repo cascade-deletes DB records.
	if req.Force {
		secrets, err := s.secretRepo.ListAllInFolderTree(ctx, tenantID, req.Id)
		if err != nil {
			s.log.Warnf("Failed to list secrets for cleanup in folder %s: %v", req.Id, err)
		} else {
			for _, sec := range secrets {
				// Q3: Clean up permissions for each secret
				if err := s.permRepo.DeleteByResource(ctx, tenantID, string(authz.ResourceTypeSecret), sec.ID); err != nil {
					s.log.Warnf("Failed to delete permissions for secret %s: %v", sec.ID, err)
				}
				// Q5: Clean up SecretVersion records
				if err := s.versionRepo.DeleteBySecretID(ctx, sec.ID); err != nil {
					s.log.Warnf("Failed to delete versions for secret %s: %v", sec.ID, err)
				}
				// Vault cleanup
				if err := s.kvStore.DestroyAllVersions(ctx, sec.VaultPath); err != nil {
					s.log.Warnf("Failed to destroy Vault data for secret %s during folder delete: %v", sec.ID, err)
				}
			}
		}

		// Q4: Clean up permissions for descendant folders
		descendantFolders, err := s.folderRepo.ListDescendantIDs(ctx, tenantID, req.Id)
		if err != nil {
			s.log.Warnf("Failed to list descendant folders for permission cleanup in folder %s: %v", req.Id, err)
		} else {
			for _, folderID := range descendantFolders {
				if err := s.permRepo.DeleteByResource(ctx, tenantID, string(authz.ResourceTypeFolder), folderID); err != nil {
					s.log.Warnf("Failed to delete permissions for descendant folder %s: %v", folderID, err)
				}
			}
		}
	}

	if err := s.folderRepo.Delete(ctx, tenantID, req.Id, req.Force); err != nil {
		return nil, err
	}

	// Delete permissions for the root folder itself
	if err := s.permRepo.DeleteByResource(ctx, tenantID, string(authz.ResourceTypeFolder), req.Id); err != nil {
		s.log.Warnf("Failed to delete permissions for folder %s: %v", req.Id, err)
	}

	s.metrics.FolderDeleted()

	s.log.Infof("Folder deleted: id=%s force=%v user=%s", req.Id, req.Force, userID)

	return &emptypb.Empty{}, nil
}

// MoveFolder moves a folder to a new parent
func (s *FolderService) MoveFolder(ctx context.Context, req *wardenV1.MoveFolderRequest) (*wardenV1.MoveFolderResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission on source folder
	if err := s.checker.CanWriteFolder(ctx, tenantID, userID, req.Id); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to move this folder")
	}

	// Check permission on destination folder (if specified)
	if req.NewParentId != nil && *req.NewParentId != "" {
		if err := s.checker.CanWriteFolder(ctx, tenantID, userID, *req.NewParentId); err != nil {
			return nil, wardenV1.ErrorAccessDenied("no permission to move folder to this location")
		}
	}

	folder, err := s.folderRepo.Move(ctx, tenantID, req.Id, req.NewParentId)
	if err != nil {
		return nil, err
	}

	s.log.Infof("Folder moved: id=%s newParent=%v user=%s", req.Id, req.NewParentId, userID)

	return &wardenV1.MoveFolderResponse{
		Folder: s.folderRepo.ToProto(folder),
	}, nil
}

// GetFolderTree gets the folder tree structure
func (s *FolderService) GetFolderTree(ctx context.Context, req *wardenV1.GetFolderTreeRequest) (*wardenV1.GetFolderTreeResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission on root folder (if specified)
	if req.RootId != nil && *req.RootId != "" {
		if err := s.checker.CanReadFolder(ctx, tenantID, userID, *req.RootId); err != nil {
			return nil, wardenV1.ErrorAccessDenied("no permission to access this folder")
		}
	}

	maxDepth := int32(10)
	if req.MaxDepth != nil {
		maxDepth = *req.MaxDepth
	}

	roots, err := s.folderRepo.BuildTree(ctx, tenantID, req.RootId, maxDepth, req.IncludeCounts)
	if err != nil {
		return nil, err
	}

	// Get folder IDs directly accessible by this user (via user, role, or tenant permissions)
	accessibleIDs, err := s.checker.ListAccessibleFolders(ctx, tenantID, userID)
	if err != nil {
		s.log.Warnf("failed to list accessible folders: %v", err)
		accessibleIDs = []string{}
	}

	accessibleSet := make(map[string]bool, len(accessibleIDs))
	for _, id := range accessibleIDs {
		accessibleSet[id] = true
	}

	// Prune tree: only show folders the user can access.
	// Zanzibar hierarchy means children of accessible folders are also accessible.
	// Structural parent nodes are kept (with hidden secret counts) when needed
	// to show the path to accessible descendants.
	roots = pruneTreeByAccess(roots, accessibleSet, false)

	return &wardenV1.GetFolderTreeResponse{
		Roots: roots,
	}, nil
}

// pruneTreeByAccess filters the folder tree to only show accessible folders.
// A folder is accessible if it has a direct permission tuple OR its parent is accessible
// (Zanzibar hierarchy: parent folder access implies child folder access).
// Folders with no access are kept as structural nodes only if they have accessible
// descendants, with their secret counts hidden.
func pruneTreeByAccess(nodes []*wardenV1.FolderTreeNode, accessibleIDs map[string]bool, parentAccessible bool) []*wardenV1.FolderTreeNode {
	result := make([]*wardenV1.FolderTreeNode, 0, len(nodes))
	for _, node := range nodes {
		isDirectlyAccessible := accessibleIDs[node.Folder.Id]
		isAccessible := isDirectlyAccessible || parentAccessible

		// Recursively prune children, inheriting accessibility
		node.Children = pruneTreeByAccess(node.Children, accessibleIDs, isAccessible)

		// Keep node if accessible or needed as structural path to accessible descendants
		if isAccessible || len(node.Children) > 0 {
			// Update subfolder count to reflect only visible children
			node.Folder.SubfolderCount = int32(len(node.Children))

			// Hide secret count for structural-only nodes (not accessible, just a path node)
			if !isAccessible {
				node.Folder.SecretCount = 0
			}

			result = append(result, node)
		}
	}
	return result
}

// Helper functions are now in context_helper.go
