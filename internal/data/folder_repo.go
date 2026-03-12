package data

import (
	"context"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-warden/internal/data/ent"
	"github.com/go-tangra/go-tangra-warden/internal/data/ent/folder"
	"github.com/go-tangra/go-tangra-warden/internal/data/ent/secret"

	wardenV1 "github.com/go-tangra/go-tangra-warden/gen/go/warden/service/v1"
)

// derefUint32 safely dereferences a uint32 pointer, returning 0 if nil
func derefUint32(p *uint32) uint32 {
	if p == nil {
		return 0
	}
	return *p
}

type FolderRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewFolderRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *FolderRepo {
	return &FolderRepo{
		log:       ctx.NewLoggerHelper("folder/repo"),
		entClient: entClient,
	}
}

// Create creates a new folder
func (r *FolderRepo) Create(ctx context.Context, tenantID uint32, parentID *string, name, description string, createdBy *uint32) (*ent.Folder, error) {
	id := uuid.New().String()

	// Build path and calculate depth
	path := "/" + name
	depth := int32(0)

	if parentID != nil && *parentID != "" {
		parent, err := r.GetByIDAndTenant(ctx, tenantID, *parentID)
		if err != nil {
			return nil, err
		}
		if parent == nil {
			return nil, wardenV1.ErrorFolderNotFound("parent folder not found")
		}
		path = parent.Path + "/" + name
		depth = parent.Depth + 1
	}

	builder := r.entClient.Client().Folder.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetName(name).
		SetPath(path).
		SetDepth(depth).
		SetCreateTime(time.Now())

	if parentID != nil && *parentID != "" {
		builder.SetParentID(*parentID)
	}
	if description != "" {
		builder.SetDescription(description)
	}
	if createdBy != nil {
		builder.SetCreateBy(*createdBy)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, wardenV1.ErrorFolderAlreadyExists("folder already exists")
		}
		r.log.Errorf("create folder failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("create folder failed")
	}

	return entity, nil
}

// GetByID retrieves a folder by ID
func (r *FolderRepo) GetByID(ctx context.Context, id string) (*ent.Folder, error) {
	entity, err := r.entClient.Client().Folder.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get folder failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("get folder failed")
	}
	return entity, nil
}

// GetByIDAndTenant retrieves a folder by ID with tenant isolation enforced.
// Use this in service-layer calls where tenant context is available.
func (r *FolderRepo) GetByIDAndTenant(ctx context.Context, tenantID uint32, id string) (*ent.Folder, error) {
	entity, err := r.entClient.Client().Folder.Query().
		Where(folder.IDEQ(id), folder.TenantIDEQ(tenantID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get folder failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("get folder failed")
	}
	return entity, nil
}

// GetByTenantAndPath retrieves a folder by tenant ID and path
func (r *FolderRepo) GetByTenantAndPath(ctx context.Context, tenantID uint32, path string) (*ent.Folder, error) {
	entity, err := r.entClient.Client().Folder.Query().
		Where(
			folder.TenantIDEQ(tenantID),
			folder.PathEQ(path),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get folder by path failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("get folder failed")
	}
	return entity, nil
}

// List lists folders with optional parent filter
func (r *FolderRepo) List(ctx context.Context, tenantID uint32, parentID *string, nameFilter *string, page, pageSize uint32) ([]*ent.Folder, int, error) {
	query := r.entClient.Client().Folder.Query().
		Where(folder.TenantIDEQ(tenantID))

	if parentID != nil {
		if *parentID == "" {
			// Root-level folders (no parent)
			query = query.Where(folder.ParentIDIsNil())
		} else {
			query = query.Where(folder.ParentIDEQ(*parentID))
		}
	}

	if nameFilter != nil && *nameFilter != "" {
		query = query.Where(folder.NameContains(*nameFilter))
	}

	// Count total
	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count folders failed: %s", err.Error())
		return nil, 0, wardenV1.ErrorInternalServerError("count folders failed")
	}

	// Apply pagination
	if page > 0 && pageSize > 0 {
		offset := int((page - 1) * pageSize)
		query = query.Offset(offset).Limit(int(pageSize))
	}

	entities, err := query.Order(ent.Asc(folder.FieldName)).All(ctx)
	if err != nil {
		r.log.Errorf("list folders failed: %s", err.Error())
		return nil, 0, wardenV1.ErrorInternalServerError("list folders failed")
	}

	return entities, total, nil
}

// ListByParentID lists child folders
func (r *FolderRepo) ListByParentID(ctx context.Context, tenantID uint32, parentID string) ([]*ent.Folder, error) {
	entities, err := r.entClient.Client().Folder.Query().
		Where(
			folder.TenantIDEQ(tenantID),
			folder.ParentIDEQ(parentID),
		).
		Order(ent.Asc(folder.FieldName)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list child folders failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("list child folders failed")
	}
	return entities, nil
}

// Update updates a folder (tenant-scoped). When name changes, path and descendant
// paths are updated within a transaction for atomicity.
func (r *FolderRepo) Update(ctx context.Context, tenantID uint32, id string, name, description *string) (*ent.Folder, error) {
	// Fetch with tenant filter to determine if name is changing
	f, err := r.entClient.Client().Folder.Query().
		Where(folder.IDEQ(id), folder.TenantIDEQ(tenantID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, wardenV1.ErrorFolderNotFound("folder not found")
		}
		r.log.Errorf("get folder for update failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("update folder failed")
	}

	nameChanged := name != nil && *name != f.Name

	// When name changes, use a transaction so folder + descendant path updates are atomic
	if nameChanged {
		return r.updateWithRename(ctx, tenantID, f, *name, description)
	}

	// Simple update (no path changes needed)
	builder := f.Update().SetUpdateTime(time.Now())
	if name != nil {
		builder.SetName(*name)
	}
	if description != nil {
		builder.SetDescription(*description)
	}

	entity, saveErr := builder.Save(ctx)
	if saveErr != nil {
		if ent.IsConstraintError(saveErr) {
			return nil, wardenV1.ErrorFolderAlreadyExists("folder with this name already exists")
		}
		r.log.Errorf("update folder failed: %s", saveErr.Error())
		return nil, wardenV1.ErrorInternalServerError("update folder failed")
	}
	return entity, nil
}

// updateWithRename handles folder rename within a transaction to keep paths consistent.
func (r *FolderRepo) updateWithRename(ctx context.Context, tenantID uint32, f *ent.Folder, newName string, description *string) (*ent.Folder, error) {
	tx, err := r.entClient.Client().Tx(ctx)
	if err != nil {
		r.log.Errorf("begin transaction failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("update folder failed")
	}

	oldPath := f.Path
	parentPath := oldPath[:strings.LastIndex(oldPath, "/")]
	newPath := parentPath + "/" + newName

	builder := tx.Folder.UpdateOneID(f.ID).
		SetUpdateTime(time.Now()).
		SetName(newName).
		SetPath(newPath)
	if description != nil {
		builder.SetDescription(*description)
	}

	entity, saveErr := builder.Save(ctx)
	if saveErr != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			r.log.Errorf("rollback failed: %s", rbErr.Error())
		}
		if ent.IsConstraintError(saveErr) {
			return nil, wardenV1.ErrorFolderAlreadyExists("folder with this name already exists")
		}
		r.log.Errorf("update folder failed: %s", saveErr.Error())
		return nil, wardenV1.ErrorInternalServerError("update folder failed")
	}

	// Update descendant paths within the same transaction
	descendants, descErr := tx.Folder.Query().
		Where(folder.TenantIDEQ(tenantID), folder.PathHasPrefix(oldPath+"/")).
		All(ctx)
	if descErr != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			r.log.Errorf("rollback failed: %s", rbErr.Error())
		}
		r.log.Errorf("query descendant folders for path update failed: %s", descErr.Error())
		return nil, wardenV1.ErrorInternalServerError("update folder failed")
	}
	for _, d := range descendants {
		descNewPath := strings.Replace(d.Path, oldPath, newPath, 1)
		if _, dErr := tx.Folder.UpdateOneID(d.ID).SetPath(descNewPath).SetUpdateTime(time.Now()).Save(ctx); dErr != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.log.Errorf("rollback failed: %s", rbErr.Error())
			}
			r.log.Errorf("update descendant path failed: %s", dErr.Error())
			return nil, wardenV1.ErrorInternalServerError("update folder failed")
		}
	}

	if err := tx.Commit(); err != nil {
		r.log.Errorf("commit folder update failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("update folder failed")
	}

	return entity, nil
}

// Move moves a folder to a new parent (tenant-scoped).
// Uses a database transaction to prevent race conditions with concurrent moves
// that could create circular references.
func (r *FolderRepo) Move(ctx context.Context, tenantID uint32, id string, newParentID *string) (*ent.Folder, error) {
	tx, err := r.entClient.Client().Tx(ctx)
	if err != nil {
		r.log.Errorf("begin transaction failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("move folder failed")
	}

	// Get the folder within the transaction with a lock (tenant-scoped)
	f, err := tx.Folder.Query().Where(folder.IDEQ(id), folder.TenantIDEQ(tenantID)).ForUpdate().Only(ctx)
	if err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			r.log.Errorf("rollback failed: %s", rbErr.Error())
		}
		if ent.IsNotFound(err) {
			return nil, wardenV1.ErrorFolderNotFound("folder not found")
		}
		r.log.Errorf("get folder for move failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("move folder failed")
	}

	// Calculate new path and depth
	newPath := "/" + f.Name
	newDepth := int32(0)

	if newParentID != nil && *newParentID != "" {
		// Check for circular reference
		if *newParentID == id {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.log.Errorf("rollback failed: %s", rbErr.Error())
			}
			return nil, wardenV1.ErrorCircularFolderReference("cannot move folder to itself")
		}

		// Lock the parent too (tenant-scoped), to prevent concurrent moves from creating cycles
		parent, err := tx.Folder.Query().Where(folder.IDEQ(*newParentID), folder.TenantIDEQ(tenantID)).ForUpdate().Only(ctx)
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.log.Errorf("rollback failed: %s", rbErr.Error())
			}
			if ent.IsNotFound(err) {
				return nil, wardenV1.ErrorFolderNotFound("new parent folder not found")
			}
			r.log.Errorf("get parent folder failed: %s", err.Error())
			return nil, wardenV1.ErrorInternalServerError("move folder failed")
		}

		// Check if new parent is a descendant of the folder being moved
		if strings.HasPrefix(parent.Path, f.Path+"/") {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.log.Errorf("rollback failed: %s", rbErr.Error())
			}
			return nil, wardenV1.ErrorCircularFolderReference("cannot move folder to its own descendant")
		}

		newPath = parent.Path + "/" + f.Name
		newDepth = parent.Depth + 1
	}

	// Update folder
	builder := tx.Folder.UpdateOneID(id).
		SetPath(newPath).
		SetDepth(newDepth).
		SetUpdateTime(time.Now())

	if newParentID != nil && *newParentID != "" {
		builder.SetParentID(*newParentID)
	} else {
		builder.ClearParentID()
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			r.log.Errorf("rollback failed: %s", rbErr.Error())
		}
		if ent.IsConstraintError(err) {
			return nil, wardenV1.ErrorFolderAlreadyExists("folder with this name already exists in the destination")
		}
		r.log.Errorf("move folder failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("move folder failed")
	}

	// Update paths of all descendant folders within the same transaction (tenant-scoped)
	descendants, descErr := tx.Folder.Query().
		Where(folder.TenantIDEQ(tenantID), folder.PathHasPrefix(f.Path+"/")).
		All(ctx)
	if descErr != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			r.log.Errorf("rollback failed: %s", rbErr.Error())
		}
		r.log.Errorf("query descendant folders failed: %s", descErr.Error())
		return nil, wardenV1.ErrorInternalServerError("move folder failed")
	}
	for _, d := range descendants {
		descNewPath := strings.Replace(d.Path, f.Path, newPath, 1)
		if _, descErr := tx.Folder.UpdateOneID(d.ID).SetPath(descNewPath).SetUpdateTime(time.Now()).Save(ctx); descErr != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.log.Errorf("rollback failed: %s", rbErr.Error())
			}
			r.log.Errorf("update descendant path failed: %s", descErr.Error())
			return nil, wardenV1.ErrorInternalServerError("move folder failed")
		}
	}

	if err := tx.Commit(); err != nil {
		r.log.Errorf("commit folder move failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("move folder failed")
	}

	return entity, nil
}


// Delete deletes a folder (tenant-scoped)
func (r *FolderRepo) Delete(ctx context.Context, tenantID uint32, id string, force bool) error {
	// Check if folder has children (tenant-scoped)
	childCount, err := r.entClient.Client().Folder.Query().
		Where(folder.ParentIDEQ(id), folder.TenantIDEQ(tenantID)).
		Count(ctx)
	if err != nil {
		r.log.Errorf("count child folders failed: %s", err.Error())
		return wardenV1.ErrorInternalServerError("delete folder failed")
	}
	if childCount > 0 && !force {
		return wardenV1.ErrorFolderNotEmpty("folder has child folders")
	}

	// Check if folder has active secrets (tenant-scoped)
	secretCount, err := r.entClient.Client().Secret.Query().
		Where(
			secret.FolderIDEQ(id),
			secret.TenantIDEQ(tenantID),
			secret.StatusNEQ(secret.StatusSECRET_STATUS_DELETED),
		).
		Count(ctx)
	if err != nil {
		r.log.Errorf("count secrets failed: %s", err.Error())
		return wardenV1.ErrorInternalServerError("delete folder failed")
	}
	if secretCount > 0 && !force {
		return wardenV1.ErrorFolderNotEmpty("folder contains secrets")
	}

	if force {
		// Use a transaction to ensure atomicity of the cascade delete
		tx, txErr := r.entClient.Client().Tx(ctx)
		if txErr != nil {
			r.log.Errorf("begin transaction failed: %s", txErr.Error())
			return wardenV1.ErrorInternalServerError("delete folder failed")
		}

		f, err := tx.Folder.Query().
			Where(folder.IDEQ(id), folder.TenantIDEQ(tenantID)).
			Only(ctx)
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.log.Errorf("rollback failed: %s", rbErr.Error())
			}
			if ent.IsNotFound(err) {
				return wardenV1.ErrorFolderNotFound("folder not found")
			}
			r.log.Errorf("get folder for delete failed: %s", err.Error())
			return wardenV1.ErrorInternalServerError("delete folder failed")
		}

		// Delete all secrets in the folder tree (tenant-scoped)
		_, secretErr := tx.Secret.Delete().
			Where(secret.TenantIDEQ(tenantID), secret.Or(
				secret.FolderIDEQ(id),
				secret.HasFolderWith(folder.PathHasPrefix(f.Path+"/")),
			)).
			Exec(ctx)
		if secretErr != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.log.Errorf("rollback failed: %s", rbErr.Error())
			}
			r.log.Errorf("delete secrets in folder tree failed: %s", secretErr.Error())
			return wardenV1.ErrorInternalServerError("delete folder failed")
		}

		// Delete all descendant folders (tenant-scoped)
		_, descErr := tx.Folder.Delete().
			Where(folder.TenantIDEQ(tenantID), folder.PathHasPrefix(f.Path+"/")).
			Exec(ctx)
		if descErr != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.log.Errorf("rollback failed: %s", rbErr.Error())
			}
			r.log.Errorf("delete descendant folders failed: %s", descErr.Error())
			return wardenV1.ErrorInternalServerError("delete folder failed")
		}

		// Delete the folder itself
		_, delErr := tx.Folder.Delete().
			Where(folder.IDEQ(id), folder.TenantIDEQ(tenantID)).
			Exec(ctx)
		if delErr != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.log.Errorf("rollback failed: %s", rbErr.Error())
			}
			r.log.Errorf("delete folder failed: %s", delErr.Error())
			return wardenV1.ErrorInternalServerError("delete folder failed")
		}

		if err := tx.Commit(); err != nil {
			r.log.Errorf("commit folder delete failed: %s", err.Error())
			return wardenV1.ErrorInternalServerError("delete folder failed")
		}
		return nil
	}

	// Non-force: simple delete of the folder itself (tenant-scoped)
	delCount, err := r.entClient.Client().Folder.Delete().
		Where(folder.IDEQ(id), folder.TenantIDEQ(tenantID)).
		Exec(ctx)
	if err != nil {
		r.log.Errorf("delete folder failed: %s", err.Error())
		return wardenV1.ErrorInternalServerError("delete folder failed")
	}
	if delCount == 0 {
		return wardenV1.ErrorFolderNotFound("folder not found")
	}
	return nil
}

// CountSecrets counts secrets in a folder
func (r *FolderRepo) CountSecrets(ctx context.Context, tenantID uint32, folderID string) (int, error) {
	count, err := r.entClient.Client().Secret.Query().
		Where(secret.FolderIDEQ(folderID), secret.TenantIDEQ(tenantID)).
		Count(ctx)
	if err != nil {
		r.log.Errorf("count secrets failed: %s", err.Error())
		return 0, wardenV1.ErrorInternalServerError("count secrets failed")
	}
	return count, nil
}

// CountSubfolders counts subfolders in a folder
func (r *FolderRepo) CountSubfolders(ctx context.Context, tenantID uint32, folderID string) (int, error) {
	count, err := r.entClient.Client().Folder.Query().
		Where(folder.ParentIDEQ(folderID), folder.TenantIDEQ(tenantID)).
		Count(ctx)
	if err != nil {
		r.log.Errorf("count subfolders failed: %s", err.Error())
		return 0, wardenV1.ErrorInternalServerError("count subfolders failed")
	}
	return count, nil
}

// ListDescendantIDs returns all descendant folder IDs for a folder (excluding itself)
func (r *FolderRepo) ListDescendantIDs(ctx context.Context, tenantID uint32, folderID string) ([]string, error) {
	f, err := r.GetByIDAndTenant(ctx, tenantID, folderID)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, nil
	}

	descendants, err := r.entClient.Client().Folder.Query().
		Where(folder.TenantIDEQ(tenantID), folder.PathHasPrefix(f.Path+"/")).
		Select(folder.FieldID).
		All(ctx)
	if err != nil {
		r.log.Errorf("list descendant folder IDs failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("list descendant folders failed")
	}

	ids := make([]string, len(descendants))
	for i, d := range descendants {
		ids[i] = d.ID
	}
	return ids, nil
}

// GetParentID returns the parent folder ID (implements ResourceLookup interface)
func (r *FolderRepo) GetFolderParentID(ctx context.Context, tenantID uint32, folderID string) (*string, error) {
	f, err := r.GetByIDAndTenant(ctx, tenantID, folderID)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, nil
	}
	return f.ParentID, nil
}

// ToProto converts an ent.Folder to wardenV1.Folder
func (r *FolderRepo) ToProto(entity *ent.Folder) *wardenV1.Folder {
	if entity == nil {
		return nil
	}

	proto := &wardenV1.Folder{
		Id:          entity.ID,
		TenantId:    derefUint32(entity.TenantID),
		Name:        entity.Name,
		Path:        entity.Path,
		Description: entity.Description,
		Depth:       entity.Depth,
	}

	if entity.ParentID != nil {
		proto.ParentId = entity.ParentID
	}
	if entity.CreateBy != nil {
		proto.CreatedBy = entity.CreateBy
	}
	if entity.CreateTime != nil && !entity.CreateTime.IsZero() {
		proto.CreateTime = timestamppb.New(*entity.CreateTime)
	}
	if entity.UpdateTime != nil && !entity.UpdateTime.IsZero() {
		proto.UpdateTime = timestamppb.New(*entity.UpdateTime)
	}

	return proto
}

// ToProtoWithCounts converts an ent.Folder to wardenV1.Folder with counts
func (r *FolderRepo) ToProtoWithCounts(ctx context.Context, tenantID uint32, entity *ent.Folder) (*wardenV1.Folder, error) {
	proto := r.ToProto(entity)
	if proto == nil {
		return nil, nil
	}

	secretCount, err := r.CountSecrets(ctx, tenantID, entity.ID)
	if err != nil {
		return nil, err
	}
	proto.SecretCount = int32(secretCount)

	subfolderCount, err := r.CountSubfolders(ctx, tenantID, entity.ID)
	if err != nil {
		return nil, err
	}
	proto.SubfolderCount = int32(subfolderCount)

	return proto, nil
}

// BuildTree builds a folder tree starting from root folders or a specific folder
func (r *FolderRepo) BuildTree(ctx context.Context, tenantID uint32, rootID *string, maxDepth int32, includeCounts bool) ([]*wardenV1.FolderTreeNode, error) {
	var roots []*ent.Folder
	var err error

	if rootID != nil && *rootID != "" {
		root, err := r.GetByIDAndTenant(ctx, tenantID, *rootID)
		if err != nil {
			return nil, err
		}
		if root == nil {
			return nil, wardenV1.ErrorFolderNotFound("root folder not found")
		}
		roots = []*ent.Folder{root}
	} else {
		roots, err = r.entClient.Client().Folder.Query().
			Where(
				folder.TenantIDEQ(tenantID),
				folder.ParentIDIsNil(),
			).
			Order(ent.Asc(folder.FieldName)).
			All(ctx)
		if err != nil {
			r.log.Errorf("get root folders failed: %s", err.Error())
			return nil, wardenV1.ErrorInternalServerError("get folder tree failed")
		}
	}

	nodes := make([]*wardenV1.FolderTreeNode, 0, len(roots))
	for _, root := range roots {
		node, err := r.buildTreeNode(ctx, root, 0, maxDepth, includeCounts)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}

	return nodes, nil
}

func (r *FolderRepo) buildTreeNode(ctx context.Context, f *ent.Folder, currentDepth, maxDepth int32, includeCounts bool) (*wardenV1.FolderTreeNode, error) {
	var folderProto *wardenV1.Folder
	var err error

	if includeCounts {
		folderProto, err = r.ToProtoWithCounts(ctx, *f.TenantID, f)
		if err != nil {
			return nil, err
		}
	} else {
		folderProto = r.ToProto(f)
	}

	node := &wardenV1.FolderTreeNode{
		Folder:   folderProto,
		Children: make([]*wardenV1.FolderTreeNode, 0),
	}

	// Check if we should continue building the tree
	if maxDepth > 0 && currentDepth >= maxDepth {
		return node, nil
	}

	// Get children
	children, err := r.ListByParentID(ctx, *f.TenantID, f.ID)
	if err != nil {
		return nil, err
	}

	for _, child := range children {
		childNode, err := r.buildTreeNode(ctx, child, currentDepth+1, maxDepth, includeCounts)
		if err != nil {
			return nil, err
		}
		node.Children = append(node.Children, childNode)
	}

	return node, nil
}

// GetAllDescendantIDs returns all descendant folder IDs
func (r *FolderRepo) GetAllDescendantIDs(ctx context.Context, tenantID uint32, folderID string) ([]string, error) {
	f, err := r.GetByIDAndTenant(ctx, tenantID, folderID)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, nil
	}

	descendants, err := r.entClient.Client().Folder.Query().
		Where(
			folder.TenantIDEQ(tenantID),
			folder.PathHasPrefix(f.Path+"/"),
		).
		Select(folder.FieldID).
		All(ctx)
	if err != nil {
		r.log.Errorf("get descendant folders failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("get descendant folders failed")
	}

	ids := make([]string, 0, len(descendants))
	for _, d := range descendants {
		ids = append(ids, d.ID)
	}

	return ids, nil
}

