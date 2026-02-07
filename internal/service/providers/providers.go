package providers

import (
	"context"
	"strings"

	"github.com/go-kratos/kratos/v2/metadata"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-warden/internal/authz"
	"github.com/go-tangra/go-tangra-warden/internal/data"
)

// ProvideResourceLookup creates a ResourceLookup from repositories
func ProvideResourceLookup(folderRepo *data.FolderRepo, secretRepo *data.SecretRepo) authz.ResourceLookup {
	return &resourceLookupImpl{
		folderRepo: folderRepo,
		secretRepo: secretRepo,
	}
}

// ProvidePermissionStore creates a PermissionStore from the permission repo
func ProvidePermissionStore(permRepo *data.PermissionRepo) authz.PermissionStore {
	return permRepo
}

// ProvideAuthzEngine creates the authorization engine
func ProvideAuthzEngine(store authz.PermissionStore, lookup authz.ResourceLookup, ctx *bootstrap.Context) *authz.Engine {
	return authz.NewEngine(store, lookup, ctx.GetLogger())
}

// ProvideAuthzChecker creates the authorization checker
func ProvideAuthzChecker(engine *authz.Engine) *authz.Checker {
	return authz.NewChecker(engine)
}

// resourceLookupImpl implements authz.ResourceLookup
type resourceLookupImpl struct {
	folderRepo *data.FolderRepo
	secretRepo *data.SecretRepo
}

func (r *resourceLookupImpl) GetFolderParentID(ctx context.Context, tenantID uint32, folderID string) (*string, error) {
	return r.folderRepo.GetFolderParentID(ctx, tenantID, folderID)
}

func (r *resourceLookupImpl) GetSecretFolderID(ctx context.Context, tenantID uint32, secretID string) (*string, error) {
	return r.secretRepo.GetSecretFolderID(ctx, tenantID, secretID)
}

func (r *resourceLookupImpl) GetUserRoleIDs(ctx context.Context, tenantID uint32, userID string) ([]string, error) {
	// Extract roles from gRPC metadata (x-roles header sent by transcoder)
	md, ok := metadata.FromServerContext(ctx)
	if !ok {
		return nil, nil
	}

	rolesStr := md.Get("x-md-global-roles")
	if rolesStr == "" {
		return nil, nil
	}

	// Split comma-separated roles
	var roles []string
	for _, role := range strings.Split(rolesStr, ",") {
		role = strings.TrimSpace(role)
		if role != "" {
			roles = append(roles, role)
		}
	}

	return roles, nil
}
