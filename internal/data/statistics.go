package data

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	entCrud "github.com/tx7do/go-crud/entgo"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	wardenV1 "github.com/go-tangra/go-tangra-warden/gen/go/warden/service/v1"
	"github.com/go-tangra/go-tangra-warden/internal/data/ent"
	"github.com/go-tangra/go-tangra-warden/internal/data/ent/folder"
	"github.com/go-tangra/go-tangra-warden/internal/data/ent/secret"
	"github.com/go-tangra/go-tangra-warden/internal/data/ent/secretversion"
)

// StatisticsRepo provides methods for collecting Warden statistics
type StatisticsRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

// NewStatisticsRepo creates a new StatisticsRepo
func NewStatisticsRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *StatisticsRepo {
	return &StatisticsRepo{
		entClient: entClient,
		log:       ctx.NewLoggerHelper("warden/statistics/repo"),
	}
}

// GetSecretCount returns the total number of secrets for a tenant
func (r *StatisticsRepo) GetSecretCount(ctx context.Context, tenantID uint32) (int64, error) {
	count, err := r.entClient.Client().Secret.Query().
		Where(secret.TenantIDEQ(tenantID)).
		Count(ctx)
	if err != nil {
		r.log.Errorf("get secret count failed: %s", err.Error())
		return 0, wardenV1.ErrorInternalServerError("get statistics failed")
	}
	return int64(count), nil
}

// GetSecretCountByStatus returns the count of secrets with the given status for a tenant
func (r *StatisticsRepo) GetSecretCountByStatus(ctx context.Context, tenantID uint32, status secret.Status) (int64, error) {
	count, err := r.entClient.Client().Secret.Query().
		Where(
			secret.TenantIDEQ(tenantID),
			secret.StatusEQ(status),
		).
		Count(ctx)
	if err != nil {
		r.log.Errorf("get secret count by status failed: %s", err.Error())
		return 0, wardenV1.ErrorInternalServerError("get statistics failed")
	}
	return int64(count), nil
}

// GetFolderCount returns the total number of folders for a tenant
func (r *StatisticsRepo) GetFolderCount(ctx context.Context, tenantID uint32) (int64, error) {
	count, err := r.entClient.Client().Folder.Query().
		Where(folder.TenantIDEQ(tenantID)).
		Count(ctx)
	if err != nil {
		r.log.Errorf("get folder count failed: %s", err.Error())
		return 0, wardenV1.ErrorInternalServerError("get statistics failed")
	}
	return int64(count), nil
}

// GetVersionCount returns the total number of secret versions for a tenant
func (r *StatisticsRepo) GetVersionCount(ctx context.Context, tenantID uint32) (int64, error) {
	count, err := r.entClient.Client().SecretVersion.Query().
		Where(secretversion.HasSecretWith(secret.TenantIDEQ(tenantID))).
		Count(ctx)
	if err != nil {
		r.log.Errorf("get version count failed: %s", err.Error())
		return 0, wardenV1.ErrorInternalServerError("get statistics failed")
	}
	return int64(count), nil
}

// GetGlobalSecretCountByStatus returns the count of secrets grouped by status across all tenants.
func (r *StatisticsRepo) GetGlobalSecretCountByStatus(ctx context.Context) (map[string]int64, error) {
	result := make(map[string]int64)
	statuses := []secret.Status{
		secret.StatusSECRET_STATUS_UNSPECIFIED,
		secret.StatusSECRET_STATUS_ACTIVE,
		secret.StatusSECRET_STATUS_ARCHIVED,
		secret.StatusSECRET_STATUS_DELETED,
	}
	for _, status := range statuses {
		count, err := r.entClient.Client().Secret.Query().
			Where(secret.StatusEQ(status)).
			Count(ctx)
		if err != nil {
			r.log.Errorf("get global secret count by status failed: %s", err.Error())
			return nil, wardenV1.ErrorInternalServerError("get statistics failed")
		}
		if count > 0 {
			result[string(status)] = int64(count)
		}
	}
	return result, nil
}

// GetGlobalFolderCount returns the total number of folders across all tenants.
func (r *StatisticsRepo) GetGlobalFolderCount(ctx context.Context) (int64, error) {
	count, err := r.entClient.Client().Folder.Query().Count(ctx)
	if err != nil {
		r.log.Errorf("get global folder count failed: %s", err.Error())
		return 0, wardenV1.ErrorInternalServerError("get statistics failed")
	}
	return int64(count), nil
}

// GetGlobalVersionCount returns the total number of secret versions across all tenants.
func (r *StatisticsRepo) GetGlobalVersionCount(ctx context.Context) (int64, error) {
	count, err := r.entClient.Client().SecretVersion.Query().Count(ctx)
	if err != nil {
		r.log.Errorf("get global version count failed: %s", err.Error())
		return 0, wardenV1.ErrorInternalServerError("get statistics failed")
	}
	return int64(count), nil
}
