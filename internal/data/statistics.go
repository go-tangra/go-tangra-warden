package data

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	entCrud "github.com/tx7do/go-crud/entgo"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

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
		return 0, err
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
		return 0, err
	}
	return int64(count), nil
}

// GetFolderCount returns the total number of folders for a tenant
func (r *StatisticsRepo) GetFolderCount(ctx context.Context, tenantID uint32) (int64, error) {
	count, err := r.entClient.Client().Folder.Query().
		Where(folder.TenantIDEQ(tenantID)).
		Count(ctx)
	if err != nil {
		return 0, err
	}
	return int64(count), nil
}

// GetVersionCount returns the total number of secret versions for a tenant
func (r *StatisticsRepo) GetVersionCount(ctx context.Context, tenantID uint32) (int64, error) {
	count, err := r.entClient.Client().SecretVersion.Query().
		Where(secretversion.HasSecretWith(secret.TenantIDEQ(tenantID))).
		Count(ctx)
	if err != nil {
		return 0, err
	}
	return int64(count), nil
}
