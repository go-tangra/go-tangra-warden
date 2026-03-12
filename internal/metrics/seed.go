package metrics

import (
	"context"

	"github.com/go-tangra/go-tangra-warden/internal/data"
)

// Seed loads initial gauge values from the database.
// Called once at startup so Prometheus has accurate values from the start.
func (c *Collector) Seed(ctx context.Context, statsRepo *data.StatisticsRepo) {
	c.log.Info("Seeding Prometheus metrics from database...")

	secretsByStatus, err := statsRepo.GetGlobalSecretCountByStatus(ctx)
	if err != nil {
		c.log.Errorf("Failed to seed secret stats: %v", err)
	} else {
		for status, count := range secretsByStatus {
			c.SecretsByStatus.WithLabelValues(status).Set(float64(count))
		}
	}

	folderCount, err := statsRepo.GetGlobalFolderCount(ctx)
	if err != nil {
		c.log.Errorf("Failed to seed folder stats: %v", err)
	} else {
		c.FoldersTotal.Set(float64(folderCount))
	}

	versionCount, err := statsRepo.GetGlobalVersionCount(ctx)
	if err != nil {
		c.log.Errorf("Failed to seed version stats: %v", err)
	} else {
		c.SecretVersionsTotal.Set(float64(versionCount))
	}

	c.log.Info("Prometheus metrics seeded successfully")
}
