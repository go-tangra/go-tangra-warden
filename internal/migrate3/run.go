package migrate3

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/go-tangra/go-tangra-warden/v4/internal/transfer"
)

// DefaultTenant is the v4 platform tenant.
const DefaultTenant = "00000000-0000-0000-0000-000000000001"

// Importer is the v4 side (transfer.Service).
type Importer interface {
	ImportMigration(ctx context.Context, m transfer.Migration, v transfer.MigrationVault, o transfer.MigrationOptions) (transfer.MigrationReport, error)
}

// ImportConfig is the import-v3 command line.
type ImportConfig struct {
	In, KeyFile, UsersFile string
	TenantID               string
	RoleMap                string
	ActorEmail             string
	DryRun, AllowExisting  bool
}

// ImportResult is printed after an import or a dry run.
type ImportResult struct {
	Mapping MappingReport            `json:"mapping"`
	Import  transfer.MigrationReport `json:"import"`
}

// Failed reports whether the operator must look at the result.
func (r ImportResult) Failed() bool { return r.Import.Failed() }

// RunImport opens the bundle in memory, maps it and imports it.
func RunImport(ctx context.Context, cfg ImportConfig, imp Importer, v transfer.MigrationVault) (ImportResult, error) {
	var res ImportResult
	if cfg.In == "" || cfg.KeyFile == "" || cfg.UsersFile == "" || cfg.ActorEmail == "" {
		return res, errors.New("migrate3: -in, -key-file, -users and -actor-email are required")
	}
	roles, err := ParseRoleMap(cfg.RoleMap)
	if err != nil {
		return res, err
	}
	f, err := os.Open(cfg.UsersFile)
	if err != nil {
		return res, fmt.Errorf("migrate3: users file: %w", err)
	}
	users, err := ParseUsers(f)
	_ = f.Close()
	if err != nil {
		return res, err
	}
	b, err := ReadFiles(cfg.In, cfg.KeyFile)
	if err != nil {
		return res, err
	}
	defer scrub(b)
	m, mrep, err := Map(b, cfg.TenantID, users, roles, cfg.ActorEmail)
	res.Mapping = mrep
	if err != nil {
		return res, err
	}
	res.Import, err = imp.ImportMigration(ctx, m, v, transfer.MigrationOptions{DryRun: cfg.DryRun, AllowExisting: cfg.AllowExisting})
	for i := range m.Secrets {
		m.Secrets[i].TOTP = ""
		for j := range m.Secrets[i].Versions {
			m.Secrets[i].Versions[j].Password = ""
		}
	}
	return res, err
}
