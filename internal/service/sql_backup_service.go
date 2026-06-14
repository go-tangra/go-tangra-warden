package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-common/backup/sqldump"
	commonV1 "github.com/go-tangra/go-tangra-common/gen/go/common/service/v1"
	appViewer "github.com/go-tangra/go-tangra-common/viewer"

	"github.com/go-tangra/go-tangra-warden/internal/data/ent"
	"github.com/go-tangra/go-tangra-warden/internal/data/ent/migrate"
	"github.com/go-tangra/go-tangra-warden/pkg/vault"
)

// SqlBackupService implements the streaming common.service.v1.BackupService for
// Warden. The SQL dump captures all warden_* metadata; the actual secret
// material lives in Vault, so it is exported/imported as encrypted archive
// "extras" alongside the dump (only when include_secrets is set).
type SqlBackupService struct {
	commonV1.UnimplementedBackupServiceServer

	log       *log.Helper
	engine    *sqldump.Engine
	entClient *entCrud.EntClient[*ent.Client]
	kvStore   *vault.KVStore
}

func NewSqlBackupService(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client], kvStore *vault.KVStore) *SqlBackupService {
	dsn := ctx.GetConfig().Data.Database.GetSource()
	tables := make([]string, 0, len(migrate.Tables))
	for _, t := range migrate.Tables {
		tables = append(tables, t.Name)
	}
	return &SqlBackupService{
		log:       ctx.NewLoggerHelper("warden/service/sql-backup"),
		engine:    sqldump.New(dsn, sqldump.Options{Module: "warden", Tables: tables}),
		entClient: entClient,
		kvStore:   kvStore,
	}
}

const (
	extraSecretPasswords = "secretPasswords"
	extraTotpSecrets     = "totpSecrets"
)

// ExportBackup streams the SQL dump, with Vault secret material bundled as
// encrypted extras when include_secrets is requested.
func (s *SqlBackupService) ExportBackup(req *commonV1.ExportBackupRequest, stream commonV1.BackupService_ExportBackupServer) error {
	var extras map[string][]byte
	if req.GetIncludeSecrets() {
		extras = s.collectVaultSecrets(stream.Context())
	}
	w := &grpcExportWriter{stream: stream}
	if err := s.engine.Dump(stream.Context(), w, extras); err != nil {
		s.log.Errorf("export backup: %v", err)
		return err
	}
	return w.flush()
}

// collectVaultSecrets reads every secret's password (and TOTP) from Vault and
// returns them as JSON-encoded extras keyed by secret ID. Best-effort: a missing
// individual secret is logged and skipped, not fatal.
func (s *SqlBackupService) collectVaultSecrets(ctx context.Context) map[string][]byte {
	sctx := appViewer.NewSystemViewerContext(ctx)
	secrets, err := s.entClient.Client().Secret.Query().All(sctx)
	if err != nil {
		s.log.Errorf("collect vault secrets: list secrets: %v", err)
		return nil
	}
	passwords := make(map[string]string)
	totp := make(map[string]string)
	for _, sec := range secrets {
		if pw, _, err := s.kvStore.GetPassword(sctx, sec.VaultPath); err == nil {
			passwords[sec.ID] = pw
		} else {
			s.log.Warnf("vault password for %s: %v", sec.ID, err)
		}
		if sec.HasTotp {
			if url, err := s.kvStore.GetTotpURL(sctx, s.kvStore.BuildTotpPath(tenantOf(sec), sec.ID)); err == nil {
				totp[sec.ID] = url
			} else {
				s.log.Warnf("vault totp for %s: %v", sec.ID, err)
			}
		}
	}
	extras := make(map[string][]byte, 2)
	if len(passwords) > 0 {
		b, _ := json.Marshal(passwords)
		extras[extraSecretPasswords] = b
	}
	if len(totp) > 0 {
		b, _ := json.Marshal(totp)
		extras[extraTotpSecrets] = b
	}
	s.log.Infof("collected vault material: %d passwords, %d totp", len(passwords), len(totp))
	return extras
}

// ImportBackup restores the SQL dump, then writes the bundled secret material
// back into Vault using the restored secrets' vault paths.
func (s *SqlBackupService) ImportBackup(stream commonV1.BackupService_ImportBackupServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	opts := first.GetOptions()
	if opts == nil {
		return errors.New("warden: first ImportBackup message must carry options")
	}
	mode := sqldump.RestoreMerge
	if opts.GetMode() == commonV1.RestoreMode_RESTORE_MODE_FULL_SYNC {
		mode = sqldump.RestoreFullSync
	}

	res, extras, err := s.engine.Restore(stream.Context(), &grpcImportReader{stream: stream}, mode)
	if err != nil {
		s.log.Errorf("import backup: %v", err)
		return stream.SendAndClose(&commonV1.ImportBackupResponse{Success: false, Module: "warden", Warnings: []string{err.Error()}})
	}

	warnings := res.Warnings
	if len(extras) > 0 {
		warnings = append(warnings, s.restoreVaultSecrets(stream.Context(), extras)...)
	}

	out := &commonV1.ImportBackupResponse{Success: true, Module: "warden", Warnings: warnings}
	for _, t := range res.Tables {
		out.Tables = append(out.Tables, &commonV1.TableResult{Table: t.Table, Rows: t.Rows, Deleted: t.Deleted, Skipped: t.Skipped, Note: t.Note})
	}
	s.log.Infof("import backup done: %d tables, %d warnings", len(res.Tables), len(warnings))
	return stream.SendAndClose(out)
}

// restoreVaultSecrets writes secret passwords/TOTP back to Vault for the
// just-restored secrets, returning per-secret warnings.
func (s *SqlBackupService) restoreVaultSecrets(ctx context.Context, extras map[string][]byte) []string {
	var passwords, totp map[string]string
	if b, ok := extras[extraSecretPasswords]; ok {
		_ = json.Unmarshal(b, &passwords)
	}
	if b, ok := extras[extraTotpSecrets]; ok {
		_ = json.Unmarshal(b, &totp)
	}
	if len(passwords) == 0 && len(totp) == 0 {
		return nil
	}

	sctx := appViewer.NewSystemViewerContext(ctx)
	secrets, err := s.entClient.Client().Secret.Query().All(sctx)
	if err != nil {
		return []string{"vault restore: list secrets: " + err.Error()}
	}
	var warns []string
	for _, sec := range secrets {
		if pw, ok := passwords[sec.ID]; ok && pw != "" {
			if _, err := s.kvStore.StorePassword(sctx, sec.VaultPath, pw, nil); err != nil {
				warns = append(warns, "vault password "+sec.ID+": "+err.Error())
			}
		}
		if url, ok := totp[sec.ID]; ok && url != "" {
			if err := s.kvStore.StoreTotpURL(sctx, s.kvStore.BuildTotpPath(tenantOf(sec), sec.ID), url); err != nil {
				warns = append(warns, "vault totp "+sec.ID+": "+err.Error())
			}
		}
	}
	return warns
}

func tenantOf(sec *ent.Secret) uint32 {
	if sec.TenantID != nil {
		return *sec.TenantID
	}
	return 0
}

// --- gRPC stream <-> io adapters -------------------------------------------

// grpcExportWriter adapts the server stream to io.Writer, coalescing the
// engine's many small framed writes into ~256 KB gRPC messages. flush() must be
// called once at the end.
type grpcExportWriter struct {
	stream commonV1.BackupService_ExportBackupServer
	buf    []byte
}

const exportSendSize = 256 * 1024

func (w *grpcExportWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for len(w.buf) >= exportSendSize {
		if err := w.stream.Send(&commonV1.ExportBackupResponse{Content: w.buf[:exportSendSize]}); err != nil {
			return 0, err
		}
		w.buf = append([]byte(nil), w.buf[exportSendSize:]...)
	}
	return len(p), nil
}

func (w *grpcExportWriter) flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	if err := w.stream.Send(&commonV1.ExportBackupResponse{Content: w.buf}); err != nil {
		return err
	}
	w.buf = nil
	return nil
}

// grpcImportReader adapts the client stream's content chunks to io.Reader.
type grpcImportReader struct {
	stream commonV1.BackupService_ImportBackupServer
	buf    []byte
	done   bool
}

func (r *grpcImportReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.done {
			return 0, io.EOF
		}
		msg, err := r.stream.Recv()
		if err == io.EOF {
			r.done = true
			return 0, io.EOF
		}
		if err != nil {
			return 0, err
		}
		if c := msg.GetContent(); len(c) > 0 {
			r.buf = c
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}
