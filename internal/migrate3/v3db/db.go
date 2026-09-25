// Package v3db reads a warden v3 deployment for the export: the portal's
// Postgres (warden_* tables, sys_users, sys_roles) in one read-only
// repeatable-read transaction, and the v3 Vault (KV v2, AppRole). Covered by
// the tagged integration suite against real Postgres and Vault containers.
package v3db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-warden/v4/internal/migrate3"
)

// PG is a read-only snapshot of one v3 tenant.
type PG struct {
	conn   *pgx.Conn
	tx     pgx.Tx
	tenant uint32
}

// Open connects and starts a READ ONLY, REPEATABLE READ transaction so every
// read of the export sees one consistent snapshot and nothing can be written.
func Open(ctx context.Context, dsn string, tenant uint32) (*PG, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" || strings.Contains(dsn, "${") {
		return nil, errors.New("v3db: the DSN is empty or still contains ${...} placeholders")
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("v3db: connect: %w", redact(err, dsn))
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly, IsoLevel: pgx.RepeatableRead})
	if err != nil {
		_ = conn.Close(ctx)
		return nil, fmt.Errorf("v3db: begin: %w", err)
	}
	return &PG{conn: conn, tx: tx, tenant: tenant}, nil
}

// redact keeps the DSN (it carries the password) out of error messages.
func redact(err error, dsn string) error {
	msg := err.Error()
	if dsn != "" {
		msg = strings.ReplaceAll(msg, dsn, "[dsn]")
	}
	return errors.New(msg)
}

// Close ends the snapshot (rollback: nothing was written) and disconnects.
func (p *PG) Close(ctx context.Context) {
	_ = p.tx.Rollback(ctx)
	_ = p.conn.Close(ctx)
}

// Folders lists the live folders.
func (p *PG) Folders(ctx context.Context) ([]migrate3.SrcFolder, error) {
	rows, err := p.tx.Query(ctx, `SELECT id, parent_id, name, coalesce(path, ''), coalesce(description, ''), create_by, create_time, update_time
		FROM warden_folders WHERE coalesce(tenant_id, 0) = $1 AND delete_time IS NULL ORDER BY coalesce(depth, 0), path, id`, p.tenant)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (migrate3.SrcFolder, error) {
		var f migrate3.SrcFolder
		var by *int64
		err := r.Scan(&f.ID, &f.ParentID, &f.Name, &f.Path, &f.Description, &by, &f.CreateTime, &f.UpdateTime)
		f.CreateBy = u32(by)
		return f, err
	})
}

// Secrets lists the live secrets (DELETED only when asked).
func (p *PG) Secrets(ctx context.Context, includeDeleted bool) ([]migrate3.SrcSecret, error) {
	rows, err := p.tx.Query(ctx, `SELECT id, folder_id, name, coalesce(username, ''), coalesce(host_url, ''), vault_path, coalesce(current_version, 0),
		metadata, coalesce(description, ''), coalesce(status::text, ''), coalesce(has_totp, false), create_by, update_by, create_time, update_time
		FROM warden_secrets WHERE coalesce(tenant_id, 0) = $1
		AND ($2 OR (delete_time IS NULL AND coalesce(status::text, '') <> 'SECRET_STATUS_DELETED')) ORDER BY folder_id NULLS FIRST, name, id`, p.tenant, includeDeleted)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (migrate3.SrcSecret, error) {
		var s migrate3.SrcSecret
		var cv int64
		var by, upd *int64
		err := r.Scan(&s.ID, &s.FolderID, &s.Name, &s.Username, &s.HostURL, &s.VaultPath, &cv, &s.Metadata, &s.Description, &s.Status, &s.HasTOTP,
			&by, &upd, &s.CreateTime, &s.UpdateTime)
		s.CurrentVersion, s.CreateBy, s.UpdateBy = int(cv), u32(by), u32(upd)
		return s, err
	})
}

// Versions lists the version rows of the given secrets.
func (p *PG) Versions(ctx context.Context, secretIDs []string) ([]migrate3.SrcVersion, error) {
	rows, err := p.tx.Query(ctx, `SELECT secret_id, version_number, coalesce(comment, ''), coalesce(checksum, ''), create_by, create_time
		FROM warden_secret_versions WHERE secret_id = ANY($1) AND delete_time IS NULL ORDER BY secret_id, version_number`, secretIDs)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (migrate3.SrcVersion, error) {
		var v migrate3.SrcVersion
		var n int64
		var by *int64
		err := r.Scan(&v.SecretID, &n, &v.Comment, &v.Checksum, &by, &v.CreateTime)
		v.Version, v.CreateBy = int(n), u32(by)
		return v, err
	})
}

// Permissions lists the live, unexpired permission rows.
func (p *PG) Permissions(ctx context.Context) ([]migrate3.SrcPermission, error) {
	rows, err := p.tx.Query(ctx, `SELECT resource_type::text, resource_id, relation::text, subject_type::text, subject_id, granted_by, expires_at, create_time
		FROM warden_permissions WHERE coalesce(tenant_id, 0) = $1 AND delete_time IS NULL AND (expires_at IS NULL OR expires_at > now())
		ORDER BY create_time NULLS FIRST, id`, p.tenant)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (migrate3.SrcPermission, error) {
		var g migrate3.SrcPermission
		var by *int64
		err := r.Scan(&g.ResourceType, &g.ResourceID, &g.Relation, &g.SubjectType, &g.SubjectID, &by, &g.ExpiresAt, &g.CreateTime)
		g.GrantedBy = u32(by)
		return g, err
	})
}

// UserEmails resolves portal user ids to e-mail addresses.
func (p *PG) UserEmails(ctx context.Context, ids []uint32) (map[uint32]string, error) {
	list := make([]int64, 0, len(ids))
	for _, id := range ids {
		list = append(list, int64(id))
	}
	rows, err := p.tx.Query(ctx, `SELECT id, coalesce(email, '') FROM sys_users WHERE id = ANY($1)`, list)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uint32]string{}
	for rows.Next() {
		var id int64
		var email string
		if err := rows.Scan(&id, &email); err != nil {
			return nil, err
		}
		out[uint32(id)] = email // #nosec G115 -- portal ids are uint32
	}
	return out, rows.Err()
}

// RoleCodes maps portal role ids to their codes.
func (p *PG) RoleCodes(ctx context.Context) (map[string]string, error) {
	rows, err := p.tx.Query(ctx, `SELECT id::text, coalesce(code, '') FROM sys_roles`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, code string
		if err := rows.Scan(&id, &code); err != nil {
			return nil, err
		}
		out[id] = code
	}
	return out, rows.Err()
}

func u32(v *int64) *uint32 {
	if v == nil || *v < 0 || *v > int64(^uint32(0)) {
		return nil
	}
	x := uint32(*v) // #nosec G115 -- range checked above
	return &x
}

// VaultOptions configure the v3 Vault reader.
type VaultOptions struct {
	Address          string
	Mount            string
	RoleID, SecretID string
	AllowPlaintext   bool
	CAFile           string
	Timeout          time.Duration
}

// Vault reads the v3 KV v2 mount with an AppRole token (read calls only).
type Vault struct {
	kv *api.KVv2
}

// OpenVault logs in with AppRole.
func OpenVault(ctx context.Context, o VaultOptions) (*Vault, error) {
	if strings.HasPrefix(o.Address, "http://") && !o.AllowPlaintext {
		return nil, errors.New("v3db: plaintext vault address refused (pass -allow-plaintext inside a private network)")
	}
	if o.RoleID == "" || o.SecretID == "" {
		return nil, errors.New("v3db: vault role id and secret id are required")
	}
	if o.Mount == "" {
		o.Mount = "secret"
	}
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	cfg := api.DefaultConfig()
	cfg.Address, cfg.Timeout, cfg.MaxRetries = o.Address, o.Timeout, 2
	if o.CAFile != "" {
		if err := cfg.ConfigureTLS(&api.TLSConfig{CACert: o.CAFile}); err != nil {
			return nil, fmt.Errorf("v3db: vault tls: %w", err)
		}
	}
	c, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("v3db: vault client: %w", err)
	}
	auth, err := approle.NewAppRoleAuth(o.RoleID, &approle.SecretID{FromString: o.SecretID})
	if err != nil {
		return nil, fmt.Errorf("v3db: approle: %w", err)
	}
	sec, err := c.Auth().Login(ctx, auth)
	if err != nil || sec == nil || sec.Auth == nil {
		return nil, errors.New("v3db: vault login failed (AppRole role id / secret id)")
	}
	return &Vault{kv: c.KVv2(o.Mount)}, nil
}

func notFound(err error) bool {
	var re *api.ResponseError
	return errors.Is(err, api.ErrSecretNotFound) || (errors.As(err, &re) && re.StatusCode == 404)
}

// Metadata reads a path's version list.
func (v *Vault) Metadata(ctx context.Context, path string) (migrate3.KVMeta, error) {
	m, err := v.kv.GetMetadata(ctx, path)
	if err != nil {
		if notFound(err) {
			return migrate3.KVMeta{}, migrate3.ErrNoKV
		}
		return migrate3.KVMeta{}, err
	}
	out := migrate3.KVMeta{Versions: map[int]migrate3.KVVersion{}}
	for _, ver := range m.Versions {
		out.Versions[ver.Version] = migrate3.KVVersion{CreatedTime: ver.CreatedTime, Deleted: !ver.DeletionTime.IsZero(), Destroyed: ver.Destroyed}
	}
	return out, nil
}

// Read returns one version's data (0 = latest).
func (v *Vault) Read(ctx context.Context, path string, version int) (map[string]any, error) {
	var sec *api.KVSecret
	var err error
	if version > 0 {
		sec, err = v.kv.GetVersion(ctx, path, version)
	} else {
		sec, err = v.kv.Get(ctx, path)
	}
	if err != nil {
		if notFound(err) {
			return nil, migrate3.ErrNoKV
		}
		return nil, err
	}
	if sec == nil || sec.Data == nil {
		return nil, migrate3.ErrNoKV
	}
	return sec.Data, nil
}
