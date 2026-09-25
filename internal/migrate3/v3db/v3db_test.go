//go:build integration

package v3db

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/go-tangra/go-tangra-warden/v4/internal/audit"
	"github.com/go-tangra/go-tangra-warden/v4/internal/migrate3"
	"github.com/go-tangra/go-tangra-warden/v4/internal/repo/repodb"
	"github.com/go-tangra/go-tangra-warden/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
	"github.com/go-tangra/go-tangra-warden/v4/internal/transfer"
	"github.com/go-tangra/go-tangra-warden/v4/internal/vault"
)

// v3 DDL as the portal's Ent migration creates it (the columns the export reads).
const v3DDL = `
CREATE TABLE sys_users (id bigserial PRIMARY KEY, tenant_id bigint, username varchar, email varchar);
CREATE TABLE sys_roles (id bigserial PRIMARY KEY, tenant_id bigint, code varchar, name varchar);
CREATE TABLE warden_folders (id varchar PRIMARY KEY, create_by bigint, create_time timestamptz, update_time timestamptz, delete_time timestamptz,
  tenant_id bigint DEFAULT 0, name varchar(255) NOT NULL, path varchar(4096) NOT NULL, description varchar(1024), depth integer NOT NULL DEFAULT 0, parent_id varchar);
CREATE TABLE warden_secrets (id varchar PRIMARY KEY, create_by bigint, update_by bigint, create_time timestamptz, update_time timestamptz, delete_time timestamptz,
  tenant_id bigint DEFAULT 0, name varchar(255) NOT NULL, username varchar(255), host_url varchar(2048), vault_path varchar NOT NULL,
  current_version integer NOT NULL DEFAULT 1, metadata jsonb, description varchar(4096), status varchar NOT NULL DEFAULT 'SECRET_STATUS_ACTIVE',
  has_totp boolean NOT NULL DEFAULT false, folder_id varchar);
CREATE TABLE warden_secret_versions (id bigserial PRIMARY KEY, create_by bigint, create_time timestamptz, update_time timestamptz, delete_time timestamptz,
  version_number integer NOT NULL, vault_path varchar NOT NULL, comment varchar(1024), checksum varchar(64) NOT NULL, secret_id varchar NOT NULL);
CREATE TABLE warden_permissions (id bigserial PRIMARY KEY, create_time timestamptz, update_time timestamptz, delete_time timestamptz, tenant_id bigint DEFAULT 0,
  resource_type varchar NOT NULL, resource_id varchar(36) NOT NULL, relation varchar NOT NULL, subject_type varchar NOT NULL, subject_id varchar(36) NOT NULL,
  granted_by bigint, expires_at timestamptz, folder_permissions varchar, secret_permissions varchar);
`

const (
	fInfra = "7f1c1a52-5b0e-4d0e-9a1e-000000000001"
	fDB    = "7f1c1a52-5b0e-4d0e-9a1e-000000000002"
	fGone  = "7f1c1a52-5b0e-4d0e-9a1e-000000000003"
	sProd  = "9a2b3c4d-0000-4000-8000-000000000001"
	sRoot  = "9a2b3c4d-0000-4000-8000-000000000002"
	sDel   = "9a2b3c4d-0000-4000-8000-000000000003"
	sOther = "9a2b3c4d-0000-4000-8000-000000000004" // tenant 5: never exported
	v4T    = migrate3.DefaultTenant
	uAlice = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"
	uOps   = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c88"
)

func startPG(t *testing.T) (host, port string) {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: testcontainers.ContainerRequest{
		Image: "timescale/timescaledb:latest-pg16", ExposedPorts: []string{"5432/tcp"},
		Env:        map[string]string{"POSTGRES_PASSWORD": "test", "POSTGRES_DB": "gwa"},
		WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
	}, Started: true})
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	h, _ := c.Host(ctx)
	p, _ := c.MappedPort(ctx, "5432/tcp")
	return h, p.Port()
}

func startVault(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: testcontainers.ContainerRequest{
		Image: "hashicorp/vault:1.18", ExposedPorts: []string{"8200/tcp"},
		Env:        map[string]string{"VAULT_DEV_ROOT_TOKEN_ID": "dev-root", "VAULT_DEV_LISTEN_ADDRESS": "0.0.0.0:8200"},
		CapAdd:     []string{"IPC_LOCK"},
		WaitingFor: wait.ForHTTP("/v1/sys/health").WithPort("8200/tcp").WithStartupTimeout(2 * time.Minute),
	}, Started: true})
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	h, _ := c.Host(ctx)
	p, _ := c.MappedPort(ctx, "8200/tcp")
	return "http://" + h + ":" + p.Port()
}

type rootVault struct {
	t    *testing.T
	addr string
}

func (v rootVault) call(method, path string, body any) map[string]any {
	v.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, v.addr+"/v1/"+path, rd)
	req.Header.Set("X-Vault-Token", "dev-root")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		v.t.Fatalf("vault %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode >= 300 && resp.StatusCode != 400 {
		v.t.Fatalf("vault %s %s: %d %v", method, path, resp.StatusCode, out)
	}
	return out
}

// approle creates a role with the policy and returns its credentials.
func (v rootVault) approle(name, policy string) (string, string) {
	v.call("PUT", "sys/policies/acl/"+name, map[string]string{"policy": policy})
	v.call("POST", "auth/approle/role/"+name, map[string]any{"token_policies": []string{name}, "token_ttl": "1h"})
	role := v.call("GET", "auth/approle/role/"+name+"/role-id", nil)["data"].(map[string]any)["role_id"].(string)
	secret := v.call("POST", "auth/approle/role/"+name+"/secret-id", nil)["data"].(map[string]any)["secret_id"].(string)
	return role, secret
}

func seedV3(t *testing.T, ctx context.Context, dsn string, rv rootVault) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, v3DDL); err != nil {
		t.Fatal(err)
	}
	t1, t2, t3 := time.Date(2021, 1, 1, 10, 0, 0, 0, time.UTC), time.Date(2022, 2, 2, 10, 0, 0, 0, time.UTC), time.Date(2023, 3, 3, 10, 0, 0, 0, time.UTC)
	future, past := time.Now().Add(24*time.Hour), time.Now().Add(-time.Hour)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO sys_users (id, tenant_id, username, email) VALUES (1, 0, 'alice', 'Alice@Example.org'), (2, 0, 'ops', 'ops@example.org'), (3, 0, 'ghost', NULL)`)
	exec(`INSERT INTO sys_roles (id, tenant_id, code) VALUES (1, 0, 'platform:admin')`)
	exec(`INSERT INTO warden_folders (id, create_by, create_time, update_time, tenant_id, name, path, description, depth, parent_id) VALUES
		($1, 1, $3, $4, 0, 'Infra', '/Infra', 'servers', 0, NULL),
		($2, 2, $4, $4, 0, 'DB', '/Infra/DB', NULL, 1, $1)`, fInfra, fDB, t1, t2)
	exec(`INSERT INTO warden_folders (id, create_time, delete_time, tenant_id, name, path, depth) VALUES ($1, $2, $2, 0, 'Old', '/Old', 0)`, fGone, t1)
	exec(`INSERT INTO warden_secrets (id, create_by, update_by, create_time, update_time, tenant_id, name, username, host_url, vault_path, current_version, metadata, description, status, has_totp, folder_id) VALUES
		($1, 1, 2, $5, $7, 0, 'prod', 'root', 'https://db.example.org', 'warden/0/'||$1::varchar, 3, '{"env":"prod"}', 'primary', 'SECRET_STATUS_ACTIVE', true, $8),
		($2, 3, NULL, $6, NULL, 0, 'root-level', NULL, NULL, 'warden/0/'||$2::varchar, 1, NULL, NULL, 'SECRET_STATUS_ARCHIVED', false, NULL),
		($3, 1, 1, $5, $6, 0, 'deleted', NULL, NULL, 'warden/0/'||$3::varchar, 1, NULL, NULL, 'SECRET_STATUS_DELETED', false, NULL),
		($4, 1, 1, $5, $6, 5, 'other tenant', NULL, NULL, 'warden/5/'||$4::varchar, 1, NULL, NULL, 'SECRET_STATUS_ACTIVE', false, NULL)`,
		sProd, sRoot, sDel, sOther, t1, t2, t3, fDB)
	// Vault: prod has three versions (v1 destroyed later), a TOTP URL; root-level one version.
	for _, pw := range []string{"WARDEN-MARKER-PW-p1", "WARDEN-MARKER-PW-p2", "WARDEN-MARKER-PW-p3"} {
		rv.call("POST", "secret/data/warden/0/"+sProd, map[string]any{"data": map[string]any{"password": pw}})
	}
	rv.call("POST", "secret/destroy/warden/0/"+sProd, map[string]any{"versions": []int{1}})
	rv.call("POST", "secret/data/warden/0/"+sProd+"/totp", map[string]any{"data": map[string]any{"totp_url": "otpauth://totp/Acme:root?secret=JBSWY3DPEHPK3PXP&issuer=Acme&period=60"}})
	rv.call("POST", "secret/data/warden/0/"+sRoot, map[string]any{"data": map[string]any{"password": "WARDEN-MARKER-PW-r1"}})
	rv.call("POST", "secret/data/warden/0/"+sDel, map[string]any{"data": map[string]any{"password": "WARDEN-MARKER-PW-d1"}})
	exec(`INSERT INTO warden_secret_versions (create_by, create_time, version_number, vault_path, comment, checksum, secret_id) VALUES
		(1, $2, 1, 'warden/0/'||$1::varchar, 'initial', $5, $1),
		(2, $3, 2, 'warden/0/'||$1::varchar, 'rotated', $6, $1),
		(2, $4, 3, 'warden/0/'||$1::varchar, 'again', $7, $1)`, sProd, t1, t2, t3,
		secrets.Checksum("WARDEN-MARKER-PW-p1"), secrets.Checksum("WARDEN-MARKER-PW-p2"), secrets.Checksum("WARDEN-MARKER-PW-p3"))
	exec(`INSERT INTO warden_secret_versions (create_by, create_time, version_number, vault_path, comment, checksum, secret_id) VALUES (3, $2, 1, 'warden/0/'||$1::varchar, '', $3, $1)`,
		sRoot, t2, secrets.Checksum("WARDEN-MARKER-PW-r1"))
	exec(`INSERT INTO warden_permissions (create_time, tenant_id, resource_type, resource_id, relation, subject_type, subject_id, granted_by, expires_at, delete_time) VALUES
		($3, 0, 'RESOURCE_TYPE_FOLDER', $1, 'RELATION_OWNER', 'SUBJECT_TYPE_USER', '1', 1, NULL, NULL),
		($3, 0, 'RESOURCE_TYPE_FOLDER', $1, 'RELATION_VIEWER', 'SUBJECT_TYPE_USER', '2', 1, NULL, NULL),
		($3, 0, 'RESOURCE_TYPE_FOLDER', $1, 'RELATION_EDITOR', 'SUBJECT_TYPE_ROLE', 'platform:admin', 1, NULL, NULL),
		($3, 0, 'RESOURCE_TYPE_SECRET', $2, 'RELATION_VIEWER', 'SUBJECT_TYPE_ROLE', '1', 1, $4, NULL),
		($3, 0, 'RESOURCE_TYPE_SECRET', $2, 'RELATION_OWNER', 'SUBJECT_TYPE_USER', '2', 2, NULL, NULL),
		($3, 0, 'RESOURCE_TYPE_SECRET', $2, 'RELATION_VIEWER', 'SUBJECT_TYPE_TENANT', 'all', 1, NULL, NULL),
		($3, 0, 'RESOURCE_TYPE_SECRET', $2, 'RELATION_SHARER', 'SUBJECT_TYPE_USER', '3', 1, $5, NULL),
		($3, 0, 'RESOURCE_TYPE_SECRET', $2, 'RELATION_EDITOR', 'SUBJECT_TYPE_USER', '1', 1, NULL, $3)`, fInfra, sProd, t2, future, past)
}

// TestExportImportRoundTrip exports a seeded v3 tenant from real Postgres and
// Vault, then imports the bundle into a real v4 store and Vault mount.
func TestExportImportRoundTrip(t *testing.T) {
	ctx := context.Background()
	host, port := startPG(t)
	addr := startVault(t)
	rv := rootVault{t: t, addr: addr}
	v3DSN := "postgres://postgres:test@" + host + ":" + port + "/gwa?sslmode=disable"
	seedV3(t, ctx, v3DSN, rv)

	// v3 AppRole: the portal's warden policy (data + metadata under warden/).
	rv.call("POST", "sys/auth/approle", map[string]string{"type": "approle"})
	v3Role, v3Secret := rv.approle("warden-v3", `path "secret/data/warden/*" { capabilities = ["read","list"] }
path "secret/metadata/warden/*" { capabilities = ["read","list"] }`)

	dir := t.TempDir()
	out, keyOut := filepath.Join(dir, "v3.bundle"), filepath.Join(dir, "v3.key")
	pg, err := Open(ctx, v3DSN, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The snapshot is read-only.
	if _, err := pg.tx.Exec(ctx, "DELETE FROM warden_permissions"); err == nil {
		t.Fatal("export transaction accepts writes")
	}
	pg.Close(ctx)
	pg, err = Open(ctx, v3DSN, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close(ctx)
	if _, err := OpenVault(ctx, VaultOptions{Address: addr, RoleID: v3Role, SecretID: v3Secret}); err == nil {
		t.Fatal("plaintext vault accepted without the opt-in")
	}
	if _, err := OpenVault(ctx, VaultOptions{Address: addr, RoleID: v3Role, SecretID: "wrong", AllowPlaintext: true}); err == nil {
		t.Fatal("bad secret id accepted")
	}
	kv, err := OpenVault(ctx, VaultOptions{Address: addr, RoleID: v3Role, SecretID: v3Secret, AllowPlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	sum, err := migrate3.RunExport(ctx, migrate3.ExportConfig{Out: out, KeyOut: keyOut}, pg, kv)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Folders != 2 || sum.Secrets != 2 || sum.Versions != 4 || sum.VersionsMissing != 1 || len(sum.ChecksumMismatches) != 0 || sum.TOTP != 1 ||
		sum.Grants != 6 || sum.UsersWithoutEmail != 1 || sum.SecretsByStatus["archived"] != 1 {
		t.Fatalf("%+v", sum)
	}
	raw, _ := json.Marshal(sum)
	sealed, _ := os.ReadFile(out)
	for _, blob := range [][]byte{raw, sealed} {
		if bytes.Contains(blob, []byte("MARKER")) || bytes.Contains(blob, []byte("JBSWY3DP")) {
			t.Fatal("material outside the sealed bundle")
		}
	}
	b, err := migrate3.ReadFiles(out, keyOut)
	if err != nil {
		t.Fatal(err)
	}
	if b.Secrets[0].ID != sRoot && b.Secrets[1].ID != sRoot {
		t.Fatalf("%+v", b.Secrets)
	}

	// --- v4 side: warden database and the warden KV mount on the same containers.
	admin, _ := pgx.Connect(ctx, "postgres://postgres:test@"+host+":"+port+"/gwa?sslmode=disable")
	for _, q := range []string{"CREATE DATABASE warden", "CREATE ROLE warden_app LOGIN PASSWORD 'app' NOBYPASSRLS"} {
		if _, err := admin.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	_ = admin.Close(ctx)
	if err := store.Migrate(ctx, "postgres://postgres:test@"+host+":"+port+"/warden?sslmode=disable"); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, "postgres://warden_app:app@"+host+":"+port+"/warden?sslmode=disable", 4)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rv.call("POST", "sys/mounts/warden", map[string]any{"type": "kv", "options": map[string]string{"version": "2"}})
	v4Role, v4Secret := rv.approle("warden", `path "warden/data/*" { capabilities = ["create","read","update","delete"] }
path "warden/metadata/*" { capabilities = ["read","delete","list"] }
path "auth/token/renew-self" { capabilities = ["update"] }`)
	v4v, err := vault.New(ctx, vault.Options{Address: addr, Mount: "warden", RoleID: v4Role, SecretID: v4Secret, AllowPlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v4v.Close()
	db := repodb.New(st)
	aw := audit.NewWriter(db, func(err error) { t.Errorf("audit: %v", err) })
	svc := transfer.New(db, nil, nil, nil, aw)

	users := filepath.Join(dir, "users.csv")
	_ = os.WriteFile(users, []byte("alice@example.org,"+uAlice+"\nops@example.org,"+uOps+"\n"), 0o600)
	cfg := migrate3.ImportConfig{In: out, KeyFile: keyOut, UsersFile: users, TenantID: v4T, RoleMap: "platform:admin=admin", ActorEmail: "ops@example.org", DryRun: true}
	dry, err := migrate3.RunImport(ctx, cfg, svc, v4v)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := db.AllSecrets(ctx, v4T, 10); len(n) != 0 {
		t.Fatal("dry run wrote")
	}
	cfg.DryRun = false
	res, err := migrate3.RunImport(ctx, cfg, svc, v4v)
	if err != nil {
		t.Fatal(err)
	}
	aw.Close()
	if res.Failed() || res.Import.Secrets.Created != 2 || res.Import.Versions.Created != 3 || res.Import.Versions.Skipped != 1 || res.Import.Verified != 2 ||
		res.Import.TOTP.Created != 1 || res.Mapping.UnknownSubjects != 0 || dry.Import.Secrets != res.Import.Secrets || dry.Import.Grants != res.Import.Grants {
		t.Fatalf("dry %+v\nreal %+v", dry, res)
	}
	noMat, _ := json.Marshal(res)
	if bytes.Contains(noMat, []byte("MARKER")) || bytes.Contains(noMat, []byte("otpauth")) {
		t.Fatal("material in the report")
	}
	all, _ := db.AllSecrets(ctx, v4T, 10)
	var prod store.Secret
	for _, s := range all {
		if s.Name == "prod" {
			prod = s
		}
	}
	if prod.CurrentVersion != 3 || !prod.HasTOTP || !prod.CreatedAt.Equal(time.Date(2021, 1, 1, 10, 0, 0, 0, time.UTC)) || *prod.CreatedBy != uAlice || *prod.UpdatedBy != uOps || prod.FolderPath != "/Infra/DB" {
		t.Fatalf("%+v", prod)
	}
	vers, _ := db.VersionsOf(ctx, v4T, prod.ID)
	if len(vers) != 3 || !vers[2].MaterialMissing || vers[2].Version != 1 || vers[0].Source != transfer.MigrationSource || !vers[1].CreatedAt.Equal(time.Date(2022, 2, 2, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("%+v", vers)
	}
	// Real Vault: the skipped version stays unreadable, the others keep their numbers.
	if _, err := v4v.GetPassword(ctx, v4T, prod.ID, 1); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("skipped version: %v", err)
	}
	for n, want := range map[int]string{2: "WARDEN-MARKER-PW-p2", 3: "WARDEN-MARKER-PW-p3", 0: "WARDEN-MARKER-PW-p3"} {
		if got, err := v4v.GetPassword(ctx, v4T, prod.ID, n); err != nil || got != want {
			t.Fatalf("v%d: %v", n, err)
		}
	}
	if vs, _ := v4v.Versions(ctx, v4T, prod.ID); len(vs) != 2 {
		t.Fatalf("live versions %v", vs)
	}
	if seed, _ := v4v.GetTOTP(ctx, v4T, prod.ID); !strings.Contains(seed, "period=60") || !strings.Contains(seed, "issuer=Acme") {
		t.Fatal("seed not normalised with its parameters")
	}
	// Grants: originals only (no importer owner), tenant and role mapped.
	var ids []string
	for _, s := range all {
		ids = append(ids, s.ID)
	}
	fs, _ := db.AllFolders(ctx, v4T, 10)
	for _, f := range fs {
		ids = append(ids, f.ID)
	}
	grants, _ := db.GrantsOnResources(ctx, v4T, ids)
	kinds := map[string]int{}
	for _, g := range grants {
		kinds[g.SubjectType+":"+g.SubjectID+":"+g.Relation]++
		if g.GrantedAt.Year() != 2022 {
			t.Fatalf("granted_at not kept: %+v", g)
		}
	}
	if len(grants) != 6 || kinds["user:"+uAlice+":owner"] != 1 || kinds["role:admin:editor"] != 1 || kinds["role:admin:viewer"] != 1 || kinds["tenant::viewer"] != 1 || kinds["user:"+uOps+":owner"] != 1 {
		t.Fatalf("%v", kinds)
	}
	rows, _ := db.QueryAudit(ctx, v4T, "migration_imported", "", time.Time{}, time.Now().Add(time.Hour), time.Time{}, 10)
	if len(rows) != 1 || rows[0].ActorID != uOps {
		t.Fatalf("%+v", rows)
	}
	// Not idempotent: a second run is refused.
	if _, err := migrate3.RunImport(ctx, cfg, svc, v4v); !errors.Is(err, transfer.ErrTenantNotEmpty) {
		t.Fatalf("second import: %v", err)
	}
}
