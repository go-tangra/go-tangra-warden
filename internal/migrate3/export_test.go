package migrate3

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-warden/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-warden/v4/internal/transfer"
)

type fakeSource struct {
	folders []SrcFolder
	secrets []SrcSecret
	vers    []SrcVersion
	perms   []SrcPermission
	emails  map[uint32]string
	roles   map[string]string
	fail    string
	deleted bool // includeDeleted seen
}

func (f *fakeSource) err(op string) error {
	if f.fail == op {
		return errors.New(op + " failed")
	}
	return nil
}
func (f *fakeSource) Folders(context.Context) ([]SrcFolder, error) {
	return f.folders, f.err("folders")
}
func (f *fakeSource) Secrets(_ context.Context, includeDeleted bool) ([]SrcSecret, error) {
	f.deleted = includeDeleted
	var out []SrcSecret
	for _, s := range f.secrets {
		if includeDeleted || s.Status != "SECRET_STATUS_DELETED" {
			out = append(out, s)
		}
	}
	return out, f.err("secrets")
}
func (f *fakeSource) Versions(context.Context, []string) ([]SrcVersion, error) {
	return f.vers, f.err("versions")
}
func (f *fakeSource) Permissions(context.Context) ([]SrcPermission, error) {
	return f.perms, f.err("permissions")
}
func (f *fakeSource) UserEmails(_ context.Context, ids []uint32) (map[uint32]string, error) {
	out := map[uint32]string{}
	for _, id := range ids {
		if e, ok := f.emails[id]; ok {
			out[id] = e
		}
	}
	return out, f.err("users")
}
func (f *fakeSource) RoleCodes(context.Context) (map[string]string, error) {
	return f.roles, f.err("roles")
}

type fakeKV struct {
	meta map[string]KVMeta
	data map[string]map[int]map[string]any // path → version → data (0 = latest)
	fail string
}

func (k *fakeKV) Metadata(_ context.Context, path string) (KVMeta, error) {
	if k.fail == "meta" {
		return KVMeta{}, errors.New("vault down")
	}
	m, ok := k.meta[path]
	if !ok {
		return KVMeta{}, ErrNoKV
	}
	return m, nil
}

func (k *fakeKV) Read(_ context.Context, path string, version int) (map[string]any, error) {
	if k.fail == "read" {
		return nil, errors.New("vault down")
	}
	d, ok := k.data[path][version]
	if !ok {
		return nil, ErrNoKV
	}
	return d, nil
}

func u32(v uint32) *uint32 { return &v }

func v3Fixture() (*fakeSource, *fakeKV) {
	t1 := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2022, 2, 2, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2023, 3, 3, 0, 0, 0, 0, time.UTC)
	future := time.Now().Add(time.Hour)
	infra, db := "f-infra", "f-db"
	src := &fakeSource{
		folders: []SrcFolder{
			{ID: infra, Name: "Infra", Path: "/Infra", Description: "servers", CreateBy: u32(1), CreateTime: &t1, UpdateTime: &t2},
			{ID: db, ParentID: &infra, Name: "DB", Path: "/Infra/DB", CreateBy: u32(2), CreateTime: &t2},
		},
		secrets: []SrcSecret{
			{ID: "s1", FolderID: &db, Name: "prod", Username: "root", HostURL: "https://db", VaultPath: "warden/0/s1", CurrentVersion: 3, Metadata: []byte(`{"env":"prod"}`),
				Status: "SECRET_STATUS_ACTIVE", HasTOTP: true, CreateBy: u32(1), UpdateBy: u32(2), CreateTime: &t1, UpdateTime: &t3},
			{ID: "s2", Name: "root-level", VaultPath: "warden/0/s2", CurrentVersion: 1, Metadata: []byte("null"), Status: "SECRET_STATUS_ARCHIVED", HasTOTP: true, CreateBy: u32(99)},
			{ID: "s3", Name: "gone", VaultPath: "warden/0/s3", CurrentVersion: 1, Status: "SECRET_STATUS_DELETED"},
			{ID: "s4", Name: "novault", VaultPath: "warden/0/s4", CurrentVersion: 1, Status: "SECRET_STATUS_ACTIVE"},
		},
		vers: []SrcVersion{
			{SecretID: "s1", Version: 1, Comment: "initial", Checksum: secrets.Checksum("pw-1"), CreateBy: u32(1), CreateTime: &t1},
			{SecretID: "s1", Version: 2, Comment: "rotated", Checksum: strings.ToUpper(secrets.Checksum("WARDEN-MARKER-PW-2")), CreateBy: u32(2), CreateTime: &t2},
			{SecretID: "s1", Version: 3, Comment: "bad", Checksum: "0000", CreateBy: u32(2), CreateTime: &t3},
			{SecretID: "s2", Version: 1, Checksum: ""},
			{SecretID: "s4", Version: 1, Checksum: "x"},
		},
		perms: []SrcPermission{
			{ResourceType: "RESOURCE_TYPE_FOLDER", ResourceID: infra, Relation: "RELATION_OWNER", SubjectType: "SUBJECT_TYPE_USER", SubjectID: "1", GrantedBy: u32(1), CreateTime: &t1},
			{ResourceType: "RESOURCE_TYPE_SECRET", ResourceID: "s1", Relation: "RELATION_VIEWER", SubjectType: "SUBJECT_TYPE_ROLE", SubjectID: "1", ExpiresAt: &future},
			{ResourceType: "RESOURCE_TYPE_SECRET", ResourceID: "s2", Relation: "RELATION_EDITOR", SubjectType: "SUBJECT_TYPE_ROLE", SubjectID: "platform:admin"},
			{ResourceType: "RESOURCE_TYPE_SECRET", ResourceID: "s2", Relation: "RELATION_SHARER", SubjectType: "SUBJECT_TYPE_TENANT", SubjectID: "all"},
			{ResourceType: "RESOURCE_TYPE_SECRET", ResourceID: "s3", Relation: "RELATION_VIEWER", SubjectType: "SUBJECT_TYPE_USER", SubjectID: "2"}, // on a deleted secret
			{ResourceType: "RESOURCE_TYPE_SECRET", ResourceID: "s2", Relation: "RELATION_VIEWER", SubjectType: "SUBJECT_TYPE_USER", SubjectID: "abc"},
		},
		emails: map[uint32]string{1: "Alice@Example.org", 2: "bob@example.org"},
		roles:  map[string]string{"1": "platform:admin"},
	}
	kv := &fakeKV{
		meta: map[string]KVMeta{
			"warden/0/s1": {Versions: map[int]KVVersion{1: {CreatedTime: t1, Destroyed: true}, 2: {CreatedTime: t2}, 3: {CreatedTime: t3}, 4: {CreatedTime: t3, Deleted: true}}},
			"warden/0/s2": {Versions: map[int]KVVersion{1: {CreatedTime: t2}, 2: {CreatedTime: t3}}},
		},
		data: map[string]map[int]map[string]any{
			"warden/0/s1":      {2: {"password": "WARDEN-MARKER-PW-2"}, 3: {"password": "WARDEN-MARKER-PW-3"}},
			"warden/0/s1/totp": {0: {"totp_url": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"}},
			"warden/0/s2":      {1: {"password": "WARDEN-MARKER-PW-r"}, 2: {"nopassword": true}},
		},
	}
	return src, kv
}

func TestExport(t *testing.T) {
	src, kv := v3Fixture()
	b, sum, err := Export(context.Background(), src, kv, ExportOptions{Tenant: 0})
	if err != nil {
		t.Fatal(err)
	}
	if b.Format != Format || b.Version != FormatVersion || len(b.Folders) != 2 || len(b.Secrets) != 3 || src.deleted {
		t.Fatalf("%+v", b)
	}
	f := b.Folders[0]
	if f.CreatedBy != "alice@example.org" || f.Description != "servers" || f.CreatedAt == nil || f.UpdatedAt == nil {
		t.Fatalf("%+v", f)
	}
	s1 := b.Secrets[0]
	if s1.Status != "active" || s1.TOTPURL == "" || s1.CreatedBy != "alice@example.org" || s1.UpdatedBy != "bob@example.org" || string(s1.Metadata) != `{"env":"prod"}` {
		t.Fatalf("%+v", s1)
	}
	// 1 destroyed, 2 and 3 present (3 with a bad checksum), 4 deleted and without a row.
	if len(s1.Versions) != 4 || !s1.Versions[0].Missing || s1.Versions[0].Comment != "initial" || s1.Versions[1].Password != "WARDEN-MARKER-PW-2" ||
		s1.Versions[1].ChecksumMismatch || !s1.Versions[2].ChecksumMismatch || !s1.Versions[3].Missing || s1.Versions[1].CreatedBy != "bob@example.org" {
		t.Fatalf("%+v", s1.Versions)
	}
	s2 := b.Secrets[1]
	if s2.Status != "archived" || s2.Metadata != nil || s2.TOTPURL != "" || len(s2.Versions) != 2 || s2.Versions[0].Password != "WARDEN-MARKER-PW-r" || !s2.Versions[1].Missing || s2.CreatedBy != "" {
		t.Fatalf("%+v", s2)
	}
	if s4 := b.Secrets[2]; len(s4.Versions) != 1 || !s4.Versions[0].Missing {
		t.Fatalf("%+v", s4)
	}
	if len(b.Grants) != 5 || b.Grants[4].Subject != "" || b.Grants[4].SubjectV3 != "abc" {
		t.Fatalf("%+v", b.Grants)
	}
	g := b.Grants[0]
	if g.ResourceType != "folder" || g.Relation != "owner" || g.SubjectType != "user" || g.Subject != "alice@example.org" || g.SubjectV3 != "1" || g.GrantedBy != "alice@example.org" || g.GrantedAt == nil {
		t.Fatalf("%+v", g)
	}
	if r := b.Grants[1]; r.Subject != "platform:admin" || r.SubjectV3 != "1" || r.ExpiresAt == nil {
		t.Fatalf("numeric role id not resolved: %+v", r)
	}
	if ten := b.Grants[3]; ten.SubjectType != "tenant" || ten.Subject != "all" || ten.Relation != "sharer" {
		t.Fatalf("%+v", ten)
	}
	if sum.Folders != 2 || sum.Secrets != 3 || sum.SecretsByStatus["archived"] != 1 || sum.Versions != 7 || sum.VersionsMissing != 4 || len(sum.ChecksumMismatches) != 1 ||
		sum.ChecksumUnverified != 1 || sum.TOTP != 1 || sum.TOTPMissing != 1 || sum.Grants != 5 || sum.GrantsSkipped != 1 || sum.UsersWithoutEmail != 2 || len(sum.Warnings) == 0 {
		t.Fatalf("%+v", sum)
	}
	raw, _ := json.Marshal(sum)
	for _, bad := range []string{"MARKER", "JBSWY", "otpauth"} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("material in summary: %s", raw)
		}
	}
	// -include-deleted brings the deleted secret and its grant.
	src, kv = v3Fixture()
	kv.meta["warden/0/s3"] = KVMeta{Versions: map[int]KVVersion{1: {}}}
	kv.data["warden/0/s3"] = map[int]map[string]any{1: {"password": "WARDEN-MARKER-PW-d"}}
	b, sum, err = Export(context.Background(), src, kv, ExportOptions{IncludeDeleted: true})
	if err != nil || len(b.Secrets) != 4 || sum.SecretsByStatus["deleted"] != 1 || sum.Grants != 6 {
		t.Fatalf("%+v %v", sum, err)
	}
}

func TestExportFailsClosed(t *testing.T) {
	for _, op := range []string{"folders", "secrets", "versions", "permissions", "users", "roles"} {
		src, kv := v3Fixture()
		src.fail = op
		if _, _, err := Export(context.Background(), src, kv, ExportOptions{}); err == nil {
			t.Errorf("%s failure ignored", op)
		}
	}
	for _, op := range []string{"meta", "read"} {
		src, kv := v3Fixture()
		kv.fail = op
		if _, _, err := Export(context.Background(), src, kv, ExportOptions{}); err == nil || strings.Contains(err.Error(), "MARKER") {
			t.Errorf("%s: %v", op, err)
		}
	}
	src, kv := v3Fixture()
	kv.data["warden/0/s1/totp"] = map[int]map[string]any{0: {"totp_url": 42}}
	_, sum, err := Export(context.Background(), src, kv, ExportOptions{})
	if err != nil || sum.TOTPMissing != 2 {
		t.Fatalf("%+v %v", sum, err)
	}
}

func TestRunExportAndImport(t *testing.T) {
	dir := t.TempDir()
	out, key := filepath.Join(dir, "b"), filepath.Join(dir, "k")
	src, kv := v3Fixture()
	sum, err := RunExport(context.Background(), ExportConfig{Out: out, KeyOut: key}, src, kv)
	if err != nil || sum.Secrets != 3 {
		t.Fatal(sum, err)
	}
	// Refuses to run at all when an output exists (nothing read, nothing written).
	src2, kv2 := v3Fixture()
	src2.fail = "folders"
	if _, err := RunExport(context.Background(), ExportConfig{Out: filepath.Join(dir, "b2"), KeyOut: key}, src2, kv2); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatal(err)
	}
	if _, err := RunExport(context.Background(), ExportConfig{Out: out, KeyOut: filepath.Join(dir, "k2")}, src2, kv2); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatal(err)
	}
	if _, err := RunExport(context.Background(), ExportConfig{Out: filepath.Join(dir, "b3"), KeyOut: filepath.Join(dir, "k3")}, src2, kv2); err == nil {
		t.Fatal("source failure ignored")
	}
	if _, err := RunExport(context.Background(), ExportConfig{}, src, kv); err == nil {
		t.Fatal("missing paths accepted")
	}

	users := filepath.Join(dir, "users.csv")
	_ = os.WriteFile(users, []byte("alice@example.org,"+uAlice+"\nbob@example.org,"+uOps+"\n"), 0o600)
	imp := &fakeImporter{}
	cfg := ImportConfig{In: out, KeyFile: key, UsersFile: users, TenantID: v4Tenant, RoleMap: "platform:admin=admin", ActorEmail: "bob@example.org", DryRun: true}
	res, err := RunImport(context.Background(), cfg, imp, nil)
	if err != nil || !imp.opts.DryRun || imp.got.ActorID != uOps || len(imp.got.Secrets) != 3 || len(res.Mapping.UnmappedRoles) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if res.Failed() {
		t.Fatalf("%+v", res)
	}
	imp.rep.ValidationFailures = []string{"x"}
	if res, _ = RunImport(context.Background(), cfg, imp, nil); !res.Failed() {
		t.Fatal("import failure not reported")
	}
	for name, bad := range map[string]ImportConfig{
		"key":      {In: out, KeyFile: filepath.Join(dir, "none"), UsersFile: users, TenantID: v4Tenant, ActorEmail: "bob@example.org"},
		"users":    {In: out, KeyFile: key, UsersFile: filepath.Join(dir, "none"), TenantID: v4Tenant, ActorEmail: "bob@example.org"},
		"badusers": {In: out, KeyFile: key, UsersFile: key, TenantID: v4Tenant, ActorEmail: "bob@example.org"},
		"roles":    {In: out, KeyFile: key, UsersFile: users, TenantID: v4Tenant, RoleMap: "broken", ActorEmail: "bob@example.org"},
		"actor":    {In: out, KeyFile: key, UsersFile: users, TenantID: v4Tenant, ActorEmail: "eve@example.org"},
		"missing":  {},
	} {
		if _, err := RunImport(context.Background(), bad, imp, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	imp.err = errors.New("refused")
	if _, err := RunImport(context.Background(), cfg, imp, nil); err == nil {
		t.Fatal("import error swallowed")
	}
}

type fakeImporter struct {
	got  transfer.Migration
	opts transfer.MigrationOptions
	rep  transfer.MigrationReport
	err  error
}

func (f *fakeImporter) ImportMigration(_ context.Context, m transfer.Migration, _ transfer.MigrationVault, o transfer.MigrationOptions) (transfer.MigrationReport, error) {
	f.got, f.opts = m, o
	return f.rep, f.err
}
