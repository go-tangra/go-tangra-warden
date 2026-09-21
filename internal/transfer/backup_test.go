package transfer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/services/warden/internal/authz"
	"github.com/go-freya/freya/services/warden/internal/secrets"
)

const tB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"

var carol = authz.Subjects{TenantID: tB, UserID: uB, Roles: []string{"owner"}}

func seed(t *testing.T, f *fx) (secretID string) {
	t.Helper()
	ctx := context.Background()
	infra, _ := f.fo.Create(ctx, alice, nil, "Infra")
	db, _ := f.fo.Create(ctx, alice, &infra.ID, "Databases")
	v, err := f.se.Create(ctx, alice, secrets.Input{FolderID: &db.ID, Name: "prod", Username: "root", Metadata: json.RawMessage(`{"env":"prod"}`), Password: "WARDEN-MARKER-PW-b1", TOTP: "JBSWY3DPEHPK3PXP"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.se.UpdatePassword(ctx, alice, v.ID, "WARDEN-MARKER-PW-b2", "rotated"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.se.Create(ctx, alice, secrets.Input{Name: "root-secret", Password: "WARDEN-MARKER-PW-b3"}); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(48 * time.Hour)
	if _, err := f.az.Grant(ctx, alice, authz.GrantInput{ResourceType: "folder", ResourceID: infra.ID, SubjectType: "role", SubjectID: "ops", Relation: "viewer", ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}
	return v.ID
}

func TestBackupExportImport(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	seed(t, f)
	// Without material: no passwords or seeds anywhere.
	plain, err := f.svc.ExportBackup(ctx, alice, false, f.vt)
	if err != nil || len(plain.Folders) != 2 || len(plain.Secrets) != 2 || len(plain.Versions) != 3 || len(plain.Grants) != 5 || plain.WithMaterial {
		t.Fatalf("%+v %v", plain, err)
	}
	raw, _ := json.Marshal(plain)
	if strings.Contains(string(raw), "MARKER") || strings.Contains(string(raw), "JBSWY3DP") {
		t.Fatal("material in a plain backup")
	}
	// With material: every version carries its password, the secret its seed.
	full, err := f.svc.ExportBackup(ctx, alice, true, f.vt)
	if err != nil || !full.WithMaterial {
		t.Fatal(err)
	}
	for _, v := range full.Versions {
		if !strings.HasPrefix(v.Password, "WARDEN-MARKER-PW-") {
			t.Fatalf("version without material: %+v", v)
		}
	}
	if full.Secrets[0].Seed == "" && full.Secrets[1].Seed == "" {
		t.Fatal("seed missing")
	}
	ev := f.events(tA, "backup_exported")
	if len(ev) != 2 || !strings.Contains(string(ev[1].Details), `"with_material":true`) || strings.Contains(string(ev[1].Details), "MARKER") {
		t.Fatalf("%+v", ev)
	}
	// Import with material into an empty tenant reproduces everything with new ids.
	raw, _ = json.Marshal(full)
	rep, err := f.svc.ImportBackup(ctx, carol, raw, f.vt)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Folders.Created != 2 || rep.Secrets.Created != 2 || rep.Versions.Created != 3 || rep.Grants.Created != 5 || len(rep.Warnings) != 0 {
		t.Fatalf("%+v", rep)
	}
	tree, _ := f.fo.Tree(ctx, carol)
	if len(tree) != 1 || tree[0].Folder.Path != "/Infra" || len(tree[0].Children) != 1 || tree[0].Children[0].Folder.Path != "/Infra/Databases" {
		t.Fatalf("%+v", tree)
	}
	all, _ := f.se.Readable(ctx, carol, nil, 0)
	if len(all) != 2 {
		t.Fatalf("secrets %d", len(all))
	}
	for _, v := range all {
		if v.Name == "prod" {
			if v.CurrentVersion != 2 || !v.HasTOTP || !strings.Contains(string(v.Metadata), "prod") || v.FolderPath != "/Infra/Databases" {
				t.Fatalf("%+v", v)
			}
			if m, _ := f.se.Reveal(ctx, carol, v.ID, 0); m.Password != "WARDEN-MARKER-PW-b2" {
				t.Fatalf("material %+v", m)
			}
			if m, _ := f.se.Reveal(ctx, carol, v.ID, 1); m.Password != "WARDEN-MARKER-PW-b1" {
				t.Fatalf("material v1 %+v", m)
			}
			if c, err := f.se.TOTPCode(ctx, carol, v.ID); err != nil || len(c.Code) != 6 {
				t.Fatalf("totp %v", err)
			}
			vs, _ := f.se.Versions(ctx, carol, v.ID)
			if vs[0].Source != "backup" || vs[0].Missing || vs[1].Comment != "" {
				t.Fatalf("%+v", vs)
			}
		}
	}
	// Ids were remapped: none of the original ids exist in tenant B.
	for _, s := range full.Secrets {
		if _, ok := f.ms.Secrets[s.ID]; ok && f.ms.Secrets[s.ID].TenantID == tB {
			t.Fatal("id reused")
		}
	}
	// Grants kept: the ops role grant with its expiry, alice's owner grants by user id.
	var roleGrants, aliceGrants int
	for _, g := range f.ms.Grants {
		if g.TenantID == tB && g.SubjectType == "role" && g.SubjectID == "ops" && g.ExpiresAt != nil {
			roleGrants++
		}
		if g.TenantID == tB && g.SubjectID == uA {
			aliceGrants++
		}
	}
	if roleGrants != 1 || aliceGrants != 4 {
		t.Fatalf("grants role %d alice %d", roleGrants, aliceGrants)
	}
	if len(f.events(tB, "backup_imported")) != 1 {
		t.Fatal("import audit")
	}
	// Importing the plain backup: versions recorded as material_missing, seed flagged missing, siblings reused.
	rawPlain, _ := json.Marshal(plain)
	rep, err = f.svc.ImportBackup(ctx, carol, rawPlain, f.vt)
	if err != nil || rep.Folders.Skipped != 2 || rep.Secrets.Created != 2 || rep.Versions.Created != 3 {
		t.Fatalf("%+v %v", rep, err)
	}
	if !strings.Contains(strings.Join(rep.Warnings, "\n"), "seed missing") {
		t.Fatalf("warnings %v", rep.Warnings)
	}
	missing := 0
	for _, vs := range f.ms.Versions {
		for _, v := range vs {
			if v.TenantID == tB && v.MaterialMissing {
				missing++
			}
		}
	}
	if missing != 3 {
		t.Fatalf("material_missing %d", missing)
	}
}

func TestBackupRefusalsAndFailures(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	seed(t, f)
	full, _ := f.svc.ExportBackup(ctx, alice, true, f.vt)
	raw, _ := json.Marshal(full)
	for name, bad := range map[string]string{
		"schema":   strings.Replace(string(raw), `"schema_version":1`, `"schema_version":2`, 1),
		"module":   strings.Replace(string(raw), `"module":"warden"`, `"module":"other"`, 1),
		"garbage":  `{"module":"warden","schema_version":1,"folders":[`,
		"too many": `{"module":"warden","schema_version":1,"grants":[` + strings.Repeat(`{},`, MaxItems*4) + `{}]}`,
	} {
		if _, err := f.svc.ImportBackup(ctx, carol, []byte(bad), f.vt); !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Dangling references and invalid entities are reported, not fatal.
	broken := full
	broken.Folders = append(broken.Folders, BackupFolder{ID: "dangling", ParentID: strp("nope"), Name: "X", Path: "/?/X"})
	broken.Secrets = append(broken.Secrets, BackupSecret{ID: "s-bad", Name: "", Metadata: json.RawMessage(`[]`)}, BackupSecret{ID: "s-orphan", FolderID: strp("nope"), Name: "orphan", HasTOTP: true})
	past := time.Unix(1, 0)
	broken.Grants = append(broken.Grants, BackupGrant{ResourceType: "secret", ResourceID: "s-orphan", SubjectType: "user", SubjectID: uA, Relation: "viewer", ExpiresAt: &past},
		BackupGrant{ResourceType: "secret", ResourceID: "missing", SubjectType: "user", SubjectID: uA, Relation: "viewer"},
		BackupGrant{ResourceType: "secret", ResourceID: "s-orphan", SubjectType: "group", SubjectID: uA, Relation: "viewer"})
	rawBroken, _ := json.Marshal(broken)
	rep, err := f.svc.ImportBackup(ctx, carol, rawBroken, f.vt)
	if err != nil || rep.Folders.Failed != 1 || rep.Secrets.Failed != 1 || rep.Secrets.Created != 3 || rep.Grants.Skipped != 3 {
		t.Fatalf("%+v %v", rep, err)
	}
	joined := strings.Join(rep.Warnings, "\n")
	for _, w := range []string{"parent missing", "invalid fields", "placed at the root", "no versions", "seed missing"} {
		if !strings.Contains(joined, w) {
			t.Fatalf("warning %q missing in %v", w, rep.Warnings)
		}
	}
	// Vault down during import: versions fall back to material_missing, seeds warn.
	f.vt.Down = true
	rep, err = f.svc.ImportBackup(ctx, authz.Subjects{TenantID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99", UserID: uB}, raw, f.vt)
	if err != nil || rep.Versions.Failed != 3 || rep.Versions.Created != 3 {
		t.Fatalf("%+v %v", rep, err)
	}
	if !strings.Contains(strings.Join(rep.Warnings, "\n"), "seed not stored") {
		t.Fatalf("%v", rep.Warnings)
	}
	// Export failures: vault down and store errors.
	if _, err := f.svc.ExportBackup(ctx, alice, true, f.vt); !errors.Is(err, secrets.ErrVaultUnavailable) && err == nil {
		t.Fatal("vault down export")
	}
	f.vt.Down = false
	for _, op := range []string{"AllFolders", "AllSecrets", "VersionsOf", "GrantsOnResources"} {
		f.ms.FailOn(op, errors.New("db"))
		if _, err := f.svc.ExportBackup(ctx, alice, false, f.vt); err == nil {
			t.Fatalf("%s", op)
		}
		f.ms.FailOn(op, nil)
	}
	if n := len(f.events(tA, "backup_exported")); n < 5 {
		t.Fatalf("failed exports audited: %d", n)
	}
	// Import store failures per entity.
	tenantC := authz.Subjects{TenantID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4caa", UserID: uB}
	for _, op := range []string{"InsertFolder", "InsertSecret", "InsertVersion", "UpsertGrant", "SetSecretVersion", "SetSecretTOTP"} {
		f.ms.FailOn(op, errors.New("db"))
		rep, err := f.svc.ImportBackup(ctx, tenantC, raw, f.vt)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if rep.Folders.Failed+rep.Secrets.Failed+rep.Versions.Failed+rep.Grants.Failed+len(rep.Warnings) == 0 {
			t.Fatalf("%s: nothing reported %+v", op, rep)
		}
		f.ms.FailOn(op, nil)
		// Fresh tenant per attempt so siblings do not collide.
		tenantC.TenantID = tenantC.TenantID[:35] + string(rune('b'+len(op)%5))
	}
	// A parent folder vanishing between creation and lookup.
	f.ms.FailOn("GetFolder", errors.New("db"))
	rep, _ = f.svc.ImportBackup(ctx, authz.Subjects{TenantID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4cdd", UserID: uB}, raw, f.vt)
	if rep.Folders.Failed != 1 {
		t.Fatalf("%+v", rep)
	}
	f.ms.FailOn("GetFolder", nil)
	// When the sibling lookup fails the existing folder cannot be reused: its children lose their parent.
	f.ms.FailOn("FolderChildren", errors.New("db"))
	rep, _ = f.svc.ImportBackup(ctx, carol, raw, f.vt)
	if rep.Folders.Skipped != 1 || rep.Folders.Failed != 1 {
		t.Fatalf("%+v", rep)
	}
	f.ms.FailOn("FolderChildren", nil)
}
