package transfer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-warden/v4/internal/authz"
	"github.com/go-tangra/go-tangra-warden/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
	"github.com/go-tangra/go-tangra-warden/v4/internal/vault"
)

const (
	uC    = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99" // original author
	actor = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4caa" // the operator running the import
)

var (
	t2021 = time.Date(2021, 5, 6, 7, 8, 9, 0, time.UTC)
	t2022 = time.Date(2022, 1, 2, 3, 4, 5, 0, time.UTC)
	t2023 = time.Date(2023, 9, 8, 7, 6, 5, 0, time.UTC)
)

func sp(s string) *string { return &s }

// sampleMigration is a small v3 tenant already mapped onto v4 subjects: a folder
// tree, a secret whose first KV version was destroyed, one with a single
// version at the root, and grants including duplicates and leftovers.
func sampleMigration() Migration {
	future := time.Now().Add(240 * time.Hour)
	past := time.Unix(1_700_000_000, 0).Add(-time.Hour) // the fixture clock
	return Migration{TenantID: tB, ActorID: actor, Source: MigrationSource,
		Folders: []MigFolder{
			{Key: "f-db", ParentKey: sp("f-infra"), Name: "Databases", CreatedAt: t2022, UpdatedAt: t2023, CreatedBy: uC, UpdatedBy: uC},
			{Key: "f-infra", Name: "Infra", CreatedAt: t2021, UpdatedAt: t2022, CreatedBy: uC, UpdatedBy: uA},
		},
		Secrets: []MigSecret{
			{Key: "s-db", FolderKey: sp("f-db"), Name: "prod", Username: "root", HostURL: "https://db.example.org", Description: "primary",
				Metadata: json.RawMessage(`{"env":"prod"}`), TOTP: "otpauth://totp/Acme:root?secret=JBSWY3DPEHPK3PXP&issuer=Acme&digits=8",
				CreatedAt: t2021, UpdatedAt: t2023, CreatedBy: uC, UpdatedBy: uA,
				Versions: []MigVersion{
					{Number: 3, Password: "WARDEN-MARKER-PW-m3", Comment: "rotated", Checksum: secrets.Checksum("WARDEN-MARKER-PW-m3"), CreatedAt: t2023, CreatedBy: uA},
					{Number: 1, Missing: true, Comment: "initial", Checksum: "abc", CreatedAt: t2021, CreatedBy: uC},
					{Number: 2, Password: "WARDEN-MARKER-PW-m2", CreatedAt: t2022, CreatedBy: uC},
				}},
			{Key: "s-root", Name: "root-level", CreatedAt: t2022, CreatedBy: uC,
				Versions: []MigVersion{{Number: 1, Password: "WARDEN-MARKER-PW-r1", Checksum: strings.ToUpper(secrets.Checksum("WARDEN-MARKER-PW-r1")), CreatedAt: t2022, CreatedBy: uC}}},
		},
		Grants: []MigGrant{
			{ResourceType: authz.Folder, ResourceKey: "f-infra", SubjectType: authz.SubjectUser, SubjectID: uC, Relation: authz.Viewer, GrantedAt: t2021, GrantedBy: uC},
			{ResourceType: authz.Folder, ResourceKey: "f-infra", SubjectType: authz.SubjectUser, SubjectID: uC, Relation: authz.Owner, GrantedAt: t2021, GrantedBy: uC}, // stronger duplicate wins
			{ResourceType: authz.Folder, ResourceKey: "f-infra", SubjectType: authz.SubjectTenant, Relation: authz.Viewer, GrantedAt: t2022, GrantedBy: uC},
			{ResourceType: authz.Secret, ResourceKey: "s-db", SubjectType: authz.SubjectRole, SubjectID: "admin", Relation: authz.Editor, GrantedAt: t2022, GrantedBy: uA, ExpiresAt: &future},
			{ResourceType: authz.Secret, ResourceKey: "s-root", SubjectType: authz.SubjectUser, SubjectID: uA, Relation: authz.Owner, GrantedAt: t2022},
			{ResourceType: authz.Secret, ResourceKey: "s-gone", SubjectType: authz.SubjectUser, SubjectID: uA, Relation: authz.Viewer},                   // resource not imported
			{ResourceType: authz.Secret, ResourceKey: "s-root", SubjectType: authz.SubjectUser, SubjectID: uC, Relation: authz.Viewer, ExpiresAt: &past}, // expired
		},
	}
}

func (f *fx) folderByName(name string) store.Folder {
	for _, fo := range f.ms.Folders {
		if fo.Name == name {
			return fo
		}
	}
	return store.Folder{}
}

func (f *fx) secretByName(name string) store.Secret {
	for _, s := range f.ms.Secrets {
		if s.Name == name {
			return s
		}
	}
	return store.Secret{}
}

func noMaterial(t *testing.T, v any) {
	t.Helper()
	raw, _ := json.Marshal(v)
	for _, bad := range []string{"MARKER", "JBSWY3DP", "otpauth"} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("material %q in %s", bad, raw)
		}
	}
}

func TestImportMigrationPreservesHistory(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	rep, err := f.svc.ImportMigration(ctx, sampleMigration(), f.vt, MigrationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	noMaterial(t, rep)
	if rep.Folders.Created != 2 || rep.Secrets.Created != 2 || rep.Versions.Created != 3 || rep.Versions.Skipped != 1 ||
		rep.Grants.Created != 4 || rep.Grants.Skipped != 3 || rep.Grants.Failed != 0 || rep.TOTP.Created != 1 || rep.Verified != 2 || rep.Unowned != 0 || rep.Failed() {
		t.Fatalf("%+v", rep)
	}
	infra, db := f.folderByName("Infra"), f.folderByName("Databases")
	if !infra.CreatedAt.Equal(t2021) || !infra.UpdatedAt.Equal(t2022) || *infra.CreatedBy != uC || *infra.UpdatedBy != uA || infra.ParentID != nil {
		t.Fatalf("infra %+v", infra)
	}
	if *db.ParentID != infra.ID || db.Path != "/Infra/Databases" || len(db.Ancestors) != 1 || !db.CreatedAt.Equal(t2022) {
		t.Fatalf("db %+v", db)
	}
	sec := f.secretByName("prod")
	if *sec.FolderID != db.ID || sec.CurrentVersion != 3 || !sec.HasTOTP || !sec.CreatedAt.Equal(t2021) || !sec.UpdatedAt.Equal(t2023) ||
		*sec.CreatedBy != uC || *sec.UpdatedBy != uA || string(sec.Metadata) != `{"env":"prod"}` || sec.HostURL != "https://db.example.org" {
		t.Fatalf("secret %+v", sec)
	}
	// Version numbers are kept: 1 was destroyed in v3 and stays unreadable.
	vers, _ := f.ms.VersionsOf(ctx, tB, sec.ID)
	if len(vers) != 3 {
		t.Fatalf("%+v", vers)
	}
	for _, v := range vers {
		if v.Source != MigrationSource {
			t.Fatalf("source %+v", v)
		}
		switch v.Version {
		case 1:
			if !v.MaterialMissing || v.Checksum != "abc" || v.Comment != "initial" || !v.CreatedAt.Equal(t2021) || *v.CreatedBy != uC {
				t.Fatalf("v1 %+v", v)
			}
		case 2:
			if v.MaterialMissing || v.Checksum != secrets.Checksum("WARDEN-MARKER-PW-m2") || !v.CreatedAt.Equal(t2022) {
				t.Fatalf("v2 %+v", v)
			}
		case 3:
			if v.MaterialMissing || v.Comment != "rotated" || !v.CreatedAt.Equal(t2023) || *v.CreatedBy != uA {
				t.Fatalf("v3 %+v", v)
			}
		}
	}
	if _, err := f.vt.GetPassword(ctx, tB, sec.ID, 1); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("v1 readable: %v", err)
	}
	for n, want := range map[int]string{2: "WARDEN-MARKER-PW-m2", 3: "WARDEN-MARKER-PW-m3", 0: "WARDEN-MARKER-PW-m3"} {
		if got, _ := f.vt.GetPassword(ctx, tB, sec.ID, n); got != want {
			t.Fatalf("version %d: %q", n, got)
		}
	}
	// The TOTP URL is stored in v4's canonical form with its parameters.
	seed, _ := f.vt.GetTOTP(ctx, tB, sec.ID)
	if !strings.Contains(seed, "secret=JBSWY3DPEHPK3PXP") || !strings.Contains(seed, "digits=8") || !strings.Contains(seed, "issuer=Acme") {
		t.Fatalf("seed %q", seed)
	}
	// Grants: originals only, with their times and granters; the importer gets none.
	var grants []store.Grant
	for _, g := range f.ms.Grants {
		if g.TenantID == tB {
			grants = append(grants, g)
		}
		if g.SubjectID == actor {
			t.Fatalf("importer granted: %+v", g)
		}
	}
	if len(grants) != 4 {
		t.Fatalf("%+v", grants)
	}
	for _, g := range grants {
		if g.ResourceID == infra.ID && g.SubjectType == authz.SubjectUser && (g.Relation != authz.Owner || !g.GrantedAt.Equal(t2021) || *g.GrantedBy != uC) {
			t.Fatalf("folder grant %+v", g)
		}
		if g.SubjectType == authz.SubjectTenant && g.SubjectID != "" {
			t.Fatalf("tenant grant %+v", g)
		}
		if g.SubjectType == authz.SubjectRole && (g.ExpiresAt == nil || g.SubjectID != "admin") {
			t.Fatalf("role grant %+v", g)
		}
		if g.GrantedBy == nil { // no granter in v3 → the importer
			t.Fatalf("granted_by missing %+v", g)
		}
	}
	// uC owns the folder tree, so the history is readable through inheritance.
	if got, err := f.se.Reveal(ctx, authz.Subjects{TenantID: tB, UserID: uC}, sec.ID, 2); err != nil || got.Password != "WARDEN-MARKER-PW-m2" {
		t.Fatalf("reveal v2: %v", err)
	}
	if _, err := f.se.Reveal(ctx, authz.Subjects{TenantID: tB, UserID: uC}, sec.ID, 1); err == nil {
		t.Fatal("missing version revealed")
	}
	ev := f.events(tB, "migration_imported")
	if len(ev) != 1 || ev[0].ActorID != actor || ev[0].SubjectKind != "migration" || !strings.Contains(string(ev[0].Details), `"secrets":2`) {
		t.Fatalf("%+v", ev)
	}
	noMaterial(t, ev)
}

func TestImportMigrationDryRunWritesNothing(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	dry, err := f.svc.ImportMigration(ctx, sampleMigration(), f.vt, MigrationOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !dry.DryRun || len(f.ms.Folders) != 0 || len(f.ms.Secrets) != 0 || len(f.ms.Grants) != 0 || f.vt.Writes() != 0 || len(f.events(tB, "")) != 0 {
		t.Fatalf("dry run wrote: %+v", dry)
	}
	noMaterial(t, dry)
	// The dry run predicts the real counts (verification only happens for real).
	real, err := newFx(t).svc.ImportMigration(ctx, sampleMigration(), vault.NewFake(), MigrationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Folders != real.Folders || dry.Secrets != real.Secrets || dry.Versions != real.Versions || dry.Grants != real.Grants || dry.TOTP != real.TOTP || dry.Verified != 0 {
		t.Fatalf("dry %+v\nreal %+v", dry, real)
	}
}

func TestImportMigrationRefusesExistingData(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	existing, err := f.fo.Create(ctx, carol, nil, "infra") // clashes with "Infra" case-insensitively
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.se.Create(ctx, carol, secrets.Input{FolderID: &existing.ID, Name: "old", Password: "WARDEN-MARKER-PW-old"}); err != nil {
		t.Fatal(err)
	}
	for _, dry := range []bool{true, false} {
		if _, err := f.svc.ImportMigration(ctx, sampleMigration(), f.vt, MigrationOptions{DryRun: dry}); !errors.Is(err, ErrTenantNotEmpty) {
			t.Fatalf("dry=%v: %v", dry, err)
		}
	}
	m := sampleMigration()
	m.Secrets = append(m.Secrets, MigSecret{Key: "s-dup", FolderKey: sp("f-infra"), Name: "OLD", Versions: []MigVersion{{Number: 1, Password: "WARDEN-MARKER-PW-d"}}})
	m.Grants = append(m.Grants, MigGrant{ResourceType: authz.Secret, ResourceKey: "s-dup", SubjectType: authz.SubjectUser, SubjectID: uC, Relation: authz.Owner})
	rep, err := f.svc.ImportMigration(ctx, m, f.vt, MigrationOptions{AllowExisting: true})
	if err != nil {
		t.Fatal(err)
	}
	// "Infra" merges into the existing "infra"; grants on it are not touched.
	if rep.Folders.Created != 1 || rep.Folders.Skipped != 1 || rep.Secrets.Created != 3 || len(rep.NameConflicts) != 2 {
		t.Fatalf("%+v", rep)
	}
	for _, g := range f.ms.Grants {
		if g.ResourceID == existing.ID && g.SubjectID != carol.UserID {
			t.Fatalf("grant on the pre-existing folder: %+v", g)
		}
	}
	if db := f.folderByName("Databases"); *db.ParentID != existing.ID || db.Path != "/infra/Databases" {
		t.Fatalf("%+v", db)
	}
}

func TestImportMigrationValidation(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	long := strings.Repeat("x", 201)
	m := Migration{TenantID: tB, ActorID: actor, Source: MigrationSource,
		Folders: []MigFolder{
			{Key: "bad", Name: strings.Repeat("f", 101)},
			{Key: "child", ParentKey: sp("bad"), Name: "child"},
			{Key: "orphan", ParentKey: sp("nowhere"), Name: "orphan"},
			{Key: "loop1", ParentKey: sp("loop2"), Name: "l1"},
			{Key: "loop2", ParentKey: sp("loop1"), Name: "l2"},
			{Key: "ok", Name: "ok"},
			{Key: "Ok", Name: "OK"}, // duplicate sibling: merged
			{Key: "slash", Name: "a/b"},
		},
		Secrets: []MigSecret{
			{Key: "in-bad", FolderKey: sp("child"), Name: "lost", Versions: []MigVersion{{Number: 1, Password: "p"}}},
			{Key: "long", Name: long, Versions: []MigVersion{{Number: 1, Password: "p"}}},
			{Key: "meta", Name: "meta", Metadata: json.RawMessage(`{"a":"` + strings.Repeat("m", 17<<10) + `"}`), Versions: []MigVersion{{Number: 1, Password: "p"}}},
			{Key: "nomat", Name: "nomat", Versions: []MigVersion{{Number: 1, Missing: true}}},
			{Key: "none", Name: "none"},
			{Key: "bigpw", Name: "bigpw", Versions: []MigVersion{{Number: 1, Password: strings.Repeat("p", secrets.PasswordMax+1)}}},
			{Key: "badnum", Name: "badnum", Versions: []MigVersion{{Number: 0, Password: "p"}}},
			{Key: "totp", FolderKey: sp("Ok"), Name: "totp", TOTP: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=7", Versions: []MigVersion{{Number: 1, Password: "WARDEN-MARKER-PW-t", Comment: strings.Repeat("c", 600)}}},
			{Key: "nullmeta", FolderKey: sp("ok"), Name: "nullmeta", Metadata: json.RawMessage(`null`), Versions: []MigVersion{{Number: 1, Password: "WARDEN-MARKER-PW-n"}}},
			{Key: "dupname", FolderKey: sp("ok"), Name: "NullMeta", Versions: []MigVersion{{Number: 1, Password: "WARDEN-MARKER-PW-n2"}}},
		},
		Grants: []MigGrant{
			{ResourceType: authz.Folder, ResourceKey: "ok", SubjectType: authz.SubjectUser, SubjectID: uC, Relation: "admin"},
			{ResourceType: authz.Folder, ResourceKey: "ok", SubjectType: "group", SubjectID: uC, Relation: authz.Viewer},
		},
	}
	rep, err := f.svc.ImportMigration(ctx, m, f.vt, MigrationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Folders.Created != 1 || rep.Folders.Skipped != 1 || rep.Folders.Failed != 6 {
		t.Fatalf("folders %+v", rep.Folders)
	}
	if rep.Secrets.Created != 3 || rep.Secrets.Failed != 7 || rep.TOTP.Skipped != 1 || rep.Grants.Failed != 2 || !rep.Failed() {
		t.Fatalf("%+v", rep)
	}
	joined := strings.Join(rep.ValidationFailures, "\n")
	for _, want := range []string{"folder name", "parent", "secret fields", "no recoverable password", "version number", "password too long"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in\n%s", want, joined)
		}
	}
	if !strings.Contains(strings.Join(rep.Warnings, "\n"), "comment truncated") || len(rep.NameConflicts) != 2 {
		t.Fatalf("%+v", rep)
	}
	if s := f.secretByName("nullmeta"); string(s.Metadata) != "{}" {
		t.Fatalf("%q", s.Metadata)
	}
	if s := f.secretByName("totp"); s.HasTOTP {
		t.Fatal("invalid seed stored")
	}
	vers, _ := f.ms.VersionsOf(ctx, tB, f.secretByName("totp").ID)
	if len([]rune(vers[0].Comment)) != secrets.CommentMax {
		t.Fatalf("comment %d", len(vers[0].Comment))
	}
	noMaterial(t, rep)
	for _, bad := range []Migration{{TenantID: "nope", ActorID: actor}, {TenantID: tB, ActorID: "nope"}} {
		if _, err := f.svc.ImportMigration(ctx, bad, f.vt, MigrationOptions{}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: %v", bad, err)
		}
	}
}

func TestImportMigrationChecksumMismatch(t *testing.T) {
	f := newFx(t)
	m := sampleMigration()
	m.Secrets[1].Versions[0].Checksum = "deadbeef"
	rep, err := f.svc.ImportMigration(context.Background(), m, f.vt, MigrationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verified != 1 || len(rep.ChecksumMismatches) != 1 || !strings.Contains(rep.ChecksumMismatches[0], "root-level") || !rep.Failed() {
		t.Fatalf("%+v", rep)
	}
	noMaterial(t, rep)
}

func TestImportMigrationCleansUpAfterFailures(t *testing.T) {
	ctx := context.Background()
	for name, arm := range map[string]func(f *fx){
		"vault put":     func(f *fx) { f.vt.FailAfter = 1 },
		"vault skip":    func(f *fx) { f.vt.FailAfter = 1 },
		"vault totp":    func(f *fx) { f.vt.FailAfter = 4 },
		"insert secret": func(f *fx) { f.ms.FailOn("InsertSecret", errors.New("db down")) },
		"insert ver":    func(f *fx) { f.ms.FailOn("InsertVersion", errors.New("db down")) },
		"insert folder": func(f *fx) { f.ms.FailOn("InsertFolder", errors.New("db down")) },
		"upsert grant":  func(f *fx) { f.ms.FailOn("UpsertGrant", errors.New("db down")) },
		"verify":        func(f *fx) {},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFx(t)
			arm(f)
			m := sampleMigration()
			if name == "vault skip" {
				m.Secrets = m.Secrets[:1] // first write is the skip of version 1
			}
			var v MigrationVault = f.vt
			if name == "verify" {
				v = unreadable{f.vt}
			}
			rep, err := f.svc.ImportMigration(ctx, m, v, MigrationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if !rep.Failed() {
				t.Fatalf("%+v", rep)
			}
			// Nothing half-written: every stored secret has a row, every row its material.
			for _, s := range f.ms.Secrets {
				if _, err := f.vt.GetPassword(ctx, tB, s.ID, 0); err != nil {
					t.Fatalf("row without material: %s", s.Name)
				}
			}
			if name != "verify" && name != "upsert grant" && name != "vault totp" {
				for _, v := range f.vt.Dump() {
					if v != "" && !rowFor(f, v) {
						t.Fatalf("orphaned material after %s", name)
					}
				}
			}
		})
	}
}

func rowFor(f *fx, material string) bool {
	for _, s := range f.ms.Secrets {
		for n := 1; n <= s.CurrentVersion; n++ {
			if pw, _ := f.vt.GetPassword(context.Background(), s.TenantID, s.ID, n); pw == material {
				return true
			}
		}
		if seed, _ := f.vt.GetTOTP(context.Background(), s.TenantID, s.ID); seed == material {
			return true
		}
	}
	return false
}

// unreadable accepts writes but cannot read material back.
type unreadable struct{ *vault.Fake }

func (unreadable) GetPassword(context.Context, string, string, int) (string, error) {
	return "", vault.ErrUnavailable
}

func TestImportMigrationStoreErrorsAndRanks(t *testing.T) {
	ctx := context.Background()
	for _, op := range []string{"AllSecrets", "FolderChildren"} {
		f := newFx(t)
		f.ms.FailOn(op, errors.New("db down"))
		if _, err := f.svc.ImportMigration(ctx, sampleMigration(), f.vt, MigrationOptions{}); err == nil {
			t.Fatalf("%s failure ignored", op)
		}
	}
	f := newFx(t)
	m := sampleMigration()
	m.Grants = []MigGrant{
		{ResourceType: authz.Secret, ResourceKey: "s-root", SubjectType: authz.SubjectRole, SubjectID: "ops", Relation: authz.Viewer},
		{ResourceType: authz.Secret, ResourceKey: "s-root", SubjectType: authz.SubjectRole, SubjectID: "ops", Relation: authz.Sharer},
		{ResourceType: authz.Secret, ResourceKey: "s-root", SubjectType: authz.SubjectRole, SubjectID: "ops", Relation: authz.Editor},
		{ResourceType: authz.Secret, ResourceKey: "s-root", SubjectType: authz.SubjectRole, SubjectID: "ops", Relation: authz.Sharer},
		{ResourceType: authz.Folder, ResourceKey: "f-infra", SubjectType: authz.SubjectTenant, SubjectID: "all", Relation: authz.Viewer},
	}
	rep, err := f.svc.ImportMigration(ctx, m, f.vt, MigrationOptions{})
	if err != nil || rep.Grants.Created != 2 || rep.Grants.Skipped != 3 || rep.Unowned != 4 {
		t.Fatalf("%+v %v", rep, err)
	}
	for _, g := range f.ms.Grants {
		if (g.SubjectID == "ops" && g.Relation != authz.Editor) || (g.SubjectType == authz.SubjectTenant && g.SubjectID != "") {
			t.Fatalf("%+v", g)
		}
	}
}
