package migrate3

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-warden/v4/internal/transfer"
)

const (
	v4Tenant = "00000000-0000-0000-0000-000000000001"
	uAlice   = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"
	uOps     = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c88"
)

func TestParseUsers(t *testing.T) {
	u, err := ParseUsers(strings.NewReader("email,id\nAlice@Example.org," + uAlice + "\n\nops@example.org," + uOps + "\n"))
	if err != nil || u["alice@example.org"] != uAlice || u["ops@example.org"] != uOps || len(u) != 2 {
		t.Fatal(u, err)
	}
	for name, in := range map[string]string{
		"bad uuid":   "a@example.org,nope\n",
		"columns":    "a@example.org\n",
		"no email":   "," + uAlice + "\n",
		"conflict":   "a@example.org," + uAlice + "\nA@example.org," + uOps + "\n",
		"bad csv":    "\"a@example.org," + uAlice + "\n",
		"header mid": "a@example.org," + uAlice + "\nemail,id\n",
	} {
		if _, err := ParseUsers(strings.NewReader(in)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// The same pair twice is harmless.
	if _, err := ParseUsers(strings.NewReader("a@example.org," + uAlice + "\na@example.org," + uAlice + "\n")); err != nil {
		t.Fatal(err)
	}
}

func TestParseRoleMap(t *testing.T) {
	m, err := ParseRoleMap(" platform:admin=admin, 1=admin ,ops=operator")
	if err != nil || m["platform:admin"] != "admin" || m["1"] != "admin" || m["ops"] != "operator" {
		t.Fatal(m, err)
	}
	if m, err := ParseRoleMap(""); err != nil || len(m) != 0 {
		t.Fatal(m, err)
	}
	for _, bad := range []string{"admin", "=admin", "a=", "a=b c", "a=b,a=c"} {
		if _, err := ParseRoleMap(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func mappingBundle() *Bundle {
	ts := time.Date(2022, 2, 2, 2, 2, 2, 0, time.UTC)
	fid := "f1"
	return &Bundle{Format: Format, Version: FormatVersion,
		Folders: []Folder{{ID: fid, Name: "Infra", Path: "/Infra", Description: "dropped", CreatedAt: &ts, UpdatedAt: &ts, CreatedBy: "ALICE@example.org"}},
		Secrets: []Secret{
			{ID: "s1", FolderID: &fid, Name: "db", Status: "active", TOTPURL: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", CreatedAt: &ts, CreatedBy: "alice@example.org", UpdatedBy: "gone@example.org",
				Versions: []Version{{Version: 1, Missing: true, Checksum: "c1", CreatedAt: &ts}, {Version: 2, Password: "WARDEN-MARKER-PW-2", Checksum: "c2", CreatedBy: "ops@example.org"}}},
			{ID: "s2", Name: "archived", Status: "archived", Versions: []Version{{Version: 1, Password: "p", ChecksumMismatch: true}}},
			{ID: "s3", Name: "deleted", Status: "deleted", Versions: []Version{{Version: 1, Password: "p"}}},
		},
		Grants: []Grant{
			{ResourceType: "folder", ResourceID: fid, SubjectType: "user", Subject: "Alice@example.org", SubjectV3: "7", Relation: "owner", GrantedAt: &ts, GrantedBy: "ops@example.org"},
			{ResourceType: "folder", ResourceID: fid, SubjectType: "user", Subject: "gone@example.org", SubjectV3: "9", Relation: "viewer"},
			{ResourceType: "folder", ResourceID: fid, SubjectType: "user", Subject: "", SubjectV3: "10", Relation: "viewer"},
			{ResourceType: "secret", ResourceID: "s1", SubjectType: "role", Subject: "platform:admin", SubjectV3: "platform:admin", Relation: "editor"},
			{ResourceType: "secret", ResourceID: "s1", SubjectType: "role", Subject: "1", SubjectV3: "1", Relation: "viewer"},
			{ResourceType: "secret", ResourceID: "s2", SubjectType: "role", Subject: "auditor", SubjectV3: "auditor", Relation: "viewer"},
			{ResourceType: "secret", ResourceID: "s2", SubjectType: "tenant", Subject: "all", SubjectV3: "all", Relation: "viewer"},
			{ResourceType: "secret", ResourceID: "s2", SubjectType: "group", Subject: "x", Relation: "viewer"},
		},
		Warnings: []string{"export warning"},
	}
}

func TestMap(t *testing.T) {
	users := Users{"alice@example.org": uAlice, "ops@example.org": uOps}
	roles := RoleMap{"platform:admin": "admin", "1": "admin"}
	m, rep, err := Map(mappingBundle(), v4Tenant, users, roles, "OPS@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if m.TenantID != v4Tenant || m.ActorID != uOps || m.Source != transfer.MigrationSource || len(m.Folders) != 1 || len(m.Secrets) != 3 {
		t.Fatalf("%+v", m)
	}
	f := m.Folders[0]
	if f.CreatedBy != uAlice || f.UpdatedBy != uAlice || f.CreatedAt.IsZero() || f.ParentKey != nil {
		t.Fatalf("%+v", f)
	}
	s := m.Secrets[0]
	if *s.FolderKey != "f1" || s.CreatedBy != uAlice || s.UpdatedBy != "" || s.TOTP == "" || len(s.Versions) != 2 ||
		!s.Versions[0].Missing || s.Versions[0].Checksum != "c1" || s.Versions[1].CreatedBy != uOps || s.Versions[1].Password != "WARDEN-MARKER-PW-2" {
		t.Fatalf("%+v", s)
	}
	if len(m.Grants) != 4 {
		t.Fatalf("%+v", m.Grants)
	}
	want := map[string]bool{"user|" + uAlice + "|owner": true, "role|admin|editor": true, "role|admin|viewer": true, "tenant||viewer": true}
	for _, g := range m.Grants {
		if !want[g.SubjectType+"|"+g.SubjectID+"|"+g.Relation] {
			t.Fatalf("unexpected %+v", g)
		}
		if g.SubjectType == "user" && (g.GrantedBy != uOps || g.GrantedAt.IsZero()) {
			t.Fatalf("%+v", g)
		}
	}
	if rep.UnmappedUsers["gone@example.org"] != 1 || rep.UnmappedRoles["auditor"] != 1 || rep.UnknownSubjects != 1 || rep.InvalidGrants != 1 ||
		rep.AuthorFallbacks == 0 || rep.ArchivedSecrets != 1 || rep.DeletedSecrets != 1 || rep.DroppedDescriptions != 1 ||
		rep.ExportChecksumMismatches != 1 || len(rep.ExportWarnings) != 1 {
		t.Fatalf("%+v", rep)
	}
	if _, _, err := Map(mappingBundle(), v4Tenant, users, roles, "nobody@example.org"); !errors.Is(err, ErrActor) {
		t.Fatal(err)
	}
	if _, _, err := Map(mappingBundle(), "not-a-uuid", users, roles, "ops@example.org"); err == nil {
		t.Fatal("bad tenant accepted")
	}
}
