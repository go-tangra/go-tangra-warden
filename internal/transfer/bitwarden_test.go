package transfer

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/services/warden/internal/audit"
	"github.com/go-freya/freya/services/warden/internal/authz"
	"github.com/go-freya/freya/services/warden/internal/folders"
	"github.com/go-freya/freya/services/warden/internal/memstore"
	"github.com/go-freya/freya/services/warden/internal/secrets"
	"github.com/go-freya/freya/services/warden/internal/store"
	"github.com/go-freya/freya/services/warden/internal/vault"
)

const (
	tA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	uA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"
	uB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c88"
)

var (
	alice = authz.Subjects{TenantID: tA, UserID: uA, Roles: []string{"member"}}
	bob   = authz.Subjects{TenantID: tA, UserID: uB}
)

type fx struct {
	ms  *memstore.Store
	vt  *vault.Fake
	aw  *audit.Writer
	fo  *folders.Service
	se  *secrets.Service
	az  *authz.Authz
	svc *Service
}

func newFx(t *testing.T) *fx {
	t.Helper()
	ms := memstore.New()
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	az := authz.New(ms, aw)
	vt := vault.NewFake()
	se := secrets.New(ms, vt, az, aw)
	fo := folders.New(ms, az, aw, se)
	svc := New(ms, fo, se, az, aw)
	svc.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	return &fx{ms: ms, vt: vt, aw: aw, fo: fo, se: se, az: az, svc: svc}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../tests/testdata/bitwarden/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fx) events(tenant, typ string) []store.AuditRow {
	f.aw.Flush()
	return f.ms.AuditEvents(tenant, typ)
}

func TestDecodeBounds(t *testing.T) {
	if _, err := ParseBitwarden([]byte(`{"encrypted":true,"items":[]}`)); !errors.Is(err, ErrInvalid) {
		t.Fatal("encrypted accepted")
	}
	if _, err := ParseBitwarden([]byte(`{"encrypted":false,"items":[`)); !errors.Is(err, ErrMalformed) {
		t.Fatal("malformed accepted")
	}
	if _, err := ParseBitwarden([]byte(`{"encrypted":false,"items":[],"x":` + strings.Repeat("[", 20) + strings.Repeat("]", 20) + `}`)); !errors.Is(err, ErrTooDeep) {
		t.Fatal("deep accepted")
	}
	if _, err := ParseBitwarden([]byte(`{"encrypted":false,"items":[],"folders":[{"id":"a","name":""}]}`)); !errors.Is(err, ErrInvalid) {
		t.Fatal("blank folder accepted")
	}
	if _, err := ParseBitwarden([]byte(`{"encrypted":false,"items":[],"folders":[{"id":"a","name":"x"}]} trailing`)); !errors.Is(err, ErrMalformed) {
		t.Fatal("trailing accepted")
	}
	big := make([]byte, MaxBytes+1)
	if _, err := ParseBitwarden(big); !errors.Is(err, ErrTooLarge) {
		t.Fatal("large accepted")
	}
	if _, err := ReadBounded(strings.NewReader("abc"), 2); !errors.Is(err, ErrTooLarge) {
		t.Fatal("bounded reader")
	}
	if b, err := ReadBounded(strings.NewReader("abc"), 3); err != nil || string(b) != "abc" {
		t.Fatal("bounded reader ok")
	}
	if _, err := ReadBounded(failingReader{}, 10); !errors.Is(err, ErrMalformed) {
		t.Fatal("reader error")
	}
	if d, err := Depth([]byte(`{"a":[1,{"b":2}]}`)); err != nil || d != 3 {
		t.Fatalf("depth %d %v", d, err)
	}
	if _, err := Depth([]byte(`{"a":`)); err == nil {
		t.Fatal("unbalanced")
	}
	if _, err := Depth([]byte(`{"a":1}}`)); err == nil {
		t.Fatal("extra close")
	}
	var v struct{ A int }
	if err := DecodeBounded([]byte(`{"A":"x"}`), &v); !errors.Is(err, ErrMalformed) {
		t.Fatal("type mismatch")
	}
	items := make([]string, MaxItems+1)
	for i := range items {
		items[i] = `{"type":1,"name":"x"}`
	}
	if _, err := ParseBitwarden([]byte(`{"encrypted":false,"items":[` + strings.Join(items, ",") + `]}`)); !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrTooLarge) {
		t.Fatalf("too many items: %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestValidateSample(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	target, _ := f.fo.Create(ctx, alice, nil, "Vault")
	// Two existing names collide: one in the mapped folder, one at the target root.
	team0, _ := f.fo.Create(ctx, alice, &target.ID, "Imported")
	t0, _ := f.fo.Create(ctx, alice, &team0.ID, "Team 0")
	if _, err := f.se.Create(ctx, alice, secrets.Input{FolderID: &t0.ID, Name: "service 000", Password: "x"}); err != nil {
		t.Fatal(err)
	}
	rep, err := f.svc.ValidateBitwarden(ctx, alice, fixture(t, "sample"), &target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Items != 20 || rep.Folders != 4 || rep.Skipped != 2 || len(rep.Problems) != 0 {
		t.Fatalf("%+v", rep)
	}
	if len(rep.Collisions) != 1 || rep.Collisions[0].Name != "Service 000" || rep.Collisions[0].Folder != "/Imported/Team 0" {
		t.Fatalf("collisions %+v", rep.Collisions)
	}
	if !strings.Contains(strings.Join(rep.Warnings, "\n"), "not a login") || !strings.Contains(strings.Join(rep.Warnings, "\n"), "totp seed not recognised") {
		t.Fatalf("warnings %v", rep.Warnings)
	}
	// Nothing was written; the validation is audited.
	if len(f.ms.Secrets) != 1 || len(f.ms.Folders) != 3 {
		t.Fatal("validation wrote")
	}
	if len(f.events(tA, "transfer_validated")) != 1 {
		t.Fatal("audit")
	}
	// Permission on the target and duplicates within the file.
	if _, err := f.svc.ValidateBitwarden(ctx, bob, fixture(t, "sample"), &target.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("bob: %v", err)
	}
	dup := `{"encrypted":false,"items":[{"type":1,"name":"Same","login":{"password":"a"}},{"type":1,"name":"same","login":{"password":"b"}}]}`
	rep, _ = f.svc.ValidateBitwarden(ctx, alice, []byte(dup), nil)
	if len(rep.Collisions) != 1 || rep.Collisions[0].Folder != "/" {
		t.Fatalf("in-file duplicate %+v", rep)
	}
	// Nested fixture: deep paths, trimmed names, invalid folder names dropped, problems reported.
	rep, err = f.svc.ValidateBitwarden(ctx, alice, fixture(t, "nested"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Folders != 14 || len(rep.Problems) != 3 {
		t.Fatalf("%+v", rep)
	}
	reasons := map[string]bool{}
	for _, p := range rep.Problems {
		reasons[p.Reason] = true
	}
	for _, want := range []string{"missing password", "unknown folder", "invalid name"} {
		if !reasons[want] {
			t.Fatalf("missing problem %q in %v", want, rep.Problems)
		}
	}
	if _, err := f.svc.ValidateBitwarden(ctx, alice, []byte(`{`), nil); !errors.Is(err, ErrMalformed) {
		t.Fatal("malformed")
	}
	f.ms.FailOn("FolderChildren", errors.New("db"))
	if _, err := f.svc.ValidateBitwarden(ctx, alice, fixture(t, "sample"), &target.ID); err == nil {
		t.Fatal("db error swallowed")
	}
	f.ms.FailOn("FolderChildren", nil)
}

func TestImportStrategies(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	target, _ := f.fo.Create(ctx, alice, nil, "Vault")
	// Pre-existing collision at /Imported/Team 0/Service 000.
	imp, _ := f.fo.Create(ctx, alice, &target.ID, "Imported")
	t0, _ := f.fo.Create(ctx, alice, &imp.ID, "Team 0")
	existing, _ := f.se.Create(ctx, alice, secrets.Input{FolderID: &t0.ID, Name: "Service 000", Username: "old", Password: "old"})
	if _, err := f.svc.ImportBitwarden(ctx, alice, fixture(t, "sample"), &target.ID, "merge"); !errors.Is(err, ErrInvalid) {
		t.Fatal("unknown strategy")
	}
	rep, err := f.svc.ImportBitwarden(ctx, alice, fixture(t, "sample"), &target.ID, Rename)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Created != 19 || rep.Renamed != 1 || rep.Skipped != 2 || rep.Failed != 0 {
		t.Fatalf("%+v", rep)
	}
	// Folders reused/created under the target, renamed item present, history became versions oldest first.
	var renamed *secrets.View
	all, _ := f.se.Readable(ctx, alice, &target.ID, 0)
	for i := range all {
		if all[i].Name == "Service 000 (2)" {
			renamed = &all[i]
		}
	}
	if renamed == nil || renamed.FolderPath != "/Vault/Imported/Team 0" {
		t.Fatalf("renamed %+v", renamed)
	}
	// Item 0 carries history (two older passwords), a seed and custom fields.
	vs, _ := f.se.Versions(ctx, alice, renamed.ID)
	if len(vs) != 3 || vs[0].Version != 3 || vs[0].Source != "import" || !vs[0].Current {
		t.Fatalf("history %+v", vs)
	}
	if m, _ := f.se.Reveal(ctx, alice, renamed.ID, 1); m.Password != "WARDEN-MARKER-PW-bw-older-0000" {
		t.Fatalf("oldest first: %s", m.Password)
	}
	if m, _ := f.se.Reveal(ctx, alice, renamed.ID, 0); m.Password != "WARDEN-MARKER-PW-bw-0000" {
		t.Fatalf("current last: %s", m.Password)
	}
	if !renamed.HasTOTP || !strings.Contains(string(renamed.Metadata), `"env":"prod"`) || !strings.Contains(string(renamed.Metadata), `"favorite":true`) {
		t.Fatalf("totp/metadata %+v", renamed)
	}
	// Skip leaves everything alone on a second run; overwrite adds versions to the collisions.
	rep, _ = f.svc.ImportBitwarden(ctx, alice, fixture(t, "sample"), &target.ID, Skip)
	if rep.Skipped != 22 || rep.Created != 0 {
		t.Fatalf("skip %+v", rep)
	}
	rep, _ = f.svc.ImportBitwarden(ctx, alice, fixture(t, "sample"), &target.ID, Overwrite)
	if rep.Overwritten != 20 || rep.Created != 0 {
		t.Fatalf("overwrite %+v", rep)
	}
	ex, _ := f.se.Get(ctx, alice, existing.ID)
	if ex.Username != "user0" || ex.CurrentVersion != 2 {
		t.Fatalf("overwritten %+v", ex)
	}
	if vs, _ := f.se.Versions(ctx, alice, existing.ID); vs[0].Source != "overwrite" {
		t.Fatalf("%+v", vs[0])
	}
	if len(f.events(tA, "transfer_imported")) != 3 {
		t.Fatal("audit")
	}
	// Failures: vault down mid-import counts problems; a broken folder counts failed.
	f.vt.Down = true
	rep, _ = f.svc.ImportBitwarden(ctx, alice, fixture(t, "nested"), nil, Rename)
	if rep.Failed == 0 || len(rep.Problems) < 3 {
		t.Fatalf("vault down %+v", rep)
	}
	f.vt.Down = false
	f.vt.FailAfter = f.vt.Writes() + 2
	rep, _ = f.svc.ImportBitwarden(ctx, alice, []byte(`{"encrypted":false,"items":[{"type":1,"name":"H","login":{"password":"c"},"passwordHistory":[{"lastUsedDate":"1","password":"a"},{"lastUsedDate":"2","password":"b"}]}]}`), nil, Rename)
	if rep.Created != 1 || len(rep.Warnings) == 0 {
		t.Fatalf("history failure %+v", rep)
	}
	f.vt.FailAfter = 0
	f.ms.FailOn("InsertFolder", errors.New("db"))
	rep, _ = f.svc.ImportBitwarden(ctx, alice, []byte(`{"encrypted":false,"folders":[{"id":"x","name":"New"}],"items":[{"type":1,"name":"I","folderId":"x","login":{"password":"c"}}]}`), nil, Rename)
	if rep.Failed != 1 || rep.Created != 1 {
		t.Fatalf("folder failure %+v", rep)
	}
	f.ms.FailOn("InsertFolder", nil)
	// Overwrite failing (vault down) and a target the caller cannot write.
	f.vt.Down = true
	rep, _ = f.svc.ImportBitwarden(ctx, alice, fixture(t, "sample"), &target.ID, Overwrite)
	if rep.Failed != 20 {
		t.Fatalf("overwrite failures %+v", rep)
	}
	f.vt.Down = false
	if _, err := f.svc.ImportBitwarden(ctx, bob, fixture(t, "sample"), &target.ID, Rename); !errors.Is(err, authz.ErrForbidden) {
		t.Fatal("bob import")
	}
	if _, err := f.svc.ImportBitwarden(ctx, alice, []byte(`nope`), nil, Rename); !errors.Is(err, ErrMalformed) {
		t.Fatal("malformed import")
	}
	// The root-of-tenant listing failing during preparation.
	f.ms.FailOn("SecretsInFolder", errors.New("db"))
	if _, err := f.svc.ImportBitwarden(ctx, alice, fixture(t, "sample"), nil, Rename); err == nil {
		t.Fatal("prepare db error")
	}
	f.ms.FailOn("SecretsInFolder", nil)
}

func TestExportBitwarden(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	target, _ := f.fo.Create(ctx, alice, nil, "Vault")
	rep, err := f.svc.ImportBitwarden(ctx, alice, fixture(t, "sample"), &target.ID, Rename)
	if err != nil || rep.Created != 20 {
		t.Fatalf("%+v %v", rep, err)
	}
	doc, err := f.svc.ExportBitwarden(ctx, alice, &target.ID)
	if err != nil || len(doc.Items) != 20 || len(doc.Folders) != 3 || doc.Encrypted {
		t.Fatalf("%d items %d folders %v", len(doc.Items), len(doc.Folders), err)
	}
	var withTotp, withFields int
	for _, it := range doc.Items {
		if it.Login == nil || it.Login.Password == nil || !strings.HasPrefix(*it.Login.Password, "WARDEN-MARKER-PW-bw-") {
			t.Fatalf("material missing: %+v", it)
		}
		if it.Login.TOTP != nil {
			withTotp++
		}
		if len(it.Fields) > 0 {
			withFields++
		}
	}
	if withTotp != 3 || withFields != 9 { // items 0,5,15 carry a valid seed; fields on i%3==0 plus favourites
		t.Fatalf("totp %d fields %d", withTotp, withFields)
	}
	// The export re-validates cleanly into another folder and round-trips counts.
	raw, _ := json.Marshal(doc)
	other, _ := f.fo.Create(ctx, alice, nil, "Other")
	rv, err := f.svc.ValidateBitwarden(ctx, alice, raw, &other.ID)
	if err != nil || rv.Items != 20 || len(rv.Problems) != 0 || len(rv.Collisions) != 0 {
		t.Fatalf("%+v %v", rv, err)
	}
	// Everything readable when no folder is given; bob sees nothing; audited as a bulk disclosure with the count.
	all, _ := f.svc.ExportBitwarden(ctx, alice, nil)
	if len(all.Items) != 20 {
		t.Fatalf("all %d", len(all.Items))
	}
	none, err := f.svc.ExportBitwarden(ctx, bob, nil)
	if err != nil || len(none.Items) != 0 {
		t.Fatalf("bob %v %v", none, err)
	}
	if _, err := f.svc.ExportBitwarden(ctx, bob, &target.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatal("bob folder export")
	}
	ev := f.events(tA, "transfer_exported")
	if len(ev) != 3 || !strings.Contains(string(ev[0].Details), `"count":20`) || strings.Contains(string(ev[0].Details), "MARKER") {
		t.Fatalf("%+v", ev)
	}
	f.vt.Down = true
	if _, err := f.svc.ExportBitwarden(ctx, alice, &target.ID); !errors.Is(err, secrets.ErrVaultUnavailable) {
		t.Fatal("vault down export")
	}
	f.vt.Down = false
	f.ms.FailOn("SecretsInFolders", errors.New("db"))
	if _, err := f.svc.ExportBitwarden(ctx, alice, nil); err == nil {
		t.Fatal("db error")
	}
	f.ms.FailOn("SecretsInFolders", nil)
}
