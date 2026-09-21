package share

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/services/warden/internal/audit"
	"github.com/go-freya/freya/services/warden/internal/authz"
	"github.com/go-freya/freya/services/warden/internal/memstore"
	"github.com/go-freya/freya/services/warden/internal/secrets"
	"github.com/go-freya/freya/services/warden/internal/store"
	"github.com/go-freya/freya/services/warden/internal/vault"
)

const (
	tA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	uA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"
	uB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c88"
	pw = "WARDEN-MARKER-PW-share"
)

var (
	alice = authz.Subjects{TenantID: tA, UserID: uA}
	bob   = authz.Subjects{TenantID: tA, UserID: uB}
)

type mailbox struct {
	sent []Message
	err  error
}

func (m *mailbox) Send(_ context.Context, msg Message) error {
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, msg)
	return nil
}

type fx struct {
	ms   *memstore.Store
	vt   *vault.Fake
	aw   *audit.Writer
	az   *authz.Authz
	mail *mailbox
	svc  *Service
	sid  string
	now  time.Time
}

func newFx(t *testing.T) *fx {
	t.Helper()
	ms := memstore.New()
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	az := authz.New(ms, aw)
	vt := vault.NewFake()
	mb := &mailbox{}
	f := &fx{ms: ms, vt: vt, aw: aw, az: az, mail: mb, now: time.Unix(1_700_000_000, 0)}
	f.svc = New(ms, vt, az, aw, mb, Config{PublicOrigin: "https://platform.example.org/"})
	f.svc.SetClock(func() time.Time { return f.now })
	ms.Now = func() time.Time { return f.now }
	az.SetClock(func() time.Time { return f.now })
	sec := secrets.New(ms, vt, az, aw)
	v, err := sec.Create(context.Background(), alice, secrets.Input{Name: "prod-db", Username: "root", HostURL: "https://db", Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	f.sid = v.ID
	return f
}

func (f *fx) events(t string) []store.AuditRow { f.aw.Flush(); return f.ms.AuditEvents(tA, t) }

func linkToken(t *testing.T, m Message) string {
	t.Helper()
	i := strings.Index(m.Text, "/warden/share#")
	if i < 0 {
		t.Fatalf("no link in %q", m.Text)
	}
	return strings.Fields(m.Text[i+len("/warden/share#"):])[0]
}

func TestTokens(t *testing.T) {
	tok, err := NewToken(bytes.NewReader(make([]byte, 64)))
	if err != nil || len(tok) != TokenLength || !ValidToken(tok) {
		t.Fatalf("%q %v", tok, err)
	}
	if _, err := NewToken(bytes.NewReader(nil)); err == nil {
		t.Fatal("empty source")
	}
	for _, bad := range []string{"", strings.Repeat("a", 42), strings.Repeat("a", 44), strings.Repeat("a", 42) + "=", strings.Repeat("a", 42) + "/"} {
		if ValidToken(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if len(Hash("x")) != 64 || Hash("x") == Hash("y") || Hash(tok) != Hash(string([]byte(tok))) {
		t.Fatal("hash")
	}
}

func TestCreate(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	for name, in := range map[string]Input{
		"bad email":    {RecipientEmail: "not-an-email"},
		"named":        {RecipientEmail: "Bob <bob@x.test>"},
		"long message": {RecipientEmail: "bob@x.test", Message: strings.Repeat("m", 1001)},
		"validity low": {RecipientEmail: "bob@x.test", ValiditySeconds: 10},
		"validity hi":  {RecipientEmail: "bob@x.test", ValiditySeconds: MaxValidity + 1},
		"opens":        {RecipientEmail: "bob@x.test", MaxOpens: 11},
		"cidr":         {RecipientEmail: "bob@x.test", CIDR: "10.0.0.0/99"},
	} {
		if _, err := f.svc.Create(ctx, alice, f.sid, in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.svc.Create(ctx, alice, f.sid, Input{RecipientEmail: "bob@x.test", Region: "DE"}); !errors.Is(err, ErrRegionUnavailable) {
		t.Fatal("region")
	}
	if _, err := f.svc.Create(ctx, bob, f.sid, Input{RecipientEmail: "bob@x.test"}); !errors.Is(err, ErrForbidden) {
		t.Fatal("bob shares")
	}
	if _, err := f.svc.Create(ctx, authz.Subjects{TenantID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66", UserID: uB}, f.sid, Input{RecipientEmail: "bob@x.test"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-tenant")
	}
	v, err := f.svc.Create(ctx, alice, f.sid, Input{RecipientEmail: "bob@x.test", Message: "for the migration"})
	if err != nil || v.MaxOpens != 1 || v.State != "active" || v.ExpiresAt != f.now.Add(time.Hour) || v.RecipientEmail != "bob@x.test" {
		t.Fatalf("%+v %v", v, err)
	}
	// The mail carries the link with a valid token; the database holds only the hash; the audit never has the token.
	if len(f.mail.sent) != 1 || f.mail.sent[0].To != "bob@x.test" || !strings.Contains(f.mail.sent[0].Text, "prod-db") || !strings.Contains(f.mail.sent[0].Text, "for the migration") {
		t.Fatalf("%+v", f.mail.sent)
	}
	tok := linkToken(t, f.mail.sent[0])
	if !ValidToken(tok) || !strings.Contains(f.mail.sent[0].Text, "https://platform.example.org/warden/share#"+tok) {
		t.Fatalf("link %q", f.mail.sent[0].Text)
	}
	row := f.ms.Shares[v.ID]
	if row.TokenHash != Hash(tok) || strings.Contains(row.TokenHash, tok) {
		t.Fatal("token stored")
	}
	ev := f.events("share_created")
	if len(ev) != 1 || strings.Contains(string(ev[0].Details), tok) || !strings.Contains(string(ev[0].Details), "bob@x.test") {
		t.Fatalf("%+v", ev)
	}
	// Custom policy and defaults from config.
	svc2 := New(f.ms, f.vt, f.az, f.aw, f.mail, Config{PublicOrigin: "https://p", DefaultValidity: 2 * time.Hour, DefaultMaxOpens: 3})
	svc2.SetClock(func() time.Time { return f.now })
	v2, err := svc2.Create(ctx, alice, f.sid, Input{RecipientEmail: "c@x.test", ValiditySeconds: 600, MaxOpens: 5, CIDR: "10.0.0.0/8"})
	if err != nil || v2.MaxOpens != 5 || v2.CIDR != "10.0.0.0/8" || v2.ExpiresAt != f.now.Add(10*time.Minute) {
		t.Fatalf("%+v %v", v2, err)
	}
	v3, _ := svc2.Create(ctx, alice, f.sid, Input{RecipientEmail: "d@x.test"})
	if v3.MaxOpens != 3 || v3.ExpiresAt != f.now.Add(2*time.Hour) {
		t.Fatalf("%+v", v3)
	}
	// Mail failure cancels the share and reports it.
	f.mail.err = errors.New("smtp down")
	if _, err := f.svc.Create(ctx, alice, f.sid, Input{RecipientEmail: "e@x.test"}); !errors.Is(err, ErrMail) {
		t.Fatalf("mail: %v", err)
	}
	f.mail.err = nil
	for _, sh := range f.ms.Shares {
		if sh.RecipientEmail == "e@x.test" && sh.State != "cancelled" {
			t.Fatal("share kept after mail failure")
		}
	}
	// Store and random failures.
	f.ms.FailOn("InsertShare", errors.New("db"))
	if _, err := f.svc.Create(ctx, alice, f.sid, Input{RecipientEmail: "f@x.test"}); err == nil {
		t.Fatal("insert")
	}
	f.ms.FailOn("InsertShare", nil)
	f.ms.FailOn("GetSecret", errors.New("db"))
	if _, err := f.svc.Create(ctx, alice, f.sid, Input{RecipientEmail: "f@x.test"}); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("get secret db")
	}
	f.ms.FailOn("GetSecret", nil)
	f.svc.SetRandom(bytes.NewReader(nil))
	if _, err := f.svc.Create(ctx, alice, f.sid, Input{RecipientEmail: "f@x.test"}); err == nil {
		t.Fatal("random")
	}
}

func TestOpen(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	v, _ := f.svc.Create(ctx, alice, f.sid, Input{RecipientEmail: "bob@x.test", MaxOpens: 2, Message: "hi"})
	tok := linkToken(t, f.mail.sent[0])
	// Bad, unknown tokens → not found without a lookup leak.
	for _, bad := range []string{"", "short", strings.Repeat("b", 43)} {
		if _, err := f.svc.Open(ctx, bad, ""); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	d, err := f.svc.Open(ctx, tok, "")
	if err != nil || d.Password != pw || d.Name != "prod-db" || d.Username != "root" || d.OpensLeft != 1 || d.Message != "hi" {
		t.Fatalf("%+v %v", d, err)
	}
	d, err = f.svc.Open(ctx, tok, "203.0.113.9")
	if err != nil || d.OpensLeft != 0 {
		t.Fatalf("%+v %v", d, err)
	}
	if _, err := f.svc.Open(ctx, tok, ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("third open")
	}
	if f.ms.Shares[v.ID].State != "consumed" {
		t.Fatal("state")
	}
	opened := f.events("share_opened")
	if len(opened) != 2 || opened[0].ActorKind != "recipient" || opened[0].ActorID != "bob@x.test" || strings.Contains(string(opened[0].Details), pw) {
		t.Fatalf("%+v", opened)
	}
	if n := len(f.events("share_refused")); n != 1 {
		t.Fatalf("refusals %d", n)
	}
	// Expiry and cancellation refuse; CIDR policy checks the relayed address only.
	f.mail.sent = nil
	exp, _ := f.svc.Create(ctx, alice, f.sid, Input{RecipientEmail: "c@x.test", ValiditySeconds: 300})
	expTok := linkToken(t, f.mail.sent[0])
	f.now = f.now.Add(301 * time.Second)
	if _, err := f.svc.Open(ctx, expTok, ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired")
	}
	_ = exp
	f.mail.sent = nil
	can, _ := f.svc.Create(ctx, alice, f.sid, Input{RecipientEmail: "d@x.test"})
	canTok := linkToken(t, f.mail.sent[0])
	if err := f.svc.Cancel(ctx, alice, can.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Open(ctx, canTok, ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("cancelled")
	}
	f.mail.sent = nil
	_, _ = f.svc.Create(ctx, alice, f.sid, Input{RecipientEmail: "e@x.test", CIDR: "10.0.0.0/8", MaxOpens: 3})
	cidrTok := linkToken(t, f.mail.sent[0])
	for _, addr := range []string{"", "203.0.113.9", "garbage"} {
		if _, err := f.svc.Open(ctx, cidrTok, addr); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cidr %q: %v", addr, err)
		}
	}
	if _, err := f.svc.Open(ctx, cidrTok, " 10.1.2.3 "); err != nil {
		t.Fatalf("cidr match: %v", err)
	}
	// Vault down on open is not a refusal but an error; the secret vanishing is a refusal.
	f.vt.Down = true
	if _, err := f.svc.Open(ctx, cidrTok, "10.1.2.3"); !errors.Is(err, vault.ErrUnavailable) {
		t.Fatalf("vault: %v", err)
	}
	f.vt.Down = false
	f.ms.FailOn("GetSecret", errors.New("db"))
	if _, err := f.svc.Open(ctx, cidrTok, "10.1.2.3"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("secret gone: %v", err)
	}
	f.ms.FailOn("GetSecret", nil)
	f.ms.FailOn("ConsumeShareOpen", errors.New("db"))
	if _, err := f.svc.Open(ctx, cidrTok, "10.1.2.3"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("consume db: %v", err)
	}
	f.ms.FailOn("ConsumeShareOpen", nil)
	f.ms.FailOn("ShareByTokenHash", errors.New("db"))
	if _, err := f.svc.Open(ctx, cidrTok, "10.1.2.3"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("lookup db: %v", err)
	}
	f.ms.FailOn("ShareByTokenHash", nil)
	// A race: the row is consumed between the check and the atomic increment.
	consumed := &raceStore{Store: f.ms}
	svc := New(consumed, f.vt, f.az, nil, f.mail, Config{PublicOrigin: "https://p"})
	svc.SetClock(func() time.Time { return f.now })
	if _, err := svc.Open(ctx, cidrTok, "10.1.2.3"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("race: %v", err)
	}
	// A stored CIDR that no longer parses refuses.
	for id, sh := range f.ms.Shares {
		if sh.CIDR != nil {
			bad := "nope"
			sh.CIDR = &bad
			f.ms.Shares[id] = sh
		}
	}
	if _, err := f.svc.Open(ctx, cidrTok, "10.1.2.3"); !errors.Is(err, ErrNotFound) {
		t.Fatal("bad stored cidr")
	}
}

// raceStore reports the share as active but refuses the atomic open.
type raceStore struct{ *memstore.Store }

func (r *raceStore) ConsumeShareOpen(context.Context, string) (store.Share, error) {
	return store.Share{}, store.ErrNotFound
}

func TestCancelListSweep(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	v, _ := f.svc.Create(ctx, alice, f.sid, Input{RecipientEmail: "bob@x.test", ValiditySeconds: 300})
	// List: creator's own shares; a sharer sees only theirs; bob (no share) is refused.
	list, err := f.svc.List(ctx, alice, f.sid)
	if err != nil || len(list) != 1 || list[0].ID != v.ID || list[0].State != "active" {
		t.Fatalf("%+v %v", list, err)
	}
	if _, err := f.svc.List(ctx, bob, f.sid); !errors.Is(err, ErrForbidden) {
		t.Fatal("bob list")
	}
	if _, err := f.ms.UpsertGrant(ctx, store.Grant{ID: store.NewID(), TenantID: tA, ResourceType: "secret", ResourceID: f.sid, SubjectType: "user", SubjectID: uB, Relation: "sharer"}); err != nil {
		t.Fatal(err)
	}
	if mine, _ := f.svc.List(ctx, bob, f.sid); len(mine) != 0 {
		t.Fatal("bob sees alice's shares")
	}
	// The listing reports lapsed shares as expired before the sweep ran.
	f.now = f.now.Add(301 * time.Second)
	list, _ = f.svc.List(ctx, alice, f.sid)
	if list[0].State != "expired" {
		t.Fatalf("%+v", list[0])
	}
	// Sweep marks them; cancel of a non-active share is not found.
	n, err := f.svc.Sweep(ctx)
	if err != nil || n != 1 || f.ms.Shares[v.ID].State != "expired" {
		t.Fatalf("%d %v", n, err)
	}
	if err := f.svc.Cancel(ctx, alice, v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancel expired: %v", err)
	}
	// Cancel by a sharer who did not create it (allowed), by a viewer (forbidden), unknown id (not found).
	w, _ := f.svc.Create(ctx, alice, f.sid, Input{RecipientEmail: "c@x.test"})
	carol := authz.Subjects{TenantID: tA, UserID: "carol"}
	if err := f.svc.Cancel(ctx, carol, w.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("carol: %v", err)
	}
	if err := f.svc.Cancel(ctx, bob, w.ID); err != nil {
		t.Fatalf("sharer cancel: %v", err)
	}
	if err := f.svc.Cancel(ctx, alice, store.NewID()); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown")
	}
	if n := len(f.events("share_cancelled")); n != 1 {
		t.Fatalf("cancel audit %d", n)
	}
	// Store failures and the sweeper loop.
	f.ms.FailOn("SharesOfSecret", errors.New("db"))
	if _, err := f.svc.List(ctx, alice, f.sid); err == nil {
		t.Fatal("list db")
	}
	f.ms.FailOn("SharesOfSecret", nil)
	f.ms.FailOn("GetShare", errors.New("db"))
	if err := f.svc.Cancel(ctx, alice, w.ID); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("get share db")
	}
	f.ms.FailOn("GetShare", nil)
	f.ms.FailOn("SetShareState", errors.New("db"))
	x, _ := f.svc.Create(ctx, alice, f.sid, Input{RecipientEmail: "d@x.test"})
	if err := f.svc.Cancel(ctx, alice, x.ID); err == nil {
		t.Fatal("set state db")
	}
	f.ms.FailOn("SetShareState", nil)
	f.ms.FailOn("ExpireShares", errors.New("db"))
	errs := make(chan error, 1)
	rctx, cancel := context.WithCancel(ctx)
	go f.svc.RunSweeper(rctx, 5*time.Millisecond, func(err error) {
		select {
		case errs <- err:
		default:
		}
	})
	select {
	case <-errs:
	case <-time.After(2 * time.Second):
		t.Fatal("sweeper never reported")
	}
	cancel()
	f.ms.FailOn("ExpireShares", nil)
}

func TestMailSenders(t *testing.T) {
	if _, err := NewSMTP(SMTPConfig{}); err == nil {
		t.Fatal("empty config")
	}
	if _, err := NewSMTP(SMTPConfig{Host: "h", Port: 25, From: "a@b"}); err == nil {
		t.Fatal("plaintext port refused")
	}
	s, err := NewSMTP(SMTPConfig{Host: "127.0.0.1", Port: 1, From: "a@b", AllowPlaintext: true, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), Message{To: "x@y", Subject: "s\r\nX: injected", Text: "t"}); err == nil {
		t.Fatal("closed port")
	}
	var buf bytes.Buffer
	sink := LogSink{Log: slog.New(slog.NewTextHandler(&buf, nil))}
	if err := sink.Send(context.Background(), Message{To: "x@y", Subject: "s", Text: "https://p/warden/share#" + strings.Repeat("t", 43)}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "warden/share") || !strings.Contains(buf.String(), "x@y") {
		t.Fatalf("sink logged the link: %s", buf.String())
	}
	if err := (LogSink{}).Send(context.Background(), Message{}); err != nil {
		t.Fatal(err)
	}
	if sanitizeHeader("a\r\nb") != "a  b" {
		t.Fatal("sanitize")
	}
}

func TestEdgeBranches(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	region := "DE"
	if v := view(store.Share{Region: &region}); v.Region != "DE" {
		t.Fatal("region view")
	}
	// An inconsistent row (opens at the limit but still active) is refused as exhausted.
	f.mail.sent = nil
	v, _ := f.svc.Create(ctx, alice, f.sid, Input{RecipientEmail: "bob@x.test", MaxOpens: 2})
	tok := linkToken(t, f.mail.sent[0])
	sh := f.ms.Shares[v.ID]
	sh.Opens = 2
	f.ms.Shares[v.ID] = sh
	if _, err := f.svc.Open(ctx, tok, ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("exhausted row")
	}
	// The secret load after a successful permission check failing.
	w := &secondGetFails{Store: f.ms}
	svc := New(w, f.vt, authz.New(w, nil), nil, f.mail, Config{PublicOrigin: "https://p"})
	if _, err := svc.Create(ctx, alice, f.sid, Input{RecipientEmail: "g@x.test"}); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("second load: %v", err)
	}
}

type secondGetFails struct {
	*memstore.Store
	calls int
}

func (s *secondGetFails) GetSecret(ctx context.Context, tid, id string) (store.Secret, error) {
	s.calls++
	if s.calls == 2 {
		return store.Secret{}, errors.New("db")
	}
	return s.Store.GetSecret(ctx, tid, id)
}
