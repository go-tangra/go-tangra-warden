package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
)

type memIns struct {
	mu   sync.Mutex
	rows []store.AuditRow
	err  error
}

func (m *memIns) InsertAuditRows(_ context.Context, rows []store.AuditRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.rows = append(m.rows, rows...)
	return nil
}

func (m *memIns) count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.rows) }

func ok() Event {
	return Event{Type: SecretCreated, TenantID: "t1", ActorKind: "user", ActorID: "u1", SubjectKind: "secret", SubjectID: "s1", Outcome: "ok"}
}

func TestValidate(t *testing.T) {
	if err := Validate(ok()); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Event){
		"unknown type":  func(e *Event) { e.Type = "made_up" },
		"no tenant":     func(e *Event) { e.TenantID = "" },
		"bad outcome":   func(e *Event) { e.Outcome = "maybe" },
		"bad actor":     func(e *Event) { e.ActorKind = "operator" },
		"bad subject":   func(e *Event) { e.SubjectKind = "thing" },
		"empty subject": func(e *Event) { e.SubjectKind = "" },
	} {
		e := ok()
		mut(&e)
		if err := Validate(e); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// Every vocabulary entry validates.
	for et := range known {
		e := ok()
		e.Type = et
		if err := Validate(e); err != nil {
			t.Errorf("%s: %v", et, err)
		}
	}
	if len(known) != 30 {
		t.Fatalf("vocabulary size %d", len(known))
	}
}

func TestRowRedaction(t *testing.T) {
	e := ok()
	e.Details = map[string]any{
		"password":     "x",
		"Secret_Value": "x",
		"totp_seed":    "x",
		"share_token":  "x",
		"link":         "x",
		"seed":         "x",
		"version":      3,
		"fields":       []string{"name", "username"},
		"marker":       "WARDEN-MARKER-PW-abc",
		"url":          "https://x/warden/share#" + strings.Repeat("a", 43),
		"otp":          "otpauth://totp/x?secret=abc",
		"nested":       map[string]any{"password": "x", "n": 1, "s": "WARDEN-MARKER-SEED-1"},
		"list":         []any{"WARDEN-MARKER-PW-1", 2},
	}
	r, err := Row(e, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(r.Details, &d); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"password", "Secret_Value", "totp_seed", "share_token", "link", "seed", "marker", "url", "otp"} {
		if d[k] != "[REDACTED]" {
			t.Errorf("%s not redacted: %v", k, d[k])
		}
	}
	if d["version"] != float64(3) {
		t.Errorf("version altered: %v", d["version"])
	}
	n := d["nested"].(map[string]any)
	if n["password"] != "[REDACTED]" || n["s"] != "[REDACTED]" || n["n"] != float64(1) {
		t.Errorf("nested: %v", n)
	}
	l := d["list"].([]any)
	if l[0] != "[REDACTED]" || l[1] != float64(2) {
		t.Errorf("list: %v", l)
	}
	if r.EventType != "secret_created" || r.ActorID != "u1" || r.SubjectID != "s1" || r.TS != time.Unix(1, 0) {
		t.Errorf("row: %+v", r)
	}
	// Invalid event refused; unmarshalable detail refused.
	bad := ok()
	bad.Outcome = ""
	if _, err := Row(bad, time.Now()); err == nil {
		t.Fatal("expected validation error")
	}
	bad = ok()
	bad.Details = map[string]any{"ch": make(chan int)}
	if _, err := Row(bad, time.Now()); err == nil {
		t.Fatal("expected marshal error")
	}
	// Nil details → {}.
	r, _ = Row(ok(), time.Now())
	if string(r.Details) != "{}" {
		t.Fatalf("details %s", r.Details)
	}
}

func TestSafeString(t *testing.T) {
	for _, s := range []string{"WARDEN-MARKER-PW-1", "warden-marker-seed-2", "otpauth://totp/a", "/warden/share/" + strings.Repeat("b", 43), "/warden/share#" + strings.Repeat("b", 43), "-----BEGIN RSA PRIVATE KEY-----", "eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.abc"} {
		if SafeString(s) {
			t.Errorf("%q should be unsafe", s)
		}
	}
	for _, s := range []string{"", "hello", "/warden/share", "eyJ.only"} {
		if !SafeString(s) {
			t.Errorf("%q should be safe", s)
		}
	}
}

func TestWriterBatchAndFlush(t *testing.T) {
	ins := &memIns{}
	w := NewWriter(ins, nil)
	for i := 0; i < 250; i++ {
		if err := w.Emit(ok()); err != nil {
			t.Fatal(err)
		}
	}
	w.Flush()
	if ins.count() != 250 {
		t.Fatalf("stored %d", ins.count())
	}
	if err := w.Emit(Event{}); err == nil {
		t.Fatal("expected validation error")
	}
	w.Close()
	w.Close() // idempotent
	if err := w.Emit(ok()); err == nil {
		t.Fatal("expected closed error")
	}
	w.Flush() // no-op after close
	if w.Dropped() != 1 {
		t.Fatalf("dropped %d", w.Dropped())
	}
}

func TestWriterErrorsAndOverflow(t *testing.T) {
	var mu sync.Mutex
	var errs []error
	ins := &memIns{err: errors.New("db down")}
	w := NewWriter(ins, func(err error) { mu.Lock(); errs = append(errs, err); mu.Unlock() })
	_ = w.Emit(ok())
	w.Flush()
	mu.Lock()
	n := len(errs)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("errors %d", n)
	}
	w.Close()

	// Overflow: writer with a blocked inserter and a small queue.
	block := make(chan struct{})
	slow := &blockIns{block: block}
	w2 := newWriter(slow, func(error) {}, 2)
	for i := 0; i < 10; i++ {
		_ = w2.Emit(ok())
	}
	if w2.Dropped() == 0 {
		t.Fatal("expected drops")
	}
	close(block)
	w2.Close()
}

func TestWriterTicker(t *testing.T) {
	ins := &memIns{}
	w := newWriter(ins, nil, 100)
	w.tick = 5 * time.Millisecond
	w.start()
	_ = w.Emit(ok())
	deadline := time.Now().Add(2 * time.Second)
	for ins.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ins.count() != 1 {
		t.Fatal("ticker did not flush")
	}
	w.Close()
}

type blockIns struct{ block chan struct{} }

func (b *blockIns) InsertAuditRows(context.Context, []store.AuditRow) error { <-b.block; return nil }
