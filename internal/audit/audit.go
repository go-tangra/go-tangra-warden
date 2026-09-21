// Package audit records every warden operation in a closed vocabulary with a
// detail guard that keeps material, seeds, tokens and links out of the log.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-freya/freya/services/warden/internal/store"
)

// EventType is the closed vocabulary (data-model.md).
type EventType string

// Event types.
const (
	SecretCreated         EventType = "secret_created"
	SecretRead            EventType = "secret_read"
	SecretPasswordRead    EventType = "secret_password_read"
	SecretUpdated         EventType = "secret_updated"
	SecretPasswordUpdated EventType = "secret_password_updated"
	SecretVersionRead     EventType = "secret_version_read"
	SecretRestored        EventType = "secret_restored"
	SecretMoved           EventType = "secret_moved"
	SecretDeleted         EventType = "secret_deleted"
	SecretTOTPRead        EventType = "secret_totp_read"
	SecretTOTPSet         EventType = "secret_totp_set"
	SecretTOTPRemoved     EventType = "secret_totp_removed"
	FolderCreated         EventType = "folder_created"
	FolderUpdated         EventType = "folder_updated"
	FolderMoved           EventType = "folder_moved"
	FolderDeleted         EventType = "folder_deleted"
	GrantCreated          EventType = "grant_created"
	GrantRevoked          EventType = "grant_revoked"
	AccessRefused         EventType = "access_refused"
	TransferValidated     EventType = "transfer_validated"
	TransferImported      EventType = "transfer_imported"
	TransferExported      EventType = "transfer_exported"
	BackupExported        EventType = "backup_exported"
	BackupImported        EventType = "backup_imported"
	ShareCreated          EventType = "share_created"
	ShareOpened           EventType = "share_opened"
	ShareCancelled        EventType = "share_cancelled"
	ShareRefused          EventType = "share_refused"
	VaultUnavailable      EventType = "vault_unavailable"
)

var known = map[EventType]struct{}{}

func init() {
	for _, t := range []EventType{SecretCreated, SecretRead, SecretPasswordRead, SecretUpdated, SecretPasswordUpdated, SecretVersionRead, SecretRestored,
		SecretMoved, SecretDeleted, SecretTOTPRead, SecretTOTPSet, SecretTOTPRemoved, FolderCreated, FolderUpdated, FolderMoved, FolderDeleted,
		GrantCreated, GrantRevoked, AccessRefused, TransferValidated, TransferImported, TransferExported, BackupExported, BackupImported,
		ShareCreated, ShareOpened, ShareCancelled, ShareRefused, VaultUnavailable} {
		known[t] = struct{}{}
	}
}

// Known reports whether t is in the vocabulary.
func Known(t string) bool { _, ok := known[EventType(t)]; return ok }

// Event is one record before persistence.
type Event struct {
	Type          EventType
	TenantID      string
	ActorKind     string // user | service | recipient | system
	ActorID       string
	SubjectKind   string // secret | folder | grant | share | transfer | backup | system
	SubjectID     string
	Outcome       string // ok | refused | failed
	Reason        string
	CorrelationID string
	Details       map[string]any
}

// Inserter persists batches.
type Inserter interface {
	InsertAuditRows(ctx context.Context, rows []store.AuditRow) error
}

// Forbidden detail keys (substring, case-insensitive).
var forbiddenKeys = []string{"password", "secret_value", "seed", "totp", "token", "link"}

// Marker patterns: any string value matching one is redacted.
var markers = []*regexp.Regexp{
	regexp.MustCompile(`(?i)WARDEN-MARKER-(PW|SEED)-`),
	regexp.MustCompile(`/warden/share[/#][A-Za-z0-9_-]{43}`),
	regexp.MustCompile(`(?i)otpauth://`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{3,}`),
}

// SafeString reports whether a string value carries no known secret shape.
func SafeString(s string) bool {
	for _, m := range markers {
		if m.MatchString(s) {
			return false
		}
	}
	return true
}

// Validate checks the vocabulary and required fields.
func Validate(e Event) error {
	if _, ok := known[e.Type]; !ok {
		return fmt.Errorf("audit: unknown event type %q", e.Type)
	}
	if e.TenantID == "" {
		return errors.New("audit: tenant_id is required")
	}
	switch e.Outcome {
	case "ok", "refused", "failed":
	default:
		return fmt.Errorf("audit: outcome %q", e.Outcome)
	}
	switch e.ActorKind {
	case "user", "service", "recipient", "system":
	default:
		return fmt.Errorf("audit: actor_kind %q", e.ActorKind)
	}
	switch e.SubjectKind {
	case "secret", "folder", "grant", "share", "transfer", "backup", "system":
	default:
		return fmt.Errorf("audit: subject_kind %q", e.SubjectKind)
	}
	return nil
}

func guard(v any) any {
	switch x := v.(type) {
	case string:
		if !SafeString(x) {
			return "[REDACTED]"
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = guardKey(k, vv)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = guard(vv)
		}
		return out
	default:
		return v
	}
}

func guardKey(k string, v any) any {
	lk := strings.ToLower(k)
	for _, f := range forbiddenKeys {
		if strings.Contains(lk, f) {
			return "[REDACTED]"
		}
	}
	return guard(v)
}

// Row converts an event to a store row after validation and redaction.
func Row(e Event, now time.Time) (store.AuditRow, error) {
	if err := Validate(e); err != nil {
		return store.AuditRow{}, err
	}
	details := map[string]any{}
	for k, v := range e.Details {
		details[k] = guardKey(k, v)
	}
	js, err := json.Marshal(details)
	if err != nil {
		return store.AuditRow{}, err
	}
	return store.AuditRow{TS: now, TenantID: e.TenantID, EventType: string(e.Type), ActorKind: e.ActorKind, ActorID: e.ActorID,
		SubjectKind: e.SubjectKind, SubjectID: e.SubjectID, Outcome: e.Outcome, Reason: e.Reason, CorrelationID: e.CorrelationID, Details: js}, nil
}

// Writer buffers events and writes them in batches; Emit never blocks.
type Writer struct {
	ins     Inserter
	ch      chan store.AuditRow
	wg      sync.WaitGroup
	mu      sync.Mutex
	closed  bool
	dropped int64
	onError func(error)
	flushCh chan chan struct{}
	tick    time.Duration
}

// NewWriter starts the batch writer (queue 10k, batch 200 or 500 ms).
func NewWriter(ins Inserter, onError func(error)) *Writer {
	w := newWriter(ins, onError, 10000)
	w.start()
	return w
}

func newWriter(ins Inserter, onError func(error), queue int) *Writer {
	w := &Writer{ins: ins, ch: make(chan store.AuditRow, queue), onError: onError, flushCh: make(chan chan struct{}), tick: 500 * time.Millisecond}
	if w.onError == nil {
		w.onError = func(error) {}
	}
	return w
}

func (w *Writer) start() {
	w.wg.Add(1)
	go w.run()
}

// Emit validates and queues an event.
func (w *Writer) Emit(e Event) error {
	row, err := Row(e, time.Now())
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		w.dropped++
		return errors.New("audit: writer closed")
	}
	select {
	case w.ch <- row:
	default:
		w.dropped++
		w.onError(errors.New("audit: queue full, event dropped"))
	}
	return nil
}

// Flush writes everything queued so far and returns when it is stored.
func (w *Writer) Flush() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.mu.Unlock()
	done := make(chan struct{})
	w.flushCh <- done
	<-done
}

// Dropped returns the number of dropped events.
func (w *Writer) Dropped() int64 { w.mu.Lock(); defer w.mu.Unlock(); return w.dropped }

func (w *Writer) run() {
	defer w.wg.Done()
	t := time.NewTicker(w.tick)
	defer t.Stop()
	buf := make([]store.AuditRow, 0, 200)
	flush := func() {
		if len(buf) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := w.ins.InsertAuditRows(ctx, buf); err != nil {
			w.onError(err)
		}
		cancel()
		buf = buf[:0]
	}
	for {
		select {
		case r, ok := <-w.ch:
			if !ok {
				flush()
				return
			}
			buf = append(buf, r)
			if len(buf) >= 200 {
				flush()
			}
		case <-t.C:
			flush()
		case done := <-w.flushCh:
			for len(w.ch) > 0 {
				buf = append(buf, <-w.ch)
			}
			flush()
			close(done)
		}
	}
}

// Close drains and stops the writer.
func (w *Writer) Close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	close(w.ch)
	w.mu.Unlock()
	w.wg.Wait()
}
