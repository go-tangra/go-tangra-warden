package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
)

type memQ struct {
	rows []store.AuditRow
	got  []any
	err  error
}

func (m *memQ) QueryAudit(_ context.Context, tenantID, eventType, actorID string, from, to, cursor time.Time, limit int) ([]store.AuditRow, error) {
	m.got = []any{tenantID, eventType, actorID, from, to, cursor, limit}
	if m.err != nil {
		return nil, m.err
	}
	if limit > len(m.rows) {
		limit = len(m.rows)
	}
	return m.rows[:limit], nil
}

func TestQuery(t *testing.T) {
	base := time.Unix(1000, 0)
	q := &memQ{}
	for i := 0; i < 5; i++ {
		q.rows = append(q.rows, store.AuditRow{TS: base.Add(-time.Duration(i) * time.Second), TenantID: "t", EventType: "secret_read", ActorKind: "user", ActorID: "u", Outcome: "ok"})
	}
	p, err := Query(context.Background(), q, "t", Filter{Limit: 2})
	if err != nil || len(p.Items) != 2 || p.NextCursor == "" {
		t.Fatalf("%v %+v", err, p)
	}
	if string(p.Items[0].Details) != "{}" {
		t.Fatalf("details %s", p.Items[0].Details)
	}
	// The resolved subject name is passed through.
	q.rows[0].SubjectName = "db"
	if p, err := Query(context.Background(), q, "t", Filter{Limit: 1}); err != nil || p.Items[0].SubjectName != "db" {
		t.Fatalf("subject name: %v %+v", err, p)
	}
	p2, err := Query(context.Background(), q, "t", Filter{Limit: 10, Cursor: p.NextCursor, EventType: "secret_read", ActorID: "u", From: base.Add(-time.Hour), To: base})
	if err != nil || len(p2.Items) != 5 || p2.NextCursor != "" {
		t.Fatalf("%v %+v", err, p2)
	}
	if q.got[5].(time.Time).IsZero() || q.got[6] != 11 {
		t.Fatalf("args %v", q.got)
	}
	// Default limit and "to" bound.
	if _, err := Query(context.Background(), q, "t", Filter{Limit: 999}); err != nil || q.got[6] != 51 || q.got[4].(time.Time).IsZero() {
		t.Fatalf("defaults %v %v", err, q.got)
	}
	for _, f := range []Filter{{EventType: "nope"}, {Cursor: "abc"}, {From: base, To: base.Add(-time.Second)}} {
		if _, err := Query(context.Background(), q, "t", f); !errors.Is(err, ErrFilter) {
			t.Errorf("%+v: %v", f, err)
		}
	}
	q.err = errors.New("db")
	if _, err := Query(context.Background(), q, "t", Filter{}); err == nil {
		t.Fatal("expected error")
	}
}
