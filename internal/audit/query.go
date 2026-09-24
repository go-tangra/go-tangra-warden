package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
)

// Querier reads the audit hypertable (database or in-memory).
type Querier interface {
	QueryAudit(ctx context.Context, tenantID, eventType, actorID string, from, to, cursor time.Time, limit int) ([]store.AuditRow, error)
}

// Filter selects events; zero values mean "any".
type Filter struct {
	ActorID   string
	EventType string
	From, To  time.Time
	Cursor    string
	Limit     int // ≤ 200, default 50
}

// Item is one event as returned to administrators.
type Item struct {
	TS            time.Time       `json:"ts"`
	EventType     string          `json:"event_type"`
	ActorKind     string          `json:"actor_kind"`
	ActorID       string          `json:"actor_id,omitempty"`
	SubjectKind   string          `json:"subject_kind,omitempty"`
	SubjectID     string          `json:"subject_id,omitempty"`
	SubjectName   string          `json:"subject_name,omitempty"` // secret name or folder path while it exists
	Outcome       string          `json:"outcome"`
	Reason        string          `json:"reason,omitempty"`
	CorrelationID string          `json:"correlation_id,omitempty"`
	Details       json.RawMessage `json:"details"`
}

// Page is a cursor-paged result.
type Page struct {
	Items      []Item `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// ErrFilter is returned for malformed filters.
var ErrFilter = errors.New("audit: invalid filter")

// Query lists events of one tenant newest first.
func Query(ctx context.Context, q Querier, tenantID string, f Filter) (Page, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.EventType != "" && !Known(f.EventType) {
		return Page{}, ErrFilter
	}
	if !f.From.IsZero() && !f.To.IsZero() && f.To.Before(f.From) {
		return Page{}, ErrFilter
	}
	var cursor time.Time
	if f.Cursor != "" {
		n, err := strconv.ParseInt(f.Cursor, 10, 64)
		if err != nil {
			return Page{}, ErrFilter
		}
		cursor = time.Unix(0, n)
	}
	to := f.To
	if to.IsZero() {
		to = time.Now().Add(time.Minute)
	}
	rows, err := q.QueryAudit(ctx, tenantID, f.EventType, f.ActorID, f.From, to, cursor, f.Limit+1)
	if err != nil {
		return Page{}, err
	}
	page := Page{Items: []Item{}}
	for i, r := range rows {
		if i == f.Limit {
			page.NextCursor = strconv.FormatInt(rows[i-1].TS.UnixNano(), 10)
			break
		}
		details := r.Details
		if len(details) == 0 {
			details = json.RawMessage("{}")
		}
		page.Items = append(page.Items, Item{TS: r.TS, EventType: r.EventType, ActorKind: r.ActorKind, ActorID: r.ActorID, SubjectKind: r.SubjectKind,
			SubjectID: r.SubjectID, SubjectName: r.SubjectName, Outcome: r.Outcome, Reason: r.Reason, CorrelationID: r.CorrelationID, Details: details})
	}
	return page, nil
}
