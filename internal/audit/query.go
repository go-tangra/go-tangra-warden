package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"

	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
)

// Querier reads the audit hypertable (database or in-memory).
type Querier interface {
	QueryAudit(ctx context.Context, tenantID, eventType, actorID string, from, to, cursor time.Time, limit int) ([]store.AuditRow, error)
	PageAudit(ctx context.Context, tenantID string, f store.AuditQuery, req listquery.Request) ([]store.AuditRow, int, listquery.Request, error)
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

// ErrSpan refuses a window wider than store.MaxAuditSpan; it names the from
// parameter (validation_failed {param: from}) and never carries the value.
var ErrSpan = &listquery.Error{Param: "from"}

// checkSpan refuses an explicit from more than store.MaxAuditSpan before to
// (now when absent).
func checkSpan(from, to, now time.Time) error {
	if to.IsZero() {
		to = now
	}
	if !from.IsZero() && to.Sub(from) > store.MaxAuditSpan {
		return ErrSpan
	}
	return nil
}

// Query lists events of one tenant newest first (legacy cursor path). An
// explicit window wider than store.MaxAuditSpan is ErrSpan.
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
	if err := checkSpan(f.From, f.To, time.Now()); err != nil {
		return Page{}, err
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
		page.Items = append(page.Items, item(r))
	}
	return page, nil
}

func item(r store.AuditRow) Item {
	details := r.Details
	if len(details) == 0 {
		details = json.RawMessage("{}")
	}
	return Item{TS: r.TS, EventType: r.EventType, ActorKind: r.ActorKind, ActorID: r.ActorID, SubjectKind: r.SubjectKind,
		SubjectID: r.SubjectID, SubjectName: r.SubjectName, Outcome: r.Outcome, Reason: r.Reason, CorrelationID: r.CorrelationID, Details: details}
}

// Window resolves the time window of a page: an absent to is now, an absent
// from is store.AuditWindow before to (research D6: exact counts over a
// bounded slice of the hypertable).
func Window(from, to, now time.Time) (time.Time, time.Time) {
	if to.IsZero() {
		to = now.Add(time.Minute)
	}
	if from.IsZero() {
		from = to.Add(-store.AuditWindow)
	}
	return from, to
}

// QueryPage is one list-contract page of a tenant's events (newest first by
// default) within the filter's window (Window); an explicit window wider than
// store.MaxAuditSpan is ErrSpan. The cursor and limit of the filter are
// ignored.
func QueryPage(ctx context.Context, q Querier, tenantID string, f Filter, req listquery.Request, now time.Time) (listquery.Page[Item], error) {
	if f.EventType != "" && !Known(f.EventType) {
		return listquery.Page[Item]{}, ErrFilter
	}
	if !f.From.IsZero() && !f.To.IsZero() && f.To.Before(f.From) {
		return listquery.Page[Item]{}, ErrFilter
	}
	if err := checkSpan(f.From, f.To, now); err != nil {
		return listquery.Page[Item]{}, err
	}
	from, to := Window(f.From, f.To, now)
	if to.Before(from) {
		return listquery.Page[Item]{}, ErrFilter
	}
	rows, total, applied, err := q.PageAudit(ctx, tenantID, store.AuditQuery{EventType: f.EventType, ActorID: f.ActorID, From: from, To: to}, req)
	if err != nil {
		return listquery.Page[Item]{}, err
	}
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		items = append(items, item(r))
	}
	return listquery.NewPage(items, total, applied), nil
}
