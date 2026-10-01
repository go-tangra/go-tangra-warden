package store

import (
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"
)

// List definitions of the warden tables (go-tangra
// specs/032-server-side-tables, contracts/sortable-fields.md "warden"). Sort
// fields map to constant SQL expressions over metadata columns only (the
// page queries alias secrets as s, their folder as f, shares as sh and audit
// events as a): no field can order by, or reveal anything about, a password,
// a seed or any other material, which never reaches the database anyway. The
// memstore sorts the same public names in Go. The gRPC reads, module-to-module
// secret reads and the backup walks keep their own order.
//
// NotNull marks columns declared NOT NULL in the migrations: OrderBy then
// omits NULLS LAST, so a plain btree (migrations 0005/0006) serves both
// directions. Search relevance is an expression and stays without it.
var (
	// SecretList pages GET /secrets (one folder, or the root): name order by
	// default.
	SecretList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"name":       {Expr: "s.name", Text: true, NotNull: true},
			"updated_at": {Expr: "s.updated_at", DefaultDir: listquery.Desc, NotNull: true},
			"created_at": {Expr: "s.created_at", DefaultDir: listquery.Desc, NotNull: true},
		},
		Default: "name", TieBreak: "s.id",
	}
	// SecretSearchList pages GET /secrets/search: name matches first by
	// default (relevance), then name order.
	SecretSearchList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"relevance":  {Expr: SearchRelevanceExpr, DefaultDir: listquery.Desc},
			"name":       {Expr: "s.name", Text: true, NotNull: true},
			"updated_at": {Expr: "s.updated_at", DefaultDir: listquery.Desc, NotNull: true},
		},
		Default: "relevance", TieBreak: "s.id",
	}
	// ShareList pages GET /secrets/{id}/shares: newest first.
	ShareList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"created_at": {Expr: "sh.created_at", DefaultDir: listquery.Desc, NotNull: true},
			"expires_at": {Expr: "sh.expires_at", NotNull: true},
		},
		Default: "created_at", TieBreak: "sh.id",
	}
	// AuditList pages GET /audit: newest first within the time window. The
	// hypertable has no id: the tie-breaker orders equal timestamps by every
	// other column, so rows that compare equal are identical and paging
	// still shows each event exactly once.
	AuditList = listquery.Spec{
		Fields:  map[string]listquery.Field{"ts": {Expr: "a.ts", DefaultDir: listquery.Desc, NotNull: true}},
		Default: "ts", TieBreak: AuditTieBreak, DefaultSize: 50,
	}
)

// SearchRelevanceExpr ranks a search hit: 1 when the name contains the query
// ($2 of every search query, LIKE-escaped by EscapeLike), else 0.
const SearchRelevanceExpr = "(CASE WHEN lower(s.name) LIKE '%' || lower($2) || '%' ESCAPE '\\' THEN 1 ELSE 0 END)"

// AuditTieBreak orders audit events with the same timestamp.
const AuditTieBreak = "a.event_type, a.actor_kind, a.actor_id, a.subject_kind, a.subject_id, a.outcome, a.reason, a.correlation_id, a.details::text"

// AuditWindow is the default time window of an audit page without from/to
// (research D6): exact counts over a bounded slice of the hypertable.
const AuditWindow = 7 * 24 * time.Hour

// MaxAuditSpan caps an explicit [from, to] audit window (032 security review
// F-2): a wide from would otherwise force an exact count and OFFSET over the
// whole hypertable on every page.
const MaxAuditSpan = 90 * 24 * time.Hour

// ListRequest completes r with the Spec's defaults (a zero Request from an
// internal caller pages with the defaults); an invalid hand-built Request
// falls back to the defaults entirely.
func ListRequest(r listquery.Request, s listquery.Spec) listquery.Request {
	out, err := listquery.New(r.Page, r.PageSize, r.Sort, r.Order, s)
	if err != nil {
		out, _ = listquery.New(0, 0, "", "", s)
	}
	return out
}

// SecretScope is what a caller may read, from the grants they hold (direct,
// through roles and tenant-wide, unexpired): secrets granted directly and
// folders granted (with their whole subtree). Page queries apply it in SQL to
// both the count and the page, so totals are exact and a hidden secret is
// never counted or returned.
type SecretScope struct {
	SecretIDs []string
	FolderIDs []string
}

// AuditQuery filters an audit page; From/To are required (the caller applies
// the default window).
type AuditQuery struct {
	EventType, ActorID string
	From, To           time.Time
}
