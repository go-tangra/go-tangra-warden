package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-tangra/go-tangra/v4/listquery"
	"github.com/jackc/pgx/v5"
)

// List-contract pages (go-tangra specs/032-server-side-tables): count the rows
// matching the filter and the caller's visibility, clamp the request to the
// last page, then select the page ORDER BY the Spec's constant expressions
// with the id tie-breaker, in the same tenant transaction. The cursor
// variants stay for the legacy HTTP path, gRPC and the backup walks.

// secretVisible restricts secrets (s, LEFT JOIN folders f) to a SecretScope:
// a direct grant on the secret, or a grant on its folder or any ancestor of
// it. $%[1]d is the granted secret ids, $%[2]d the granted folder ids.
const secretVisible = "(s.id = ANY($%[1]d::uuid[]) OR f.id = ANY($%[2]d::uuid[]) OR f.ancestors && $%[2]d::uuid[])"

// pageQuery runs the count and the page of one list. where is constant SQL
// parameterised by args; orderBy is built from Spec constants only.
func pageQuery[T any](ctx context.Context, tx pgx.Tx, cols, from, where string, args []any, req listquery.Request, orderBy func(listquery.Request) string,
	scan func(pgx.Rows) (T, error)) ([]T, int, listquery.Request, error) {
	var total int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+from+" WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, req, err
	}
	req = req.Clamp(total)
	rows, err := tx.Query(ctx, fmt.Sprintf("SELECT %s FROM %s WHERE %s ORDER BY %s LIMIT %d OFFSET %d", cols, from, where, orderBy(req), req.Limit(), req.Offset()), args...)
	if err != nil {
		return nil, 0, req, err
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, 0, req, err
		}
		out = append(out, v)
	}
	return out, total, req, rows.Err()
}

const secretPageFrom = "secrets s LEFT JOIN folders f ON f.id = s.folder_id AND f.tenant_id = s.tenant_id"

func scanSecretRow(r pgx.Rows) (Secret, error) { return scanSecret(r) }

// PageSecretsInFolder pages the live secrets of a folder (nil = root) the
// scope makes visible.
func PageSecretsInFolder(ctx context.Context, tx pgx.Tx, tenantID string, folderID *string, scope SecretScope, req listquery.Request) ([]Secret, int, listquery.Request, error) {
	req = ListRequest(req, SecretList)
	// A plain equality for a folder (IS NOT DISTINCT FROM cannot be an index
	// condition) and IS NULL for the root let the indexes of migrations
	// 0005/0006 deliver the page in order: (tenant_id, folder_id, <sort>, id)
	// for a folder, the partial secrets_root_* indexes for the root.
	folderCond := "s.folder_id = $2"
	if folderID == nil {
		folderCond = "s.folder_id IS NULL AND $2::uuid IS NULL"
	}
	where := "s.tenant_id = $1 AND " + folderCond + " AND s.deleted_at IS NULL AND " + fmt.Sprintf(secretVisible, 3, 4)
	args := []any{tenantID, folderID, nonNil(scope.SecretIDs), nonNil(scope.FolderIDs)}
	return pageQuery(ctx, tx, secretCols, secretPageFrom, where, args, req, func(r listquery.Request) string { return r.OrderBy(SecretList) }, scanSecretRow)
}

// SearchOrderBy is the ORDER BY of a search page: relevance is followed by
// name order (then id) so equally relevant hits read alphabetically.
func SearchOrderBy(r listquery.Request) string {
	if r.Sort == "relevance" || r.Sort == "" {
		dir := "DESC"
		if r.Order == listquery.Asc {
			dir = "ASC"
		}
		return SearchRelevanceExpr + " " + dir + ", lower(s.name) ASC, s.id ASC"
	}
	return r.OrderBy(SecretSearchList)
}

// PageSearchSecrets pages the live secrets matching q (name, username, host,
// description or folder path; never material) the scope makes visible. q is
// matched literally (EscapeLike) and is $2 of both queries
// (SearchRelevanceExpr).
func PageSearchSecrets(ctx context.Context, tx pgx.Tx, tenantID, q string, scope SecretScope, req listquery.Request) ([]Secret, int, listquery.Request, error) {
	req = ListRequest(req, SecretSearchList)
	where := `s.tenant_id = $1 AND s.deleted_at IS NULL
		AND (s.search LIKE '%' || lower($2) || '%' ESCAPE '\' OR lower(coalesce(f.path,'')) LIKE '%' || lower($2) || '%' ESCAPE '\') AND ` + fmt.Sprintf(secretVisible, 3, 4)
	args := []any{tenantID, EscapeLike(q), nonNil(scope.SecretIDs), nonNil(scope.FolderIDs)}
	return pageQuery(ctx, tx, secretCols, secretPageFrom, where, args, req, SearchOrderBy, scanSecretRow)
}

// PageSharesOfSecret pages the shares of a secret created by a user.
func PageSharesOfSecret(ctx context.Context, tx pgx.Tx, tenantID, secretID, createdBy string, req listquery.Request) ([]Share, int, listquery.Request, error) {
	req = ListRequest(req, ShareList)
	return pageQuery(ctx, tx, qualify(shareCols, "sh."), "shares sh", "sh.tenant_id = $1 AND sh.secret_id = $2 AND sh.created_by = $3",
		[]any{tenantID, secretID, createdBy}, req, func(r listquery.Request) string { return r.OrderBy(ShareList) },
		func(r pgx.Rows) (Share, error) { return scanShare(r) })
}

// PageAudit pages the events of one tenant within [From, To].
func PageAudit(ctx context.Context, tx pgx.Tx, tenantID string, f AuditQuery, req listquery.Request) ([]AuditRow, int, listquery.Request, error) {
	req = ListRequest(req, AuditList)
	return pageQuery(ctx, tx, auditCols, "warden_audit_events a", "a.tenant_id = $1 AND ($2 = '' OR a.event_type = $2) AND ($3 = '' OR a.actor_id = $3) AND a.ts >= $4 AND a.ts <= $5",
		[]any{tenantID, f.EventType, f.ActorID, f.From, f.To}, req, func(r listquery.Request) string { return r.OrderBy(AuditList) }, scanAuditRow)
}

// EscapeLike escapes the LIKE wildcards in a search term (032 security review
// F-4) so % and _ match themselves; the queries use ESCAPE '\'. The caller
// caps the term's length (secrets.SearchMax).
func EscapeLike(q string) string {
	return likeEscaper.Replace(q)
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// qualify prefixes every column of a comma-separated list.
func qualify(cols, prefix string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = prefix + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}
