//go:build integration

package store

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"
	"github.com/jackc/pgx/v5"
)

// explainTx runs EXPLAIN on every page query (Query; the count goes through
// QueryRow) before running it, so the plan checked is that of the exact SQL
// the page functions build.
type explainTx struct {
	pgx.Tx
	plans []string
}

func (e *explainTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	rows, err := e.Tx.Query(ctx, "EXPLAIN (COSTS OFF) "+sql, args...)
	if err != nil {
		return nil, err
	}
	var lines []string
	for rows.Next() {
		var l string
		if err := rows.Scan(&l); err != nil {
			rows.Close()
			return nil, err
		}
		lines = append(lines, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	e.plans = append(e.plans, strings.Join(lines, "\n"))
	return e.Tx.Query(ctx, sql, args...)
}

var (
	fullSort = regexp.MustCompile(`(?m)^\s*(->\s+)?Sort\s*$`)
	anySort  = regexp.MustCompile(`(?m)^\s*(->\s+)?(Incremental )?Sort\s*$`)
)

// TestListSortsUseIndexes checks (032 perf) that the list sorts are delivered
// in order by an index scan, without a Sort node, in both directions. Seq and
// bitmap scans are disabled so the small test tables do not hide a missing
// or mis-ordered index.
func TestListSortsUseIndexes(t *testing.T) {
	adminDSN, appDSN := startDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	st, err := Open(ctx, appDSN, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	by := uA
	folder, secret := NewID(), NewID()
	now := time.Now().UTC()
	if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
		if err := InsertFolder(ctx, tx, Folder{ID: folder, TenantID: tA, Name: "Infra", Path: "/Infra", CreatedBy: &by}); err != nil {
			return err
		}
		for i := 0; i < 20; i++ {
			id := NewID()
			if i == 0 {
				id = secret
			}
			var f *string
			if i%2 == 0 {
				f = &folder
			}
			if err := InsertSecret(ctx, tx, Secret{ID: id, TenantID: tA, FolderID: f, Name: fmt.Sprintf("s%02d", i), VaultPath: tA + "/secrets/" + id, CreatedBy: &by}); err != nil {
				return err
			}
		}
		for i := 0; i < 5; i++ {
			if err := InsertShare(ctx, tx, Share{ID: NewID(), TenantID: tA, SecretID: secret, TokenHash: NewID(), RecipientEmail: "r@example.org", MaxOpens: 1,
				ExpiresAt: now.Add(time.Hour), CreatedBy: uA}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var events []AuditRow
	for i := 0; i < 20; i++ {
		events = append(events, AuditRow{TS: now.Add(-time.Duration(i) * time.Minute), TenantID: tA, EventType: "secret.read", ActorKind: "user", ActorID: uA, Outcome: "ok"})
	}
	if err := st.InsertAuditRows(ctx, events); err != nil {
		t.Fatal(err)
	}

	scope := SecretScope{FolderIDs: []string{folder}, SecretIDs: []string{secret}}
	cases := []struct {
		name string
		// incremental allows an Incremental Sort over an index that delivers
		// the leading key (the audit tie-breaker spans every column).
		incremental bool
		run         func(tx pgx.Tx, req listquery.Request) error
		sorts       []string
	}{
		{name: "secrets in folder", sorts: []string{"name", "created_at", "updated_at"}, run: func(tx pgx.Tx, req listquery.Request) error {
			_, _, _, err := PageSecretsInFolder(ctx, tx, tA, &folder, scope, req)
			return err
		}},
		{name: "secrets at root", sorts: []string{"name", "created_at", "updated_at"}, run: func(tx pgx.Tx, req listquery.Request) error {
			_, _, _, err := PageSecretsInFolder(ctx, tx, tA, nil, scope, req)
			return err
		}},
		{name: "shares", sorts: []string{"created_at"}, run: func(tx pgx.Tx, req listquery.Request) error {
			_, _, _, err := PageSharesOfSecret(ctx, tx, tA, secret, uA, req)
			return err
		}},
		{name: "audit", incremental: true, sorts: []string{"ts"}, run: func(tx pgx.Tx, req listquery.Request) error {
			_, _, _, err := PageAudit(ctx, tx, tA, AuditQuery{From: now.Add(-time.Hour), To: now.Add(time.Minute)}, req)
			return err
		}},
	}
	for _, c := range cases {
		for _, sort := range c.sorts {
			for _, dir := range []listquery.Dir{listquery.Desc, listquery.Asc} {
				e := &explainTx{}
				err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
					for _, set := range []string{"SET LOCAL enable_seqscan = off", "SET LOCAL enable_bitmapscan = off"} {
						if _, err := tx.Exec(ctx, set); err != nil {
							return err
						}
					}
					e.Tx = tx
					return c.run(e, listquery.Request{Page: 1, PageSize: 5, Sort: sort, Order: dir})
				})
				if err != nil {
					t.Fatalf("%s %s %s: %v", c.name, sort, dir, err)
				}
				if len(e.plans) != 1 {
					t.Fatalf("%s %s %s: %d page queries", c.name, sort, dir, len(e.plans))
				}
				re := anySort
				if c.incremental {
					re = fullSort
				}
				if re.MatchString(e.plans[0]) {
					t.Errorf("%s by %s %s sorts instead of scanning an index:\n%s", c.name, sort, dir, e.plans[0])
				}
			}
		}
	}
}

// TestSearchEscapesWildcards checks F-4: % and _ in a search term match
// themselves, not any text.
func TestSearchEscapesWildcards(t *testing.T) {
	adminDSN, appDSN := startDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	st, err := Open(ctx, appDSN, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	by := uA
	folder := NewID()
	var ids []string
	if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
		if err := InsertFolder(ctx, tx, Folder{ID: folder, TenantID: tA, Name: "F", Path: "/F", CreatedBy: &by}); err != nil {
			return err
		}
		for _, name := range []string{"100% uptime", "100 percent", "db_admin", "dbXadmin", `back\slash`} {
			id := NewID()
			ids = append(ids, id)
			if err := InsertSecret(ctx, tx, Secret{ID: id, TenantID: tA, FolderID: &folder, Name: name, VaultPath: tA + "/secrets/" + id, CreatedBy: &by}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	scope := SecretScope{FolderIDs: []string{folder}}
	for q, want := range map[string]string{"0%": "100% uptime", "b_a": "db_admin", `k\s`: `back\slash`} {
		var page, legacy []Secret
		var total int
		err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) (err error) {
			if page, total, _, err = PageSearchSecrets(ctx, tx, tA, q, scope, listquery.Request{}); err != nil {
				return err
			}
			legacy, err = SearchSecrets(ctx, tx, tA, q, nil, []string{folder}, false, 10)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(page) != 1 || page[0].Name != want {
			t.Fatalf("page %q: total %d %v", q, total, page)
		}
		if len(legacy) != 1 || legacy[0].Name != want {
			t.Fatalf("legacy %q: %v", q, legacy)
		}
	}
}
