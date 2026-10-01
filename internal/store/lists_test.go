package store

import (
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra/v4/listquery"
)

func TestListSpecs(t *testing.T) {
	for name, s := range map[string]listquery.Spec{"secrets": SecretList, "search": SecretSearchList, "shares": ShareList, "audit": AuditList} {
		if err := s.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		// Sorting can never touch material or the vault reference.
		for field, f := range s.Fields {
			for _, bad := range []string{"password", "totp", "seed", "vault", "material", "token", "metadata"} {
				if strings.Contains(field, bad) || strings.Contains(f.Expr, bad) {
					t.Errorf("%s.%s names %s", name, field, bad)
				}
			}
		}
	}
}

func TestSearchOrderBy(t *testing.T) {
	r, _ := listquery.New(0, 0, "", "", SecretSearchList)
	if got := SearchOrderBy(r); got != SearchRelevanceExpr+" DESC, lower(s.name) ASC, s.id ASC" {
		t.Fatal(got)
	}
	r.Order = listquery.Asc
	if got := SearchOrderBy(r); !strings.HasPrefix(got, SearchRelevanceExpr+" ASC, ") {
		t.Fatal(got)
	}
	r, _ = listquery.New(0, 0, "name", "", SecretSearchList)
	if got := SearchOrderBy(r); got != "lower(s.name) ASC NULLS LAST, s.id ASC" {
		t.Fatal(got)
	}
}

func TestListRequestDefaults(t *testing.T) {
	if r := ListRequest(listquery.Request{}, AuditList); r.Page != 1 || r.PageSize != 50 || r.Sort != "ts" || r.Order != listquery.Desc {
		t.Fatalf("%+v", r)
	}
	if r := ListRequest(listquery.Request{Sort: "password"}, SecretList); r.Sort != "name" || r.PageSize != 25 {
		t.Fatalf("invalid falls back: %+v", r)
	}
	if got := qualify("id, tenant_id,name", "sh."); got != "sh.id, sh.tenant_id, sh.name" {
		t.Fatal(got)
	}
}
