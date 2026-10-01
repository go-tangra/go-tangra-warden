package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-tangra/go-tangra/v4/listquery"

	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
)

// The browser list endpoints answer the list contract (go-tangra
// specs/032-server-side-tables, contracts/http-list.md): page, page_size,
// sort and order in, {items,total,page,page_size,sort,order} out. A request
// with only the old cursor / limit parameters keeps its old shape plus total
// for one release; mixing both styles, or any invalid list parameter, is 422
// validation_failed naming the parameter (never its value).

// ErrListParam is the refusal of an invalid list parameter.
var ErrListParam = &Error{http.StatusUnprocessableEntity, "validation_failed"}

// listParams are the query parameters of the list contract (and the legacy
// cursor style they must not be mixed with).
var listParams = map[string]bool{"page": true, "page_size": true, "sort": true, "order": true, "cursor": true}

// WriteDetail emits {"reason": ..., "detail": {...}}; detail values never
// carry request data or secrets.
func WriteDetail(w http.ResponseWriter, e *Error, detail map[string]any) {
	WriteJSON(w, e.Status, map[string]any{"reason": e.Reason, "detail": detail})
}

// serveList answers one list request: legacy runs the old cursor path and
// adds the total (counted by the paged path with one row), paged the
// list-contract page. mapErr maps service errors to refusals.
func serveList[T any](s *Server, w http.ResponseWriter, r *http.Request, spec listquery.Spec, mapErr func(error) error,
	legacy func() (map[string]any, error), paged func(listquery.Request) (listquery.Page[T], error)) {
	q := r.URL.Query()
	if legacy != nil && listquery.Legacy(q) {
		out, err := legacy()
		if err != nil {
			Fail(w, r, s.rt.Logger(), mapErr(err))
			return
		}
		count, err := paged(store.ListRequest(listquery.Request{PageSize: 1}, spec))
		if err != nil {
			Fail(w, r, s.rt.Logger(), mapErr(err))
			return
		}
		out["total"] = count.Total
		WriteJSON(w, http.StatusOK, out)
		return
	}
	req, err := listquery.Parse(q, spec)
	var le *listquery.Error
	if errors.As(err, &le) {
		WriteDetail(w, ErrListParam, map[string]any{"param": le.Param})
		return
	}
	if err != nil {
		Fail(w, r, nil, ErrListParam)
		return
	}
	pg, err := paged(req)
	if err != nil {
		Fail(w, r, s.rt.Logger(), mapErr(err))
		return
	}
	WriteJSON(w, http.StatusOK, pg)
}

// legacyPage is the old cursor shape: items and, when there is more, the
// cursor under key (omitted on the last page, as before).
func legacyPage[T any](items []T, key, next string) map[string]any {
	if items == nil {
		items = []T{}
	}
	out := map[string]any{"items": items}
	if next != "" {
		out[key] = next
	}
	return out
}
