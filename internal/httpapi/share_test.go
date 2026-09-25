package httpapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-warden/v4/internal/cache"
	"github.com/go-tangra/go-tangra-warden/v4/internal/share"
)

type mailbox struct {
	sent []share.Message
	err  error
}

func (m *mailbox) Send(_ context.Context, msg share.Message) error {
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, msg)
	return nil
}

func tokenOf(t *testing.T, m share.Message) string {
	t.Helper()
	i := strings.Index(m.Vars["link"], "/warden/share#")
	if i < 0 {
		t.Fatal("no link")
	}
	return m.Vars["link"][i+len("/warden/share#"):]
}

func TestShareRoutes(t *testing.T) {
	st := newStory(t)
	mb := &mailbox{}
	shares := share.New(st.ms, st.vt, st.d.Authz, st.aw, mb, share.Config{PublicOrigin: "https://platform.example.org"})
	c := cache.New(cache.NewMemory())
	st.s.RegisterShares(ShareDeps{Shares: shares, Cache: c, OpenLimit: 3})
	_, sec := st.call(st.alice, "POST", "/api/warden/v1/secrets", `{"name":"db","username":"root","password":"`+pw+`"}`)
	id := sec["id"].(string)
	// Schema and permission refusals.
	for _, body := range []string{`{}`, `{"recipient_email":"x"}`, `{"recipient_email":"r@x.test","validity_seconds":10}`, `{"recipient_email":"r@x.test","max_opens":11}`, `{"recipient_email":"r@x.test","region":"de"}`} {
		if code, _ := st.call(st.alice, "POST", "/api/warden/v1/secrets/"+id+"/shares", body); code != 400 {
			t.Fatalf("%s: %d", body, code)
		}
	}
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/secrets/"+id+"/shares", `{"recipient_email":"r@x.test","region":"DE"}`); code != 400 || out["reason"] != "region_unavailable" {
		t.Fatalf("region: %d %v", code, out)
	}
	if code, out := st.call(st.bob, "POST", "/api/warden/v1/secrets/"+id+"/shares", `{"recipient_email":"r@x.test"}`); code != 403 || out["reason"] != "forbidden" {
		t.Fatalf("bob: %d %v", code, out)
	}
	if code, _ := st.call(st.other, "POST", "/api/warden/v1/secrets/"+id+"/shares", `{"recipient_email":"r@x.test"}`); code != 404 {
		t.Fatal("other")
	}
	code, sh := st.call(st.alice, "POST", "/api/warden/v1/secrets/"+id+"/shares", `{"recipient_email":"r@x.test","message":"hello","max_opens":2}`)
	if code != 201 || sh["state"] != "active" || sh["max_opens"] != float64(2) {
		t.Fatalf("create: %d %v", code, sh)
	}
	if _, ok := sh["token"]; ok {
		t.Fatal("token returned")
	}
	tok := tokenOf(t, mb.sent[0])
	// List and cancel permissions.
	if code, out := st.call(st.alice, "GET", "/api/warden/v1/secrets/"+id+"/shares", ""); code != 200 || len(out["items"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, out)
	}
	if code, _ := st.call(st.bob, "GET", "/api/warden/v1/secrets/"+id+"/shares", ""); code != 403 {
		t.Fatal("bob list")
	}
	// Public page: no material, no-store, nonce relayed into the inline script, token embedded for the script only.
	w := do(st.s, "GET", "/warden/share", "", map[string]string{"X-CSP-Nonce": "abc123"})
	body := w.Body.String()
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("page: %d %v", w.Code, w.Header())
	}
	if !strings.Contains(body, `nonce="abc123"`) || strings.Contains(body, pw) || strings.Contains(body, "root") || strings.Contains(body, tok) || !strings.Contains(body, "location.hash") {
		t.Fatalf("page body: %s", body)
	}
	if m := mb.sent[0]; m.Template != share.TemplateShare || m.Vars["link"] != "https://platform.example.org/warden/share#"+tok || m.Vars["message"] != "hello" || m.Vars["openings"] != "2" || m.Vars["secret_name"] != "db" {
		t.Fatalf("mail: %+v", m)
	}
	// Open: first discloses, second discloses (max 2), third 404; the client address comes only from the gateway header.
	code, out := st.call("", "POST", "/api/warden/v1/share/open", `{"token":"`+tok+`"}`)
	if code != 200 || out["password"] != pw || out["opens_left"] != float64(1) || out["message"] != "hello" {
		t.Fatalf("open: %d %v", code, out)
	}
	if code, _ := st.call("", "POST", "/api/warden/v1/share/open", `{"token":"`+tok+`"}`); code != 200 {
		t.Fatal("second open")
	}
	if code, out := st.call("", "POST", "/api/warden/v1/share/open", `{"token":"`+tok+`"}`); code != 404 || out["reason"] != "not_found" {
		t.Fatalf("third open: %d %v", code, out)
	}
	if code, out := st.call("", "POST", "/api/warden/v1/share/open", `{"token":"`+strings.Repeat("b", 43)+`"}`); code != 404 || out["reason"] != "not_found" {
		t.Fatalf("unknown: %d %v", code, out)
	}
	if code, _ := st.call("", "POST", "/api/warden/v1/share/open", `{"token":"x"}`); code != 400 {
		t.Fatal("token schema")
	}
	// CIDR share: refused without the gateway header, honoured with it.
	mb.sent = nil
	if code, _ := st.call(st.alice, "POST", "/api/warden/v1/secrets/"+id+"/shares", `{"recipient_email":"r@x.test","cidr":"10.0.0.0/8","max_opens":3}`); code != 201 {
		t.Fatal("cidr share")
	}
	ctok := tokenOf(t, mb.sent[0])
	if code, _ := st.call("", "POST", "/api/warden/v1/share/open", `{"token":"`+ctok+`"}`); code != 404 {
		t.Fatal("cidr without address")
	}
	w = do(st.s, "POST", "/api/warden/v1/share/open", `{"token":"`+ctok+`"}`, map[string]string{"X-Gateway-Client-Addr": "10.1.2.3"})
	if w.Code != 200 {
		t.Fatalf("cidr match: %d %s", w.Code, w.Body.String())
	}
	// Rate limit: the fourth attempt per address within a minute is refused.
	for i := 0; i < 3; i++ {
		do(st.s, "POST", "/api/warden/v1/share/open", `{"token":"`+strings.Repeat("c", 43)+`"}`, map[string]string{"X-Gateway-Client-Addr": "198.51.100.7"})
	}
	w = do(st.s, "POST", "/api/warden/v1/share/open", `{"token":"`+strings.Repeat("c", 43)+`"}`, map[string]string{"X-Gateway-Client-Addr": "198.51.100.7"})
	if w.Code != 429 || !strings.Contains(w.Body.String(), "rate_limited") {
		t.Fatalf("rate: %d %s", w.Code, w.Body.String())
	}
	// Notification cannot deliver: the user is told (503 unavailable) and the share is cancelled.
	mb.err = errors.New("notification unavailable")
	if code, out := st.call(st.alice, "POST", "/api/warden/v1/secrets/"+id+"/shares", `{"recipient_email":"undelivered@x.test"}`); code != 503 || out["reason"] != "temporarily_unavailable" {
		t.Fatalf("mail failure: %d %v", code, out)
	}
	mb.err = nil
	for _, row := range st.ms.Shares {
		if row.RecipientEmail == "undelivered@x.test" && row.State != "cancelled" {
			t.Fatal("undelivered share kept active")
		}
	}
	// Cancel: creator ok, twice 404, foreign 404.
	sid := sh["id"].(string)
	if code, _ := st.call(st.bob, "POST", "/api/warden/v1/shares/"+sid+"/cancel", ""); code != 403 && code != 404 {
		t.Fatal("bob cancel")
	}
	_, sh2 := st.call(st.alice, "POST", "/api/warden/v1/secrets/"+id+"/shares", `{"recipient_email":"z@x.test"}`)
	if code, _ := st.call(st.alice, "POST", "/api/warden/v1/shares/"+sh2["id"].(string)+"/cancel", ""); code != 204 {
		t.Fatal("cancel")
	}
	if code, _ := st.call(st.alice, "POST", "/api/warden/v1/shares/"+sh2["id"].(string)+"/cancel", ""); code != 404 {
		t.Fatal("cancel twice")
	}
	if code, _ := st.call(st.other, "POST", "/api/warden/v1/shares/"+sid+"/cancel", ""); code != 404 {
		t.Fatal("cancel foreign")
	}
	// Audit: created, opened (recipient), refused; never the token or material.
	st.aw.Flush()
	if n := len(st.ms.AuditEvents(tA, "share_opened")); n != 3 {
		t.Fatalf("opened %d", n)
	}
	if n := len(st.ms.AuditEvents(tA, "share_refused")); n < 2 {
		t.Fatalf("refused %d", n)
	}
	for _, r := range st.ms.Audit {
		if strings.Contains(string(r.Details), tok) || strings.Contains(string(r.Details), pw) {
			t.Fatal("audit leak")
		}
	}
	// Vault down on open → 503, malformed bodies → 400.
	st.vt.Down = true
	w = do(st.s, "POST", "/api/warden/v1/share/open", `{"token":"`+ctok+`"}`, map[string]string{"X-Gateway-Client-Addr": "10.1.2.4"})
	if w.Code != 503 || !strings.Contains(w.Body.String(), "vault_unavailable") {
		t.Fatalf("vault down: %d %s", w.Code, w.Body.String())
	}
	st.vt.Down = false
	if code, _ := st.call("", "POST", "/api/warden/v1/share/open", `{`); code != 400 {
		t.Fatal("malformed open")
	}
	if code, _ := st.call(st.alice, "POST", "/api/warden/v1/secrets/"+id+"/shares", `{`); code != 400 {
		t.Fatal("malformed create")
	}
}
