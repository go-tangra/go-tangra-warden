//go:build integration

package integration

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/go-freya/freya/services/warden/internal/store"
)

var shareLinkRE = regexp.MustCompile(`https://\S+/warden/share#([A-Za-z0-9_-]{43})`)

// TestShare: the recipient gets the link by mail, opens once and sees the
// password, a second open is refused, expired/cancelled/CIDR-mismatched
// shares are refused uniformly, and the token never lands in the database,
// the audit trail or the logs.
func TestShare(t *testing.T) {
	e := StartPlatform(t)
	owner, tid := e.CreateTenant("acme", "owner@acme.test")
	viewerU := e.Invite(owner, "viewer@acme.test", "member")
	code, sec := owner.JSON(http.MethodPost, "/api/warden/v1/secrets", map[string]any{"name": "db", "username": "root", "host_url": "https://db", "password": "WARDEN-MARKER-PW-share"})
	if code != 201 {
		t.Fatalf("secret → %d %v", code, sec)
	}
	sid := sec["id"].(string)
	if code, _ := owner.JSON(http.MethodPost, "/api/warden/v1/grants", map[string]any{"resource_type": "secret", "resource_id": sid, "subject_type": "user", "subject_id": viewerU.UserID, "relation": "viewer"}); code != 201 {
		t.Fatal("grant viewer")
	}
	if code, out := viewerU.JSON(http.MethodPost, "/api/warden/v1/secrets/"+sid+"/shares", map[string]any{"recipient_email": "friend@outside.test"}); code != 403 {
		t.Fatalf("viewer share → %d %v", code, out)
	}
	code, sh := owner.JSON(http.MethodPost, "/api/warden/v1/secrets/"+sid+"/shares", map[string]any{"recipient_email": "friend@outside.test", "message": "for the migration"})
	if code != 201 || sh["max_opens"] != float64(1) {
		t.Fatalf("share → %d %v", code, sh)
	}
	mail := e.LastMail("friend@outside.test")
	m := shareLinkRE.FindStringSubmatch(mail)
	if m == nil {
		t.Fatalf("no link in mail: %s", mail)
	}
	link, token := m[0], m[1]
	if !strings.Contains(mail, "for the migration") {
		t.Fatal("message missing from the mail")
	}
	anon := e.NewSession("", "")
	resp := anon.Raw(http.MethodGet, strings.SplitN(strings.TrimPrefix(link, e.Base), "#", 2)[0], nil, "")
	page := readAll(resp)
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" || strings.Contains(page, "WARDEN-MARKER") {
		t.Fatalf("page → %d %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	code, out := anon.JSON(http.MethodPost, "/api/warden/v1/share/open", map[string]any{"token": token})
	if code != 200 || out["password"] != "WARDEN-MARKER-PW-share" || out["name"] != "db" || out["opens_left"] != float64(0) {
		t.Fatalf("open → %d %v", code, out)
	}
	if code, out := anon.JSON(http.MethodPost, "/api/warden/v1/share/open", map[string]any{"token": token}); code != 404 || out["reason"] != "not_found" {
		t.Fatalf("second open → %d %v", code, out)
	}
	// Expired share.
	code, exp := owner.JSON(http.MethodPost, "/api/warden/v1/secrets/"+sid+"/shares", map[string]any{"recipient_email": "late@outside.test", "validity_seconds": 300})
	if code != 201 {
		t.Fatalf("expiring share → %d %v", code, exp)
	}
	expTok := shareLinkRE.FindStringSubmatch(e.LastMail("late@outside.test"))[1]
	if err := e.Warden.Store.Tx(context.Background(), store.Scope{System: true}, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), "UPDATE shares SET expires_at = now() - interval '1 minute' WHERE id = $1", exp["id"])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if code, _ := anon.JSON(http.MethodPost, "/api/warden/v1/share/open", map[string]any{"token": expTok}); code != 404 {
		t.Fatal("expired share opened")
	}
	if n, err := e.Warden.Shares.Sweep(context.Background()); err != nil || n < 1 {
		t.Fatalf("sweep %d %v", n, err)
	}
	// Cancelled share.
	_, can := owner.JSON(http.MethodPost, "/api/warden/v1/secrets/"+sid+"/shares", map[string]any{"recipient_email": "cancel@outside.test"})
	canTok := shareLinkRE.FindStringSubmatch(e.LastMail("cancel@outside.test"))[1]
	if code, _ := owner.JSON(http.MethodPost, "/api/warden/v1/shares/"+can["id"].(string)+"/cancel", nil); code != 204 {
		t.Fatal("cancel")
	}
	if code, _ := anon.JSON(http.MethodPost, "/api/warden/v1/share/open", map[string]any{"token": canTok}); code != 404 {
		t.Fatal("cancelled share opened")
	}
	// CIDR policy against the address the gateway relays (loopback here).
	_, _ = owner.JSON(http.MethodPost, "/api/warden/v1/secrets/"+sid+"/shares", map[string]any{"recipient_email": "net@outside.test", "cidr": "203.0.113.0/24"})
	netTok := shareLinkRE.FindStringSubmatch(e.LastMail("net@outside.test"))[1]
	if code, _ := anon.JSON(http.MethodPost, "/api/warden/v1/share/open", map[string]any{"token": netTok}); code != 404 {
		t.Fatal("cidr mismatch opened")
	}
	_, _ = owner.JSON(http.MethodPost, "/api/warden/v1/secrets/"+sid+"/shares", map[string]any{"recipient_email": "local@outside.test", "cidr": "127.0.0.0/8"})
	localTok := shareLinkRE.FindStringSubmatch(e.LastMail("local@outside.test"))[1]
	if code, out := anon.JSON(http.MethodPost, "/api/warden/v1/share/open", map[string]any{"token": localTok}); code != 200 {
		t.Fatalf("cidr match → %d %v", code, out)
	}
	// A spoofed client address header from the outside is dropped by the gateway.
	_, _ = owner.JSON(http.MethodPost, "/api/warden/v1/secrets/"+sid+"/shares", map[string]any{"recipient_email": "spoof@outside.test", "cidr": "203.0.113.0/24"})
	spoofTok := shareLinkRE.FindStringSubmatch(e.LastMail("spoof@outside.test"))[1]
	if code, _ := anon.JSON(http.MethodPost, "/api/warden/v1/share/open", map[string]any{"token": spoofTok}, "X-Gateway-Client-Addr", "203.0.113.7"); code != 404 {
		t.Fatal("spoofed address honoured")
	}
	code, list := owner.JSON(http.MethodGet, "/api/warden/v1/secrets/"+sid+"/shares", nil)
	if code != 200 || len(list["items"].([]any)) != 6 {
		t.Fatalf("list → %d %v", code, list)
	}
	if e.AuditCount(tid, "share_created", "ok") != 6 || e.AuditCount(tid, "share_opened", "ok") != 2 || e.AuditCount(tid, "share_refused", "refused") < 4 || e.AuditCount(tid, "share_cancelled", "ok") != 1 {
		t.Fatalf("audit: created %d opened %d refused %d", e.AuditCount(tid, "share_created", "ok"), e.AuditCount(tid, "share_opened", "ok"), e.AuditCount(tid, "share_refused", "refused"))
	}
	rows := e.AuditRows(tid, "share_opened")
	if rows[0].ActorKind != "recipient" || !strings.HasSuffix(rows[0].ActorID, "@outside.test") {
		t.Fatalf("%+v", rows[0])
	}
	// The tokens exist nowhere but in the mails.
	e.ScanForMaterial(t, []string{token, expTok, canTok, netTok, localTok, spoofTok, "WARDEN-MARKER-PW-"})
}

func readAll(resp *http.Response) string {
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			return b.String()
		}
	}
}
