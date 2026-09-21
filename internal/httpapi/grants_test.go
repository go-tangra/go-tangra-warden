package httpapi

import (
	"strings"
	"testing"
	"time"
)

func TestGrantRoutes(t *testing.T) {
	st := newStory(t)
	_, infra := st.call(st.alice, "POST", "/api/warden/v1/folders", `{"name":"Infra"}`)
	infraID := infra["id"].(string)
	_, db := st.call(st.alice, "POST", "/api/warden/v1/folders", `{"parent_id":"`+infraID+`","name":"Databases"}`)
	dbID := db["id"].(string)
	_, sec := st.call(st.alice, "POST", "/api/warden/v1/secrets", `{"folder_id":"`+dbID+`","name":"prod","password":"p"}`)
	secID := sec["id"].(string)
	// Schema: enums, uuid, past expiry.
	for _, body := range []string{
		`{"resource_type":"thing","resource_id":"` + infraID + `","subject_type":"role","subject_id":"ops","relation":"viewer"}`,
		`{"resource_type":"folder","resource_id":"nope","subject_type":"role","subject_id":"ops","relation":"viewer"}`,
		`{"resource_type":"folder","resource_id":"` + infraID + `","subject_type":"group","subject_id":"ops","relation":"viewer"}`,
		`{"resource_type":"folder","resource_id":"` + infraID + `","subject_type":"role","subject_id":"ops","relation":"admin"}`,
		`{"resource_type":"folder","resource_id":"` + infraID + `","subject_type":"role","subject_id":"ops","relation":"viewer","expires_at":"2000-01-01T00:00:00Z"}`,
		`{"resource_type":"folder","resource_id":"` + infraID + `","subject_type":"tenant","subject_id":"x","relation":"viewer"}`,
	} {
		if code, out := st.call(st.alice, "POST", "/api/warden/v1/grants", body); code != 400 || out["reason"] != "validation_failed" {
			t.Fatalf("%s: %d %v", body, code, out)
		}
	}
	// Bob has no share: 403; foreign tenant: 404.
	grant := `{"resource_type":"folder","resource_id":"` + infraID + `","subject_type":"role","subject_id":"ops","relation":"viewer"}`
	if code, out := st.call(st.bob, "POST", "/api/warden/v1/grants", grant); code != 403 || out["reason"] != "forbidden" {
		t.Fatalf("bob: %d %v", code, out)
	}
	if code, out := st.call(st.other, "POST", "/api/warden/v1/grants", grant); code != 404 {
		t.Fatalf("other: %d %v", code, out)
	}
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	code, g := st.call(st.alice, "POST", "/api/warden/v1/grants", `{"resource_type":"folder","resource_id":"`+infraID+`","subject_type":"role","subject_id":"ops","relation":"viewer","expires_at":"`+exp+`"}`)
	if code != 201 || g["relation"] != "viewer" || g["expires_at"] == nil {
		t.Fatalf("%d %v", code, g)
	}
	gid := g["id"].(string)
	// Bob (ops) now reads three levels down but cannot write; check and effective explain it.
	if code, _ := st.call(st.bob, "GET", "/api/warden/v1/secrets/"+secID, ""); code != 200 {
		t.Fatal("inherited read")
	}
	if code, out := st.call(st.bob, "GET", "/api/warden/v1/access/check?resource_type=secret&resource_id="+secID+"&permission=write", ""); code != 200 || out["allowed"] != false || out["relation"] != "viewer" {
		t.Fatalf("check: %d %v", code, out)
	}
	if code, _ := st.call(st.bob, "GET", "/api/warden/v1/access/check?resource_type=secret&resource_id="+secID+"&permission=admin", ""); code != 400 {
		t.Fatal("check enum")
	}
	code, eff := st.call(st.bob, "GET", "/api/warden/v1/access/effective?resource_type=secret&resource_id="+secID, "")
	if code != 200 || eff["permissions"].(map[string]any)["read"] != true || len(eff["grants"].([]any)) != 1 || eff["grants"].([]any)[0].(map[string]any)["inherited"] != true {
		t.Fatalf("effective: %d %v", code, eff)
	}
	// Accessible resources for bob: 2 folders + 1 secret; paged.
	code, acc := st.call(st.bob, "GET", "/api/warden/v1/access/resources?limit=2", "")
	if code != 200 || len(acc["items"].([]any)) != 2 || acc["next"] == "" {
		t.Fatalf("resources: %d %v", code, acc)
	}
	code, acc2 := st.call(st.bob, "GET", "/api/warden/v1/access/resources?cursor="+acc["next"].(string), "")
	if code != 200 || len(acc2["items"].([]any)) != 1 {
		t.Fatalf("resources page 2: %d %v", code, acc2)
	}
	if code, out := st.call(st.bob, "GET", "/api/warden/v1/access/resources?permission=write", ""); code != 200 || len(out["items"].([]any)) != 0 {
		t.Fatalf("write resources: %d %v", code, out)
	}
	// Listing grants on the secret includes the inherited one; bob (viewer) has no share → 403.
	code, list := st.call(st.alice, "GET", "/api/warden/v1/grants?resource_type=secret&resource_id="+secID, "")
	if code != 200 || len(list["items"].([]any)) != 4 { // three creator-owner grants and the role grant
		t.Fatalf("list: %d %v", code, list)
	}
	if code, _ := st.call(st.bob, "GET", "/api/warden/v1/grants?resource_type=secret&resource_id="+secID, ""); code != 403 {
		t.Fatal("bob list")
	}
	if code, _ := st.call(st.alice, "GET", "/api/warden/v1/grants?resource_type=secret", ""); code != 400 {
		t.Fatal("list requires resource_id")
	}
	// A sharer may not grant above their own relation.
	if code, _ := st.call(st.alice, "POST", "/api/warden/v1/grants", `{"resource_type":"secret","resource_id":"`+secID+`","subject_type":"user","subject_id":"`+uB+`","relation":"sharer"}`); code != 201 {
		t.Fatal("grant sharer")
	}
	if code, out := st.call(st.bob, "POST", "/api/warden/v1/grants", `{"resource_type":"secret","resource_id":"`+secID+`","subject_type":"tenant","relation":"editor"}`); code != 403 {
		t.Fatalf("above own: %d %v", code, out)
	}
	if code, _ := st.call(st.bob, "POST", "/api/warden/v1/grants", `{"resource_type":"secret","resource_id":"`+secID+`","subject_type":"tenant","relation":"viewer"}`); code != 201 {
		t.Fatal("sharer grants viewer")
	}
	// Revoke: bob cannot revoke the folder grant (no share there); alice can; twice → 404.
	if code, _ := st.call(st.bob, "POST", "/api/warden/v1/grants/"+gid+"/revoke", ""); code != 403 {
		t.Fatal("bob revoke")
	}
	if code, _ := st.call(st.alice, "POST", "/api/warden/v1/grants/"+gid+"/revoke", ""); code != 204 {
		t.Fatal("revoke")
	}
	if code, _ := st.call(st.alice, "POST", "/api/warden/v1/grants/"+gid+"/revoke", ""); code != 404 {
		t.Fatal("revoke twice")
	}
	if code, _ := st.call(st.alice, "POST", "/api/warden/v1/grants/not-a-uuid/revoke", ""); code != 400 {
		t.Fatal("revoke uuid")
	}
	if code, _ := st.call(st.alice, "POST", "/api/warden/v1/grants", `{`); code != 400 {
		t.Fatal("malformed")
	}
	st.aw.Flush()
	if n := len(st.ms.AuditEvents(tA, "grant_created")); n != 3 {
		t.Fatalf("grant_created %d", n)
	}
	if n := len(st.ms.AuditEvents(tA, "grant_revoked")); n != 1 {
		t.Fatalf("grant_revoked %d", n)
	}
	body := st.raw(st.alice, "GET", "/api/warden/v1/grants?resource_type=secret&resource_id="+secID, "")
	if strings.Contains(body, "password") {
		t.Fatal("grants leak")
	}
}
