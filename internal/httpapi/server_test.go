package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/go-freya/freya/internal/testrt"
	"github.com/go-freya/freya/internal/testutil"
	"github.com/go-freya/freya/services/auth/pkg/authclient"
	"github.com/go-freya/freya/services/warden/internal/store"
	"github.com/go-freya/freya/services/warden/internal/vault"
)

const issuer = "https://localhost:8443"

type signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newSigner() signer {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return signer{priv, pub}
}

func (s signer) mint(sub, tid string, roles []string) string {
	now := time.Now()
	c := authclient.Claims{RegisteredClaims: jwt.RegisteredClaims{Issuer: issuer, Subject: sub, IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)), ID: "j1"}, TenantID: tid, SessionID: "s1", Roles: roles, AMR: []string{"pwd"}}
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
	t.Header["kid"] = "k1"
	out, _ := t.SignedString(s.priv)
	return out
}

func newTestServer(t *testing.T, opts ...Option) (*Server, signer) {
	t.Helper()
	sg := newSigner()
	v := authclient.New(authclient.Config{Issuer: issuer}, authclient.StaticKeys{"k1": sg.pub}, nil)
	if err := v.RefreshKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	rt := testrt.New(t, testutil.MustCA("example.org"), "warden")
	s, err := NewHandler(rt, append([]Option{WithVerifier(v)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return s, sg
}

func do(s *Server, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://localhost"+path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func auth(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

func TestDeclaredRoutesMountedAndAuthenticated(t *testing.T) {
	s, sg := newTestServer(t)
	if len(s.Declared()) < 40 {
		t.Fatalf("declared %d", len(s.Declared()))
	}
	tok := sg.mint("u1", "t1", []string{"member"})
	forged := newSigner().mint("u1", "t1", nil)
	// Unimplemented but declared → 501 only after authentication.
	if w := do(s, "GET", "/api/warden/v1/stats", "", nil); w.Code != 401 || !strings.Contains(w.Body.String(), "unauthenticated") || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("no token: %d %s", w.Code, w.Body)
	}
	if w := do(s, "GET", "/api/warden/v1/stats", "", auth(forged)); w.Code != 401 {
		t.Fatalf("forged: %d %s", w.Code, w.Body)
	}
	if w := do(s, "GET", "/api/warden/v1/stats", "", auth(tok)); w.Code != 501 || !strings.Contains(w.Body.String(), "not_implemented") {
		t.Fatalf("declared: %d %s", w.Code, w.Body)
	}
	// Security headers on every response.
	w := do(s, "GET", "/api/warden/v1/stats", "", auth(tok))
	for k, v := range map[string]string{"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY"} {
		if w.Header().Get(k) != v {
			t.Errorf("%s = %q", k, w.Header().Get(k))
		}
	}
	// Identity from the token reaches the handler.
	s.MustHandle("GET", "/api/warden/v1/stats", func(w http.ResponseWriter, r *http.Request) {
		id, err := Caller(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		WriteJSON(w, 200, map[string]any{"user": id.UserID, "tenant": id.TenantID, "roles": id.Roles, "rid": RequestID(r), "addr": ClientAddr(r), "nonce": Nonce(r)})
	})
	w = do(s, "GET", "/api/warden/v1/stats", "", map[string]string{"Authorization": "Bearer " + tok, "X-Request-Id": "r1", "X-Gateway-Client-Addr": " 10.0.0.1 ", "X-CSP-Nonce": "n1"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"tenant":"t1"`) || !strings.Contains(w.Body.String(), `"member"`) || !strings.Contains(w.Body.String(), `"rid":"r1"`) || !strings.Contains(w.Body.String(), `"addr":"10.0.0.1"`) || !strings.Contains(w.Body.String(), `"nonce":"n1"`) {
		t.Fatalf("identity: %d %s", w.Code, w.Body)
	}
	if len(s.Implemented()) != 1 || len(s.Missing()) != len(s.Declared())-1 {
		t.Fatalf("implemented %v", s.Implemented())
	}
	// Undeclared routes are refused at wiring time.
	if err := s.HandleFunc("GET", "/api/warden/v1/nope", nil); err == nil {
		t.Fatal("expected undeclared error")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic")
			}
		}()
		s.MustHandle("GET", "/nope", nil)
	}()
	// 404 for unknown paths, 405 for wrong methods.
	if w := do(s, "GET", "/api/warden/v1/nope", "", auth(tok)); w.Code != 404 {
		t.Fatalf("404: %d", w.Code)
	}
	if w := do(s, "PATCH", "/api/warden/v1/stats", "", auth(tok)); w.Code != 405 {
		t.Fatalf("405: %d", w.Code)
	}
}

func TestPublicRoutesSkipAuthentication(t *testing.T) {
	s, _ := newTestServer(t)
	if !s.IsPublic("POST", "/api/warden/v1/share/open") || !s.IsPublic("GET", "/warden/share") || s.IsPublic("GET", "/api/warden/v1/stats") {
		t.Fatal("public flags")
	}
	tok43 := strings.Repeat("a", 43)
	if w := do(s, "POST", "/api/warden/v1/share/open", `{"token":"`+tok43+`"}`, nil); w.Code != 501 {
		t.Fatalf("public: %d %s", w.Code, w.Body)
	}
	if w := do(s, "GET", "/warden/share", "", nil); w.Code != 501 {
		t.Fatalf("public page: %d %s", w.Code, w.Body)
	}
	// Still validated.
	if w := do(s, "POST", "/api/warden/v1/share/open", `{"token":"short"}`, nil); w.Code != 400 || !strings.Contains(w.Body.String(), "validation_failed") {
		t.Fatalf("validation: %d %s", w.Code, w.Body)
	}
	// Without a verifier every non-public route is refused.
	rt := testrt.New(t, testutil.MustCA("example.org"), "warden")
	bare, err := NewHandler(rt)
	if err != nil {
		t.Fatal(err)
	}
	if w := do(bare, "GET", "/api/warden/v1/stats", "", nil); w.Code != 401 {
		t.Fatalf("bare: %d", w.Code)
	}
	if w := do(bare, "POST", "/api/warden/v1/share/open", `{"token":"`+tok43+`"}`, nil); w.Code != 501 {
		t.Fatalf("bare public: %d", w.Code)
	}
}

func TestValidation(t *testing.T) {
	s, sg := newTestServer(t)
	tok := sg.mint("u1", "t1", nil)
	h := auth(tok)
	// Unknown field, bad uuid, malformed JSON, over-long name.
	if w := do(s, "POST", "/api/warden/v1/folders", `{"name":"x","extra":1}`, h); w.Code != 400 || !strings.Contains(w.Body.String(), "validation_failed") {
		t.Fatalf("unknown field: %d %s", w.Code, w.Body)
	}
	if w := do(s, "GET", "/api/warden/v1/folders/not-a-uuid", "", h); w.Code != 400 {
		t.Fatalf("uuid: %d %s", w.Code, w.Body)
	}
	if w := do(s, "POST", "/api/warden/v1/folders", `{"name":`, h); w.Code != 400 || !strings.Contains(w.Body.String(), "malformed_body") {
		t.Fatalf("malformed: %d %s", w.Code, w.Body)
	}
	if w := do(s, "POST", "/api/warden/v1/folders", `{"name":"`+strings.Repeat("x", 101)+`"}`, h); w.Code != 400 {
		t.Fatalf("length: %d %s", w.Code, w.Body)
	}
	if w := do(s, "POST", "/api/warden/v1/folders", `{"name":"a/b"}`, h); w.Code != 400 {
		t.Fatalf("pattern: %d %s", w.Code, w.Body)
	}
	if w := do(s, "GET", "/api/warden/v1/secrets?limit=1000", "", h); w.Code != 400 {
		t.Fatalf("limit: %d %s", w.Code, w.Body)
	}
	// Valid → reaches the (unimplemented) handler.
	if w := do(s, "POST", "/api/warden/v1/folders", `{"name":"ok"}`, h); w.Code != 501 {
		t.Fatalf("valid: %d %s", w.Code, w.Body)
	}
	// JSON bodies above 64 KiB are refused; transfer routes accept 16 MiB and refuse above.
	big := `{"name":"` + strings.Repeat("x", MaxBodyBytes) + `"}`
	if w := do(s, "POST", "/api/warden/v1/folders", big, h); w.Code != 413 || !strings.Contains(w.Body.String(), "body_too_large") {
		t.Fatalf("json limit: %d %s", w.Code, w.Body)
	}
	var seen int64
	s.MustHandle("POST", "/api/warden/v1/transfer/bitwarden/validate", func(w http.ResponseWriter, r *http.Request) {
		var v map[string]any
		if err := DecodeJSON(r, &v, 16<<20); err != nil {
			Fail(w, r, nil, err)
			return
		}
		seen = int64(len(v["items"].(string)))
		w.WriteHeader(200)
	})
	payload := `{"items":"` + strings.Repeat("y", 1<<20) + `"}`
	if w := do(s, "POST", "/api/warden/v1/transfer/bitwarden/validate", payload, h); w.Code != 200 || seen != 1<<20 {
		t.Fatalf("binary route: %d %s (%d)", w.Code, w.Body, seen)
	}
	huge := `{"items":"` + strings.Repeat("y", 16<<20) + `"}`
	if w := do(s, "POST", "/api/warden/v1/transfer/bitwarden/validate", huge, h); w.Code != 413 {
		t.Fatalf("binary limit: %d %s", w.Code, w.Body)
	}
}

func TestErrorsNeverLeak(t *testing.T) {
	log := slog.New(slog.NewTextHandler(&strings.Builder{}, nil))
	for _, tc := range []struct {
		err    error
		status int
		reason string
	}{
		{errors.New("pgx: connection refused at 10.0.0.1"), 503, "temporarily_unavailable"},
		{store.ErrNotFound, 404, "not_found"},
		{vault.ErrNotFound, 404, "not_found"},
		{store.ErrConflict, 409, "conflict"},
		{vault.ErrUnavailable, 503, "vault_unavailable"},
		{ErrForbidden, 403, "forbidden"},
		{&http.MaxBytesError{}, 413, "body_too_large"},
	} {
		r := httptest.NewRequest("GET", "/x", nil)
		w := httptest.NewRecorder()
		Fail(w, r, log, tc.err)
		if w.Code != tc.status || w.Body.String() != `{"reason":"`+tc.reason+`"}`+"\n" {
			t.Errorf("%v: %d %s", tc.err, w.Code, w.Body)
		}
	}
	if ErrForbidden.Error() != "forbidden" {
		t.Fatal("Error()")
	}
}

func TestDecodeJSON(t *testing.T) {
	var v struct{ A int }
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"A":1}`))
	if err := DecodeJSON(r, &v, 0); err != nil || v.A != 1 {
		t.Fatal(err)
	}
	for _, body := range []string{`{"B":1}`, `{"A":1} x`, `{`} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		if err := DecodeJSON(r, &v, 0); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: %v", body, err)
		}
	}
	r = httptest.NewRequest("POST", "/", strings.NewReader(`{"A":1234567890}`))
	if err := DecodeJSON(r, &v, 4); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("limit: %v", err)
	}
}

func TestRemoteServing(t *testing.T) {
	s, _ := newTestServer(t, WithRemote(fstest.MapFS{
		"mf-manifest.json": {Data: []byte(`{"id":"warden"}`)},
		"assets/a.js":      {Data: []byte("1")},
		"dir/index.html":   {Data: []byte("x")},
	}))
	if w := do(s, "GET", "/ui/mf-manifest.json", "", nil); w.Code != 200 || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("manifest: %d %s", w.Code, w.Header())
	}
	if w := do(s, "GET", "/ui/assets/a.js", "", nil); w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset: %d", w.Code)
	}
	for _, p := range []string{"/ui/", "/ui/dir/", "/ui/missing.js"} {
		if w := do(s, "GET", p, "", nil); w.Code != 404 {
			t.Fatalf("%s: %d", p, w.Code)
		}
	}
}

func TestExtensionInt(t *testing.T) {
	for _, v := range []any{float64(3), 3, int64(3)} {
		if n, ok := extensionInt(v); !ok || n != 3 {
			t.Errorf("%T", v)
		}
	}
	if _, ok := extensionInt("3"); ok {
		t.Error("string accepted")
	}
	if !extensionBool(true) || extensionBool("true") {
		t.Error("bool")
	}
}
