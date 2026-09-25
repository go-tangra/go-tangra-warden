package vault

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
)

const (
	tid = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	sid = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"
)

// stub is a minimal in-memory Vault HTTP API: approle login, token
// lookup/renew, sys/health and KV v2 data/metadata under one mount.
type stub struct {
	mu        sync.Mutex
	logins    int
	sealed    bool
	deny      bool
	badToken  bool                        // lookup-self refused
	loginFail bool                        // approle login refused
	denyTOTP  bool                        // only /totp paths refused
	renewFail bool                        // renew-self refused (watcher ends → re-login)
	lease     int                         // seconds granted on login
	noMeta    bool                        // put answers without data
	nilData   bool                        // get answers with data: null
	versions  map[string][]map[string]any // path → versions (index+1)
	destroyed map[string]bool             // whole path destroyed
	gone      map[string]map[int]bool     // path → destroyed version numbers
	denyDel   bool                        // only DELETE on a data path refused
}

func newStub() *stub {
	return &stub{versions: map[string][]map[string]any{}, destroyed: map[string]bool{}, gone: map[string]map[int]bool{}, lease: 3600}
}

func (s *stub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		p := strings.TrimPrefix(r.URL.Path, "/v1/")
		switch {
		case p == "sys/health":
			if s.sealed {
				// Real Vault honours ?sealedcode=; the client asks for 299.
				w.WriteHeader(299)
				_ = json.NewEncoder(w).Encode(map[string]any{"initialized": true, "sealed": true})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"initialized": true, "sealed": false})
		case p == "auth/approle/login":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["role_id"] != "role" || in["secret_id"] != "secret" || s.loginFail {
				w.WriteHeader(400)
				_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"invalid role or secret ID"}})
				return
			}
			s.logins++
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "tok", "renewable": true, "lease_duration": s.lease}})
		case p == "auth/token/lookup-self":
			if r.Header.Get("X-Vault-Token") != "tok" || s.badToken {
				w.WriteHeader(403)
				_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": s.lease}})
		case p == "auth/token/renew-self":
			if s.renewFail {
				w.WriteHeader(500)
				_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "tok", "renewable": true, "lease_duration": s.lease}})
		case strings.HasPrefix(p, "warden/data/"):
			if s.deny || (s.denyTOTP && strings.HasSuffix(p, "/totp")) {
				w.WriteHeader(403)
				_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
				return
			}
			key := strings.TrimPrefix(p, "warden/data/")
			switch r.Method {
			case http.MethodPost, http.MethodPut:
				var in struct {
					Data map[string]any `json:"data"`
				}
				_ = json.NewDecoder(r.Body).Decode(&in)
				s.versions[key] = append(s.versions[key], in.Data)
				if s.noMeta {
					_ = json.NewEncoder(w).Encode(map[string]any{})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": len(s.versions[key]), "created_time": time.Now().UTC().Format(time.RFC3339)}})
			case http.MethodDelete: // soft-delete of the latest version
				if s.denyDel {
					w.WriteHeader(403)
					_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
					return
				}
				if s.gone[key] == nil {
					s.gone[key] = map[int]bool{}
				}
				s.gone[key][len(s.versions[key])] = true
				w.WriteHeader(204)
			case http.MethodGet:
				vs := s.versions[key]
				if len(vs) == 0 || s.destroyed[key] {
					w.WriteHeader(404)
					_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
					return
				}
				n := len(vs)
				if q := r.URL.Query().Get("version"); q != "" {
					_, _ = json.Number(q).Int64()
					var v int
					_, _ = fmtSscan(q, &v)
					if v < 1 || v > len(vs) {
						w.WriteHeader(404)
						_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
						return
					}
					n = v
				}
				var data any = vs[n-1]
				if s.nilData {
					data = nil
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": data, "metadata": map[string]any{"version": n, "created_time": time.Now().UTC().Format(time.RFC3339), "deletion_time": "", "destroyed": s.gone[key][n]}}})
			}
		case strings.HasPrefix(p, "warden/metadata/"):
			key := strings.TrimPrefix(p, "warden/metadata/")
			switch r.Method {
			case http.MethodDelete:
				if s.deny || (s.denyTOTP && strings.HasSuffix(p, "/totp")) {
					w.WriteHeader(403)
					_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
					return
				}
				if _, ok := s.versions[key]; !ok {
					w.WriteHeader(404)
					_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
					return
				}
				delete(s.versions, key)
				w.WriteHeader(204)
			case http.MethodGet:
				vs := s.versions[key]
				if len(vs) == 0 {
					w.WriteHeader(404)
					_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
					return
				}
				meta := map[string]any{}
				for i := range vs {
					meta[jsonInt(i+1)] = map[string]any{"created_time": time.Now().UTC().Format(time.RFC3339), "deletion_time": "", "destroyed": s.gone[key][i+1]}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"current_version": len(vs), "versions": meta}})
			}
		default:
			w.WriteHeader(404)
		}
	})
}

func jsonInt(i int) string { return strings.TrimSpace(strings.Repeat(" ", 0) + itoa(i)) }
func itoa(i int) string    { b, _ := json.Marshal(i); return string(b) }
func fmtSscan(s string, v *int) (int, error) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errors.New("nan")
		}
		n = n*10 + int(r-'0')
	}
	*v = n
	return 1, nil
}

func newClient(t *testing.T, s *stub) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	c, err := New(context.Background(), Options{Address: srv.URL, Mount: "warden", RoleID: "role", SecretID: "secret", AllowPlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, srv
}

func TestPathGrammar(t *testing.T) {
	if p, err := Path(tid, sid); err != nil || p != tid+"/secrets/"+sid {
		t.Fatal(p, err)
	}
	for _, bad := range [][2]string{{"../x", sid}, {tid, "../../other"}, {"", sid}, {tid, "not-a-uuid"}, {strings.ToUpper(tid), sid}} {
		if _, err := Path(bad[0], bad[1]); !errors.Is(err, ErrBadPath) {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestClientLoginAndKV(t *testing.T) {
	s := newStub()
	c, _ := newClient(t, s)
	ctx := context.Background()
	if c.Health(ctx) != HealthOK {
		t.Fatal("health")
	}
	v1, err := c.PutPassword(ctx, tid, sid, "one")
	v2, err2 := c.PutPassword(ctx, tid, sid, "two")
	if err != nil || err2 != nil || v1 != 1 || v2 != 2 {
		t.Fatalf("%d %d %v %v", v1, v2, err, err2)
	}
	if cur, _ := c.GetPassword(ctx, tid, sid, 0); cur != "two" {
		t.Fatal(cur)
	}
	if old, _ := c.GetPassword(ctx, tid, sid, 1); old != "one" {
		t.Fatal(old)
	}
	if _, err := c.GetPassword(ctx, tid, sid, 9); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing version: %v", err)
	}
	if vs, _ := c.Versions(ctx, tid, sid); len(vs) != 2 || vs[0] != 1 {
		t.Fatal(vs)
	}
	if err := c.PutTOTP(ctx, tid, sid, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	if seed, _ := c.GetTOTP(ctx, tid, sid); seed != "JBSWY3DPEHPK3PXP" {
		t.Fatal(seed)
	}
	if err := c.DeleteTOTP(ctx, tid, sid); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetTOTP(ctx, tid, sid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted seed: %v", err)
	}
	if err := c.DeleteSecret(ctx, tid, sid); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetPassword(ctx, tid, sid, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("destroyed: %v", err)
	}
	if _, err := c.GetPassword(ctx, "nope", sid, 0); !errors.Is(err, ErrBadPath) {
		t.Fatal("path grammar must be enforced on every call")
	}
	// Permission denied and sealed states fail closed with no material in the error.
	s.mu.Lock()
	s.deny = true
	s.mu.Unlock()
	if _, err := c.PutPassword(ctx, tid, sid, "secret-material"); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "secret-material") {
		t.Fatalf("denied: %v", err)
	}
	s.mu.Lock()
	s.deny, s.sealed = false, true
	s.mu.Unlock()
	if c.Health(ctx) != HealthSealed {
		t.Fatal("sealed health")
	}
}

func TestClientRefusals(t *testing.T) {
	if _, err := New(context.Background(), Options{Address: "http://127.0.0.1:1", Mount: "warden", RoleID: "r", SecretID: "s"}); err == nil {
		t.Fatal("plaintext must be refused without allow_plaintext")
	}
	if _, err := New(context.Background(), Options{Address: "http://127.0.0.1:1", Mount: "warden", AllowPlaintext: true}); err == nil {
		t.Fatal("credentials required")
	}
	s := newStub()
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	if _, err := New(context.Background(), Options{Address: srv.URL, Mount: "warden", RoleID: "wrong", SecretID: "secret", AllowPlaintext: true}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("bad approle: %v", err)
	}
	c, err := New(context.Background(), Options{Address: srv.URL, Mount: "warden", RoleID: "role", SecretID: "secret", AllowPlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	srv.Close()
	if c.Health(context.Background()) != HealthUnreachable {
		t.Fatal("unreachable")
	}
	if _, err := c.GetPassword(context.Background(), tid, sid, 0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unreachable read: %v", err)
	}
}

func TestLoadCredential(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "role_id")
	_ = os.WriteFile(p, []byte("  abc\n"), 0o600)
	if v, err := LoadCredential(p); err != nil || v != "abc" {
		t.Fatal(v, err)
	}
	_ = os.WriteFile(p, []byte("\n"), 0o600)
	if _, err := LoadCredential(p); err == nil {
		t.Fatal("empty file")
	}
	if _, err := LoadCredential(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file")
	}
}

func TestFakeSemantics(t *testing.T) {
	f := NewFake()
	ctx := context.Background()
	v, _ := f.PutPassword(ctx, tid, sid, "a")
	v2, _ := f.PutPassword(ctx, tid, sid, "b")
	if v != 1 || v2 != 2 {
		t.Fatal(v, v2)
	}
	if cur, _ := f.GetPassword(ctx, tid, sid, 0); cur != "b" {
		t.Fatal(cur)
	}
	if vs, _ := f.Versions(ctx, tid, sid); len(vs) != 2 {
		t.Fatal(vs)
	}
	_ = f.PutTOTP(ctx, tid, sid, "seed")
	if s, _ := f.GetTOTP(ctx, tid, sid); s != "seed" {
		t.Fatal(s)
	}
	_ = f.DeleteTOTP(ctx, tid, sid)
	if _, err := f.GetTOTP(ctx, tid, sid); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.GetPassword(ctx, tid, sid, 5); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.PutPassword(ctx, "bad", sid, "x"); !errors.Is(err, ErrBadPath) {
		t.Fatal(err)
	}
	f.FailAfter = 3
	if _, err := f.PutPassword(ctx, tid, sid, "c"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("fail-after")
	}
	f.FailAfter = 0
	f.Down = true
	if _, err := f.GetPassword(ctx, tid, sid, 0); !errors.Is(err, ErrUnavailable) || f.Health(ctx) != HealthUnreachable {
		t.Fatal("down")
	}
	for _, op := range []func() error{
		func() error { _, err := f.Versions(ctx, tid, sid); return err },
		func() error { return f.DeleteSecret(ctx, tid, sid) },
		func() error { return f.PutTOTP(ctx, tid, sid, "s") },
		func() error { _, err := f.GetTOTP(ctx, tid, sid); return err },
		func() error { return f.DeleteTOTP(ctx, tid, sid) },
	} {
		if err := op(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("down op: %v", err)
		}
	}
	f.Down = false
	if err := f.DeleteSecret(ctx, tid, sid); err != nil {
		t.Fatal(err)
	}
	if len(f.Dump()) != 0 {
		t.Fatal("dump after delete")
	}
	for _, bad := range []func() error{
		func() error { _, err := f.GetPassword(ctx, "x", sid, 0); return err },
		func() error { _, err := f.Versions(ctx, "x", sid); return err },
		func() error { return f.DeleteSecret(ctx, "x", sid) },
		func() error { return f.PutTOTP(ctx, "x", sid, "s") },
		func() error { _, err := f.GetTOTP(ctx, "x", sid); return err },
		func() error { return f.DeleteTOTP(ctx, "x", sid) },
	} {
		if err := bad(); !errors.Is(err, ErrBadPath) {
			t.Fatalf("bad path: %v", err)
		}
	}
}

func TestClientEdgeCases(t *testing.T) {
	s := newStub()
	c, _ := newClient(t, s)
	ctx := context.Background()
	key := tid + "/secrets/" + sid
	for _, pw := range []string{"one", "two", "three"} {
		if _, err := c.PutPassword(ctx, tid, sid, pw); err != nil {
			t.Fatal(err)
		}
	}
	// A destroyed version is skipped by Versions and refused by GetPassword.
	s.mu.Lock()
	s.gone[key] = map[int]bool{2: true}
	s.mu.Unlock()
	if vs, _ := c.Versions(ctx, tid, sid); len(vs) != 2 || vs[1] != 3 {
		t.Fatalf("%v", vs)
	}
	if _, err := c.GetPassword(ctx, tid, sid, 2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("destroyed version: %v", err)
	}
	// Versions of a missing path is not found (404 through the response error).
	if _, err := c.Versions(ctx, tid, "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing versions: %v", err)
	}
	if _, err := c.Versions(ctx, "bad", sid); !errors.Is(err, ErrBadPath) {
		t.Fatal("versions path")
	}
	// Answers without data / without metadata fail closed.
	if err := c.PutTOTP(ctx, tid, sid, "seed"); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.nilData = true
	s.mu.Unlock()
	if _, err := c.GetPassword(ctx, tid, sid, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nil data: %v", err)
	}
	if _, err := c.GetTOTP(ctx, tid, sid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nil totp data: %v", err)
	}
	s.mu.Lock()
	s.nilData, s.noMeta = false, true
	s.mu.Unlock()
	if _, err := c.PutPassword(ctx, tid, sid, "four"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no metadata: %v", err)
	}
	s.mu.Lock()
	s.noMeta = false
	s.mu.Unlock()
	// An empty seed is not found; a missing seed path deletes without error.
	if err := c.PutTOTP(ctx, tid, sid, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetTOTP(ctx, tid, sid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty seed: %v", err)
	}
	if err := c.DeleteTOTP(ctx, tid, sid); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteTOTP(ctx, tid, sid); err != nil {
		t.Fatalf("delete missing seed: %v", err)
	}
	if err := c.DeleteSecret(ctx, tid, "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99"); err != nil {
		t.Fatalf("delete missing secret: %v", err)
	}
	// Permission denied on every write path.
	s.mu.Lock()
	s.deny = true
	s.mu.Unlock()
	if err := c.PutTOTP(ctx, tid, sid, "x"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("put totp denied")
	}
	if err := c.DeleteTOTP(ctx, tid, sid); !errors.Is(err, ErrUnavailable) {
		t.Fatal("delete totp denied")
	}
	if err := c.DeleteSecret(ctx, tid, sid); !errors.Is(err, ErrUnavailable) {
		t.Fatal("delete secret denied")
	}
	if _, err := c.GetTOTP(ctx, tid, sid); !errors.Is(err, ErrUnavailable) {
		t.Fatal("get totp denied")
	}
	// Only the seed path failing: the password metadata goes, the seed error surfaces.
	s.mu.Lock()
	s.deny, s.denyTOTP = false, true
	s.mu.Unlock()
	if err := c.DeleteSecret(ctx, tid, sid); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("seed path denied: %v", err)
	}
	// Token problems make the health unauthenticated.
	s.mu.Lock()
	s.denyTOTP, s.badToken = false, true
	s.mu.Unlock()
	if c.Health(ctx) != HealthUnauthenticated {
		t.Fatal("unauthenticated")
	}
	// Bad path grammar on the remaining calls.
	for _, op := range []func() error{
		func() error { return c.DeleteSecret(ctx, "bad", sid) },
		func() error { return c.PutTOTP(ctx, "bad", sid, "s") },
		func() error { _, err := c.GetTOTP(ctx, "bad", sid); return err },
		func() error { return c.DeleteTOTP(ctx, "bad", sid) },
		func() error { _, err := c.PutPassword(ctx, "bad", sid, "s"); return err },
	} {
		if err := op(); !errors.Is(err, ErrBadPath) {
			t.Fatalf("path: %v", err)
		}
	}
	// Close on a bare client is a no-op.
	(&Client{}).Close()
}

func TestClientConstruction(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(ca, []byte("not a certificate"), 0o600)
	if _, err := New(context.Background(), Options{Address: "https://127.0.0.1:1", Mount: "warden", RoleID: "r", SecretID: "s", CAFile: ca}); err == nil || !strings.Contains(err.Error(), "tls") {
		t.Fatalf("bad ca: %v", err)
	}
	if _, err := New(context.Background(), Options{Address: "https://[::1", Mount: "warden", RoleID: "r", SecretID: "s"}); err == nil || !strings.Contains(err.Error(), "client") {
		t.Fatalf("bad address: %v", err)
	}
	// Constructor seams: the auth method and the watcher failing.
	s := newStub()
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	origAuth, origWatcher := newAuth, newWatcher
	defer func() { newAuth, newWatcher = origAuth, origWatcher }()
	newAuth = func(string, *approle.SecretID) (api.AuthMethod, error) { return nil, errors.New("boom") }
	if _, err := New(context.Background(), Options{Address: srv.URL, Mount: "warden", RoleID: "role", SecretID: "secret", AllowPlaintext: true}); err == nil || !strings.Contains(err.Error(), "approle") {
		t.Fatalf("auth seam: %v", err)
	}
	newAuth = origAuth
	newWatcher = func(*api.Client, *api.LifetimeWatcherInput) (*api.LifetimeWatcher, error) {
		return nil, errors.New("boom")
	}
	if _, err := New(context.Background(), Options{Address: srv.URL, Mount: "warden", RoleID: "role", SecretID: "secret", AllowPlaintext: true}); err == nil || !strings.Contains(err.Error(), "watcher") {
		t.Fatalf("watcher seam: %v", err)
	}
}

func TestTokenRenewalAndRelogin(t *testing.T) {
	s := newStub()
	s.lease = 3
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	c, err := New(context.Background(), Options{Address: srv.URL, Mount: "warden", RoleID: "role", SecretID: "secret", AllowPlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Renewal is refused: the watcher ends and the client logs in again.
	s.mu.Lock()
	s.renewFail = true
	s.mu.Unlock()
	deadline := time.Now().Add(15 * time.Second)
	relogged := false
	for time.Now().Before(deadline) {
		s.mu.Lock()
		n := s.logins
		s.mu.Unlock()
		if n >= 2 {
			relogged = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !relogged {
		t.Fatal("no re-login after renewal failure")
	}
	// A failing re-login is logged (and the next watcher never starts).
	var buf syncBuf
	c2, err := New(context.Background(), Options{Address: srv.URL, Mount: "warden", RoleID: "role", SecretID: "secret", AllowPlaintext: true, Logger: slog.New(slog.NewTextHandler(&buf, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	s.mu.Lock()
	s.loginFail = true
	s.mu.Unlock()
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "re-login failed") {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("re-login failure not logged")
}

type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestFakeExtras(t *testing.T) {
	f := NewFake()
	ctx := context.Background()
	f.Down = true
	if _, err := f.PutPassword(ctx, tid, sid, "x"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("down put")
	}
	f.Down = false
	if _, err := f.GetPassword(ctx, tid, sid, 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("empty get")
	}
	_, _ = f.PutPassword(ctx, tid, sid, "x")
	_ = f.PutTOTP(ctx, tid, sid, "s")
	if len(f.Dump()) != 2 || f.Writes() != 2 {
		t.Fatalf("%v %d", f.Dump(), f.Writes())
	}
	f.FailAfter = 3
	if err := f.PutTOTP(ctx, tid, sid, "s2"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("totp fail-after")
	}
	f.HealthState = HealthSealed
	if f.Health(ctx) != HealthSealed {
		t.Fatal("health state")
	}
}

func TestSkipVersion(t *testing.T) {
	ctx := context.Background()
	st := newStub()
	c, _ := newClient(t, st)
	if n, err := c.SkipVersion(ctx, tid, sid); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if n, err := c.PutPassword(ctx, tid, sid, "pw"); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	if _, err := c.GetPassword(ctx, tid, sid, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("skipped version readable: %v", err)
	}
	if vs, _ := c.Versions(ctx, tid, sid); len(vs) != 1 || vs[0] != 2 {
		t.Fatal(vs)
	}
	if _, err := c.SkipVersion(ctx, "bad", sid); !errors.Is(err, ErrBadPath) {
		t.Fatal(err)
	}
	st.denyDel = true
	if _, err := c.SkipVersion(ctx, tid, sid); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("delete refused: %v", err)
	}
	st.denyDel, st.noMeta = false, true
	if _, err := c.SkipVersion(ctx, tid, sid); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no metadata: %v", err)
	}
	st.noMeta, st.deny = false, true
	if _, err := c.SkipVersion(ctx, tid, sid); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("put refused: %v", err)
	}

	f := NewFake()
	if n, err := f.SkipVersion(ctx, tid, sid); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if _, err := f.GetPassword(ctx, tid, sid, 1); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.SkipVersion(ctx, "bad", sid); !errors.Is(err, ErrBadPath) {
		t.Fatal(err)
	}
	f.FailAfter = 2
	if _, err := f.SkipVersion(ctx, tid, sid); !errors.Is(err, ErrUnavailable) {
		t.Fatal("fail-after")
	}
	f.Down = true
	if _, err := f.SkipVersion(ctx, tid, sid); !errors.Is(err, ErrUnavailable) {
		t.Fatal("down")
	}
}
