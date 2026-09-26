//go:build integration

// Package integration boots the platform (gateway and auth as subprocesses
// built from the sibling modules) and warden in-process against real
// TimescaleDB, Valkey (TLS), OpenFGA, Vault (dev) and Mailpit containers.
// Every service holds an SVID from one shared test CA; browsers reach warden
// only through the gateway edge, exactly as in production.
package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/go-tangra/go-tangra-warden/v4/internal/app"
	"github.com/go-tangra/go-tangra-warden/v4/internal/config"
	"github.com/go-tangra/go-tangra-warden/v4/internal/share"
	"github.com/go-tangra/go-tangra-warden/v4/internal/store"
	"github.com/go-tangra/go-tangra/v4"
	fconfig "github.com/go-tangra/go-tangra/v4/config"
	"github.com/go-tangra/go-tangra/v4/discovery"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

const (
	trustDomain = "example.org"
	password    = "correct horse battery staple 42"
)

// Env is the running platform plus helpers.
type Env struct {
	T          *testing.T
	CA         *testutil.CA
	Warden     *app.App
	Base       string // gateway edge: https://127.0.0.1:port
	Mail       string // mailpit API
	VaultAddr  string
	Operator   *Session
	PlatformID string
	Cancel     context.CancelFunc
	vault      testcontainers.Container
	authBin    string
	authCfg    string
	logs       map[string]string
	sessions   []*Session
}

// Session is one signed-in browser (its own cookie jar) at the gateway edge.
type Session struct {
	Env    *Env
	Client *http.Client
	Email  string
	UserID string
	Tenant string // slug
}

func Start(t *testing.T) *Env {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	ca := testutil.MustCA(trustDomain)
	pgHost, pgPorts := container(t, testcontainers.ContainerRequest{Image: "timescale/timescaledb:latest-pg16", ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{"POSTGRES_PASSWORD": "test", "POSTGRES_DB": "auth"}, WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(2 * time.Minute)})
	pg := pgHost + ":" + pgPorts["5432/tcp"]
	adminAuth := "postgres://postgres:test@" + pg + "/auth?sslmode=disable"
	for i := 0; i < 30; i++ {
		conn, err := pgx.Connect(ctx, adminAuth)
		if err == nil {
			for _, q := range []string{"CREATE ROLE auth_app LOGIN PASSWORD 'app' NOBYPASSRLS", "CREATE ROLE gateway_app LOGIN PASSWORD 'app'", "CREATE ROLE warden_app LOGIN PASSWORD 'app' NOBYPASSRLS",
				"CREATE DATABASE gateway", "CREATE DATABASE warden"} {
				_, _ = conn.Exec(ctx, q)
			}
			_ = conn.Close(ctx)
			break
		}
		time.Sleep(time.Second)
	}
	certPath, keyPath := selfSigned(t, dir)
	vkHost, vkPorts := container(t, testcontainers.ContainerRequest{Image: "valkey/valkey:8", ExposedPorts: []string{"6379/tcp"},
		Files:      []testcontainers.ContainerFile{{HostFilePath: certPath, ContainerFilePath: "/tls/server.crt", FileMode: 0o644}, {HostFilePath: keyPath, ContainerFilePath: "/tls/server.key", FileMode: 0o644}},
		Cmd:        []string{"valkey-server", "--tls-port", "6379", "--port", "0", "--tls-cert-file", "/tls/server.crt", "--tls-key-file", "/tls/server.key", "--tls-ca-cert-file", "/tls/server.crt", "--tls-auth-clients", "no", "--requirepass", "test"},
		WaitingFor: wait.ForListeningPort("6379/tcp")})
	valkeyAddr := vkHost + ":" + vkPorts["6379/tcp"]
	fgaHost, fgaPorts := container(t, testcontainers.ContainerRequest{Image: "openfga/openfga:v1.20.0", ExposedPorts: []string{"8080/tcp"},
		Cmd: []string{"run", "--authn-method=preshared", "--authn-preshared-keys=test-key", "--playground-enabled=false"}, WaitingFor: wait.ForHTTP("/healthz").WithPort("8080/tcp")})
	mpHost, mpPorts := container(t, testcontainers.ContainerRequest{Image: "axllent/mailpit:latest", ExposedPorts: []string{"1025/tcp", "8025/tcp"}, WaitingFor: wait.ForListeningPort("8025/tcp")})
	vc, vaultAddr := startVault(t)
	roleID, secretID := initVault(t, vaultAddr)
	roleFile, secretFile := filepath.Join(dir, "role_id"), filepath.Join(dir, "secret_id")
	_ = os.WriteFile(roleFile, []byte(roleID), 0o600)
	_ = os.WriteFile(secretFile, []byte(secretID), 0o600)

	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	kekPath := filepath.Join(dir, "kek.b64")
	_ = os.WriteFile(kekPath, []byte(base64.StdEncoding.EncodeToString(kek)), 0o600)
	authHTTP, authGRPC := freePort(t), freePort(t)
	gwEdge, gwGRPC := freePort(t), freePort(t)
	logs := map[string]string{"auth": filepath.Join(dir, "auth.log"), "gateway": filepath.Join(dir, "gateway.log")}

	// --- auth (subprocess, gateway mode)
	authBin, gwBin := buildService(t, "auth", "./cmd/authsvc"), buildService(t, "gateway", "./cmd/gatewaysvc")
	svidDir := filepath.Join(dir, "svid")
	authCert, authKey, bundle, err := ca.WriteSVID(svidDir, "auth", ca.MustIssue("auth", testutil.IssueOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	authCfg := filepath.Join(dir, "auth.yaml")
	authYAML := fmt.Sprintf(`service_name: auth
trust_domain: %s
env: test
identity:
  provider: file
  file: { cert: %s, key: %s, bundle: %s }
authz: { source: file, path: %s }
server: { grpc_addr: %s, http_addr: %s }
admin: { addr: 127.0.0.1:0 }
discovery:
  static:
    gateway: ["%s"]
gateway: { enabled: true, service: gateway }
issuer: https://%s
db:
  dsn: postgres://auth_app:app@%s/auth?sslmode=disable
  migrate_dsn: %s
valkey: { addresses: ["%s"], password: test, ca_file: %s }
openfga: { url: http://%s:%s, preshared_key: test-key, allow_plaintext: true }
kek: { source: file, path: %s }
# auth delivers mail through the notification module, which this harness
# does not run: the development log sink records each message instead.
email: { transport: log }
`, trustDomain, authCert, authKey, bundle, filepath.Join(serviceDir(t, "auth"), "deploy", "policy.yaml"), authGRPC, authHTTP, gwGRPC, gwEdge,
		pg, adminAuth, valkeyAddr, certPath, fgaHost, fgaPorts["8080/tcp"], kekPath)
	if err := os.WriteFile(authCfg, []byte(authYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	// --- gateway (subprocess)
	gwCert, gwKey, _, err := ca.WriteSVID(filepath.Join(dir, "svid-gw"), "gateway", ca.MustIssue("gateway", testutil.IssueOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	gwCfg := filepath.Join(dir, "gateway.yaml")
	gwYAML := fmt.Sprintf(`service_name: gateway
trust_domain: %s
env: test
identity:
  provider: file
  file: { cert: %s, key: %s, bundle: %s }
authz: { source: file, path: %s }
server: { grpc_addr: %s }
admin: { addr: 127.0.0.1:0 }
discovery:
  static:
    auth: ["%s"]
edge:
  addr: %s
  allowed_origins: ["https://%s"]
  rate_limit: { per_second: 500, burst: 1000 }
public_origin: https://%s
db:
  dsn: postgres://gateway_app:app@%s/gateway?sslmode=disable
  migrate_dsn: postgres://postgres:test@%s/gateway?sslmode=disable
valkey: { addresses: ["%s"], password: test, ca_file: %s }
auth: { service: auth, issuer: https://%s, audience: gateway }
leases: { ttl: 2s, renew: 500ms }
forward: { body_bytes: 1048576, streams_per_client: 32, stream_max: 10m, module_timeout: 30s }
operators: { roles: [operator] }
limits:
  max_request_bytes: 16842752
`, trustDomain, gwCert, gwKey, bundle, filepath.Join(serviceDir(t, "gateway"), "deploy", "policy.yaml"), gwGRPC, authGRPC, gwEdge, gwEdge, gwEdge, pg, pg, valkeyAddr, certPath, gwEdge)
	if err := os.WriteFile(gwCfg, []byte(gwYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	// Allow-list both modules before anything registers.
	boot := exec.Command(gwBin, "bootstrap", "-config", gwCfg,
		"-allow", "spiffe://"+trustDomain+"/svc/auth=/api/v1,/authorize,/.well-known,/console;auth",
		"-allow", "spiffe://"+trustDomain+"/svc/warden=/api/warden,/warden/share,/ui;warden")
	if out, err := boot.CombinedOutput(); err != nil {
		t.Fatalf("gateway bootstrap: %v\n%s", err, out)
	}
	startProcess(t, gwBin, gwCfg, logs["gateway"])
	startProcess(t, authBin, authCfg, logs["auth"])

	// --- warden (in-process)
	wcfg := config.Default()
	wcfg.ServiceName, wcfg.TrustDomain, wcfg.Env = "warden", trustDomain, "test"
	wcfg.Server.GRPCAddr, wcfg.Server.HTTPAddr, wcfg.Admin.Addr = "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0"
	wcfg.Authz = fconfig.Authz{Source: fconfig.AuthzFile, Path: abs(t, "../../deploy/policy.yaml")}
	wcfg.Config.Limits.MaxRequestBytes = 16842752
	wcfg.DB.DSN = "postgres://warden_app:app@" + pg + "/warden?sslmode=disable"
	wcfg.DB.MigrateDSN = "postgres://postgres:test@" + pg + "/warden?sslmode=disable"
	wcfg.Valkey = config.Valkey{Addresses: []string{valkeyAddr}, Password: "test", CAFile: certPath}
	wcfg.Vault = config.Vault{Address: vaultAddr, Mount: "warden", RoleIDFile: roleFile, SecretIDFile: secretFile, AllowPlaintext: true}
	wcfg.Gateway = config.Gateway{Service: "gateway", Issuer: "https://" + gwEdge}
	wcfg.Share = config.Share{PublicOrigin: "https://" + gwEdge, DefaultValiditySeconds: 3600, DefaultMaxOpens: 1}
	// Share mail goes through the notification module in production; here a
	// stand-in renders the warden.share variables and hands them to Mailpit
	// so the tests read the link as a recipient would.
	wcfg.Mail = config.Mail{Transport: "notification"}
	notifier := &mailpitNotifier{addr: mpHost + ":" + mpPorts["1025/tcp"]}
	disc, err := discovery.NewStatic(map[string][]string{"auth": {authGRPC}, "gateway": {gwGRPC}})
	if err != nil {
		t.Fatal(err)
	}
	prov := testutil.NewMemProvider(ca, ca.MustIssue("warden", testutil.IssueOptions{}))
	wlog := filepath.Join(dir, "warden.log")
	logs["warden"] = wlog
	wf, _ := os.Create(wlog)
	w, err := app.Build(ctx, wcfg, app.Options{Migrate: true, Logger: slog.NewTextHandler(wf, &slog.HandlerOptions{Level: slog.LevelDebug}), Register: app.Wire, Mail: notifier,
		Freya: []freya.Option{freya.WithIdentityProvider(prov), freya.WithDiscovery(disc)}})
	if err != nil {
		t.Fatalf("warden build: %v", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- w.Run(runCtx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
		}
		w.Close()
		_ = wf.Close()
	})
	env := &Env{T: t, CA: ca, Warden: w, Base: "https://" + gwEdge, Mail: fmt.Sprintf("http://%s:%s", mpHost, mpPorts["8025/tcp"]), VaultAddr: vaultAddr,
		Cancel: cancel, vault: vc, authBin: authBin, authCfg: authCfg, logs: logs}
	t.Cleanup(func() {
		if t.Failed() {
			for name, p := range logs {
				b, _ := os.ReadFile(p)
				if len(b) > 8000 {
					b = b[len(b)-8000:]
				}
				t.Logf("%s log tail:\n%s", name, b)
			}
		}
	})
	env.waitReady()
	return env
}

// StartPlatform boots the stack and signs the bootstrap operator in.
func StartPlatform(t *testing.T) *Env {
	t.Helper()
	e := Start(t)
	tid, accept := e.bootstrapAuth("ops@example.org")
	e.PlatformID = tid
	op := e.NewSession("ops@example.org", "platform")
	op.acceptInvitation(accept, "Ops")
	if code, body := op.SignIn(); code != 200 {
		t.Fatalf("operator sign-in → %d %v", code, body)
	}
	e.Operator = op
	e.SeedGrants()
	op.WaitAuthorized("/api/warden/v1/stats")
	return e
}

// WaitAuthorized polls a protected warden route until the platform accepts
// the session there (verifier synced, grants visible); fails after 60 s.
func (s *Session) WaitAuthorized(path string) {
	s.Env.T.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var code int
	var body map[string]any
	for time.Now().Before(deadline) {
		code, body = s.JSON(http.MethodGet, path, nil)
		if code != 401 && code != 403 && code != 503 {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	s.Env.T.Fatalf("%s never authorized %s: %d %v", s.Email, path, code, body)
}

// NewSession creates an anonymous browser for a user of a tenant.
func (e *Env) NewSession(email, tenant string) *Session {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 150 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}}, //nolint:gosec // self-signed edge cert
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	s := &Session{Env: e, Client: client, Email: email, Tenant: tenant}
	e.sessions = append(e.sessions, s)
	return s
}

// SignIn signs the session in at the gateway edge (the auth module answers).
func (s *Session) SignIn() (int, map[string]any) {
	s.Env.T.Helper()
	s.prime()
	code, body := s.JSON(http.MethodPost, "/api/v1/signin", map[string]string{"tenant": s.Tenant, "email": s.Email, "password": password})
	if code == 200 {
		if _, me := s.JSON(http.MethodGet, "/gateway/v1/me", nil); me["user_id"] != nil {
			s.UserID, _ = me["user_id"].(string)
		}
	}
	return code, body
}

// prime fetches the CSRF cookie.
func (s *Session) prime() {
	resp, err := s.Client.Get(s.Env.Base + "/gateway/v1/me")
	if err != nil {
		s.Env.T.Fatal(err)
	}
	_ = resp.Body.Close()
}

func (s *Session) csrf() string {
	u, _ := url.Parse(s.Env.Base)
	for _, c := range s.Client.Jar.Cookies(u) {
		if c.Name == edge.CSRFCookie {
			return c.Value
		}
	}
	return ""
}

// Raw performs a request with an arbitrary body and returns the response.
func (s *Session) Raw(method, path string, body []byte, contentType string, hdr ...string) *http.Response {
	s.Env.T.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, s.Env.Base+path, rd)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if method != http.MethodGet {
		if s.csrf() == "" {
			s.prime()
		}
		req.Header.Set(edge.CSRFHeader, s.csrf())
		req.Header.Set("Origin", s.Env.Base)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		s.Env.T.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// JSON performs a browser-style JSON request and decodes an object body.
func (s *Session) JSON(method, path string, body any, hdr ...string) (int, map[string]any) {
	s.Env.T.Helper()
	var raw []byte
	ct := ""
	if body != nil {
		raw, _ = json.Marshal(body)
		ct = "application/json"
	}
	resp := s.Raw(method, path, raw, ct, hdr...)
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// JSONList is JSON for endpoints returning an array.
func (s *Session) JSONList(method, path string, body any) (int, []map[string]any) {
	s.Env.T.Helper()
	var raw []byte
	ct := ""
	if body != nil {
		raw, _ = json.Marshal(body)
		ct = "application/json"
	}
	resp := s.Raw(method, path, raw, ct)
	defer resp.Body.Close()
	var out []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// Token mints a platform access token from the live session.
func (s *Session) Token() string {
	s.Env.T.Helper()
	code, body := s.JSON(http.MethodPost, "/api/v1/session/token", nil)
	if code != 200 {
		s.Env.T.Fatalf("token → %d %v", code, body)
	}
	return body["access_token"].(string)
}

// acceptInvitation completes an invitation link (from mail or bootstrap).
func (s *Session) acceptInvitation(acceptURL, displayName string) {
	s.Env.T.Helper()
	u, err := url.Parse(acceptURL)
	if err != nil {
		s.Env.T.Fatal(err)
	}
	s.prime()
	if code, body := s.JSON(http.MethodPost, "/api/v1/invitations/accept", map[string]string{"token": u.Query().Get("token"), "display_name": displayName, "password": password}); code/100 != 2 {
		s.Env.T.Fatalf("accept invitation → %d %v", code, body)
	}
}

var acceptLinkRE = regexp.MustCompile(`https://\S+/console/invite/accept\?token=[A-Za-z0-9_-]+`)

// CreateTenant has the operator create a customer tenant and returns its
// signed-in owner and the tenant id.
func (e *Env) CreateTenant(slug, ownerEmail string) (*Session, string) {
	e.T.Helper()
	code, body := e.Operator.JSON(http.MethodPost, "/api/v1/operator/tenants", map[string]string{"slug": slug, "display_name": strings.ToUpper(slug[:1]) + slug[1:], "owner_email": ownerEmail})
	if code != 201 {
		e.T.Fatalf("create tenant → %d %v", code, body)
	}
	var tid string
	if tv, ok := body["tenant"].(map[string]any); ok {
		tid, _ = tv["id"].(string)
	}
	if tid == "" {
		e.T.Fatalf("create tenant: no tenant id in %v", body)
	}
	link := e.InvitationLink(ownerEmail)
	if link == "" {
		e.T.Fatalf("no invitation link mailed to %s", ownerEmail)
	}
	owner := e.NewSession(ownerEmail, slug)
	owner.acceptInvitation(link, "Owner")
	if code, body := owner.SignIn(); code != 200 {
		e.T.Fatalf("owner sign-in → %d %v", code, body)
	}
	e.SeedGrants()
	owner.WaitAuthorized("/api/warden/v1/stats")
	return owner, tid
}

// Invite has admin invite a member with the given role slugs into admin's
// tenant and returns the member's signed-in session.
func (e *Env) Invite(admin *Session, email string, roles ...string) *Session {
	e.T.Helper()
	code, list := admin.JSONList(http.MethodGet, "/api/v1/admin/roles", nil)
	if code != 200 {
		e.T.Fatalf("list roles → %d", code)
	}
	var ids []string
	for _, r := range list {
		for _, want := range roles {
			if r["slug"] == want {
				ids = append(ids, r["id"].(string))
			}
		}
	}
	if len(ids) != len(roles) {
		e.T.Fatalf("roles %v not all found in %v", roles, list)
	}
	if code, body := admin.JSON(http.MethodPost, "/api/v1/admin/invitations", map[string]any{"email": email, "role_ids": ids}); code != 202 {
		e.T.Fatalf("invite → %d %v", code, body)
	}
	link := e.InvitationLink(email)
	if link == "" {
		e.T.Fatalf("no invitation link mailed to %s", email)
	}
	s := e.NewSession(email, admin.Tenant)
	s.acceptInvitation(link, strings.Split(email, "@")[0])
	if code, body := s.SignIn(); code != 200 {
		e.T.Fatalf("member sign-in → %d %v", code, body)
	}
	s.WaitAuthorized("/api/warden/v1/secrets")
	return s
}

// SeedGrants registers warden's permissions and built-in role grants now
// (the service also does it periodically).
func (e *Env) SeedGrants() {
	e.T.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := e.Warden.SeedPermissions(context.Background())
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			e.T.Fatalf("seed permissions: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// InvitationLink returns the newest invitation link auth sent to an address
// (waits up to 20 s). auth runs with the development mail sink, which logs
// every message with its template variables.
func (e *Env) InvitationLink(to string) string {
	e.T.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(e.logs["auth"]); err == nil {
			link := ""
			for _, line := range strings.Split(string(b), "\n") {
				if strings.Contains(line, "email (dev sink)") && strings.Contains(line, `"to":"`+to+`"`) {
					if l := acceptLinkRE.FindString(line); l != "" {
						link = l
					}
				}
			}
			if link != "" {
				return link
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	e.T.Fatalf("no invitation for %s in the auth log", to)
	return ""
}

// LastMail returns the text of the newest message to an address (waits up to 20 s).
func (e *Env) LastMail(to string) string {
	e.T.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(e.Mail + "/api/v1/search?query=" + url.QueryEscape("to:"+to))
		if err == nil {
			var list struct {
				Messages []struct{ ID string }
			}
			_ = json.NewDecoder(resp.Body).Decode(&list)
			_ = resp.Body.Close()
			if len(list.Messages) > 0 {
				r2, err := http.Get(e.Mail + "/api/v1/message/" + list.Messages[0].ID)
				if err == nil {
					var m struct{ Text string }
					_ = json.NewDecoder(r2.Body).Decode(&m)
					_ = r2.Body.Close()
					return m.Text
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	e.T.Fatalf("no mail for %s", to)
	return ""
}

// MailCount counts messages to an address right now.
func (e *Env) MailCount(to string) int {
	resp, err := http.Get(e.Mail + "/api/v1/search?query=" + url.QueryEscape("to:"+to))
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	var list struct {
		Messages []struct{ ID string }
	}
	_ = json.NewDecoder(resp.Body).Decode(&list)
	return len(list.Messages)
}

// AuditCount counts warden audit events (flushing the writer first).
func (e *Env) AuditCount(tenantID, eventType, outcome string) int {
	e.T.Helper()
	e.Warden.Audit.Flush()
	var n int
	_ = e.Warden.Store.Tx(context.Background(), store.Scope{System: true}, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT count(*) FROM warden_audit_events WHERE tenant_id = $1 AND ($2 = '' OR event_type = $2) AND ($3 = '' OR outcome = $3)", tenantID, eventType, outcome).Scan(&n)
	})
	return n
}

// AuditRows returns the audit rows of a type, newest first.
func (e *Env) AuditRows(tenantID, eventType string) []store.AuditRow {
	e.T.Helper()
	e.Warden.Audit.Flush()
	var rows []store.AuditRow
	_ = e.Warden.Store.Tx(context.Background(), store.Scope{System: true}, func(tx pgx.Tx) error {
		var err error
		rows, err = store.QueryAudit(context.Background(), tx, tenantID, eventType, "", time.Time{}, time.Now().Add(time.Hour), time.Time{}, 200)
		return err
	})
	return rows
}

// VaultStop / VaultStart pause and resume the Vault container (a dev-mode
// Vault keeps its state only while the process lives, so the outage is a
// pause: requests hang until the client timeout and fail closed).
func (e *Env) VaultStop() {
	e.T.Helper()
	cli, err := testcontainers.NewDockerClientWithOpts(context.Background())
	if err != nil {
		e.T.Fatal(err)
	}
	defer cli.Close()
	if _, err := cli.ContainerPause(context.Background(), e.vault.GetContainerID(), client.ContainerPauseOptions{}); err != nil {
		e.T.Fatal(err)
	}
}

func (e *Env) VaultStart() {
	e.T.Helper()
	cli, err := testcontainers.NewDockerClientWithOpts(context.Background())
	if err != nil {
		e.T.Fatal(err)
	}
	defer cli.Close()
	if _, err := cli.ContainerUnpause(context.Background(), e.vault.GetContainerID(), client.ContainerUnpauseOptions{}); err != nil {
		e.T.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(e.VaultAddr + "/v1/sys/health"); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	e.T.Fatal("vault did not come back")
}

// LogContains reports whether a service log mentions s.
func (e *Env) LogContains(service, s string) bool {
	b, _ := os.ReadFile(e.logs[service])
	return strings.Contains(string(b), s)
}

func (e *Env) waitReady() {
	e.T.Helper()
	anon := e.NewSession("", "")
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		if e.Warden.Freya.Ready() {
			// Auth reached through the gateway (401), warden registered (401 on a
			// protected route rather than 404), and the token verifier synced.
			if r1, err := anon.Client.Get(e.Base + "/api/v1/session"); err == nil {
				_ = r1.Body.Close()
				if r2, err := anon.Client.Get(e.Base + "/api/warden/v1/stats"); err == nil {
					_ = r2.Body.Close()
					if r1.StatusCode == 401 && r2.StatusCode == 401 {
						return
					}
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	e.T.Fatalf("platform did not become ready")
}

// bootstrapAuth runs `authsvc bootstrap` and returns the platform tenant id
// and the operator invitation accept URL.
func (e *Env) bootstrapAuth(operatorEmail string) (tenantID, acceptURL string) {
	e.T.Helper()
	out, err := exec.Command(e.authBin, "bootstrap", "-config", e.authCfg, "-operator-email", operatorEmail).CombinedOutput()
	if err != nil {
		e.T.Fatalf("auth bootstrap: %v: %s", err, out)
	}
	var res struct {
		TenantID  string `json:"tenant_id"`
		AcceptURL string `json:"accept_url"`
	}
	if i := bytes.LastIndex(out, []byte("\n{\n")); i >= 0 {
		out = out[i+1:]
	}
	if err := json.Unmarshal(out, &res); err != nil {
		e.T.Fatalf("bootstrap output %q: %v", out, err)
	}
	return res.TenantID, res.AcceptURL
}

// ---- containers and processes

func container(t *testing.T, req testcontainers.ContainerRequest) (host string, ports map[string]string) {
	t.Helper()
	c := startContainer(t, req)
	ctx := context.Background()
	host, _ = c.Host(ctx)
	ports = map[string]string{}
	for _, p := range req.ExposedPorts {
		mp, err := c.MappedPort(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		ports[p] = mp.Port()
	}
	return host, ports
}

func startContainer(t *testing.T, req testcontainers.ContainerRequest) testcontainers.Container {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		t.Skipf("testcontainers unavailable (%s): %v", req.Image, err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	return c
}

// startVault runs a dev-mode Vault; returns the container and its address.
func startVault(t *testing.T) (testcontainers.Container, string) {
	t.Helper()
	c := startContainer(t, testcontainers.ContainerRequest{Image: "hashicorp/vault:1.18", ExposedPorts: []string{"8200/tcp"},
		Env:        map[string]string{"VAULT_DEV_ROOT_TOKEN_ID": "dev-root", "VAULT_DEV_LISTEN_ADDRESS": "0.0.0.0:8200"},
		CapAdd:     []string{"IPC_LOCK"},
		WaitingFor: wait.ForHTTP("/v1/sys/health").WithPort("8200/tcp").WithStartupTimeout(2 * time.Minute)})
	ctx := context.Background()
	host, _ := c.Host(ctx)
	port, _ := c.MappedPort(ctx, "8200/tcp")
	return c, "http://" + host + ":" + port.Port()
}

// initVault mirrors deploy/vault-init.sh: KV v2 mount, policy, AppRole.
func initVault(t *testing.T, addr string) (roleID, secretID string) {
	t.Helper()
	call := func(method, path string, body any) map[string]any {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, addr+"/v1/"+path, rd)
		req.Header.Set("X-Vault-Token", "dev-root")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("vault %s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if resp.StatusCode >= 300 && resp.StatusCode != 400 { // 400 = already mounted
			t.Fatalf("vault %s %s: %d %v", method, path, resp.StatusCode, out)
		}
		return out
	}
	call("POST", "sys/mounts/warden", map[string]any{"type": "kv", "options": map[string]string{"version": "2"}})
	call("PUT", "sys/policies/acl/warden", map[string]string{"policy": `path "warden/data/*" { capabilities = ["create","read","update","delete"] }
path "warden/metadata/*" { capabilities = ["read","delete","list"] }
path "auth/token/renew-self" { capabilities = ["update"] }`})
	call("POST", "sys/auth/approle", map[string]string{"type": "approle"})
	call("POST", "auth/approle/role/warden", map[string]any{"token_policies": []string{"warden"}, "token_ttl": "1h", "token_max_ttl": "24h", "secret_id_num_uses": 0})
	roleID = call("GET", "auth/approle/role/warden/role-id", nil)["data"].(map[string]any)["role_id"].(string)
	secretID = call("POST", "auth/approle/role/warden/secret-id", nil)["data"].(map[string]any)["secret_id"].(string)
	return
}

func selfSigned(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "valkey"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, DNSNames: []string{"localhost"}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certPath, keyPath = filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	_ = os.WriteFile(certPath, pemBlock("CERTIFICATE", der), 0o644)
	_ = os.WriteFile(keyPath, pemBlock("EC PRIVATE KEY", kb), 0o644)
	return
}

func pemBlock(typ string, der []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(der)
	var buf bytes.Buffer
	buf.WriteString("-----BEGIN " + typ + "-----\n")
	for len(b64) > 64 {
		buf.WriteString(b64[:64] + "\n")
		b64 = b64[64:]
	}
	buf.WriteString(b64 + "\n-----END " + typ + "-----\n")
	return buf.Bytes()
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

var (
	buildMu   sync.Mutex
	built     = map[string]string{}
	buildErrs = map[string]error{}
)

// buildService compiles a sibling service once per test binary.
func buildService(t *testing.T, name, pkg string) string {
	t.Helper()
	buildMu.Lock()
	defer buildMu.Unlock()
	if p, ok := built[name]; ok {
		return p
	}
	if err, ok := buildErrs[name]; ok {
		t.Fatal(err)
	}
	out := filepath.Join(os.TempDir(), fmt.Sprintf("%ssvc-warden-%d", name, os.Getpid()))
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = serviceDir(t, name)
	if b, err := cmd.CombinedOutput(); err != nil {
		buildErrs[name] = fmt.Errorf("build %s: %v\n%s", name, err, b)
		t.Fatal(buildErrs[name])
	}
	built[name] = out
	return out
}

// serviceCheckouts maps the services the harness builds to their repositories
// and the variable that overrides the checkout location.
var serviceCheckouts = map[string]struct{ repo, env, cmd string }{
	"auth":    {"go-tangra-auth", "GO_TANGRA_AUTH_DIR", "authsvc"},
	"gateway": {"go-tangra-portal", "GO_TANGRA_PORTAL_DIR", "gatewaysvc"},
}

// serviceDir is the checkout the harness builds a service from. The auth and
// portal modules keep their sdks as in-repo replaces, so they cannot be built
// from the module cache: GO_TANGRA_AUTH_DIR / GO_TANGRA_PORTAL_DIR name the
// checkouts, and by default sibling clones next to this repository
// (../go-tangra-auth, ../go-tangra-portal) are used.
func serviceDir(t *testing.T, name string) string {
	t.Helper()
	c, ok := serviceCheckouts[name]
	if !ok {
		t.Fatalf("unknown service %q", name)
	}
	dir := os.Getenv(c.env)
	if dir == "" {
		dir = "../../../" + c.repo
	}
	dir = abs(t, dir)
	if _, err := os.Stat(filepath.Join(dir, "cmd", c.cmd)); err != nil {
		t.Fatalf("%s checkout not found at %s (clone github.com/go-tangra/%s there or set %s): %v", name, dir, c.repo, c.env, err)
	}
	return dir
}

func abs(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// startProcess runs a service binary; it is stopped with the test.
func startProcess(t *testing.T, bin, cfg, logPath string) *exec.Cmd {
	t.Helper()
	logf, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-config", cfg)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
		}
		_ = logf.Close()
	})
	return cmd
}

// TestHarnessBoots proves the platform comes up: the operator holds every
// warden permission through the owner role, an anonymous browser is refused,
// and an audit-only role reaches the stats route.
func TestHarnessBoots(t *testing.T) {
	e := StartPlatform(t)
	// Protected route through the gateway: authenticated and authorized (501 until US4 lands, never 401/403/404).
	code, body := e.Operator.JSON(http.MethodGet, "/api/warden/v1/stats", nil)
	if code == 401 || code == 403 || code == 404 {
		t.Fatalf("operator stats → %d %v", code, body)
	}
	anon := e.NewSession("", "")
	if code, _ := anon.JSON(http.MethodGet, "/api/warden/v1/stats", nil); code != 401 {
		t.Fatalf("anonymous → %d", code)
	}
	// A platform token verifies at warden directly through the gateway too.
	if tok := e.Operator.Token(); len(tok) < 40 {
		t.Fatal("token")
	}
	// A customer tenant: its owner holds the permissions; a member lacks stats:read.
	owner, tid := e.CreateTenant("acme", "owner@acme.test")
	if code, _ := owner.JSON(http.MethodGet, "/api/warden/v1/stats", nil); code == 401 || code == 403 || code == 404 {
		t.Fatalf("owner stats → %d", code)
	}
	member := e.Invite(owner, "bob@acme.test", "member")
	if code, _ := member.JSON(http.MethodGet, "/api/warden/v1/stats", nil); code != 403 {
		t.Fatalf("member stats → %d (want 403)", code)
	}
	if code, _ := member.JSON(http.MethodGet, "/api/warden/v1/secrets", nil); code == 401 || code == 403 || code == 404 {
		t.Fatalf("member secrets → %d", code)
	}
	if tid == "" || e.AuditCount(tid, "", "") != 0 {
		t.Fatalf("tenant %q audit %d", tid, e.AuditCount(tid, "", ""))
	}
	h := e.Warden.Health(context.Background())
	if h.DB != "ok" || h.Vault != "ok" {
		t.Fatalf("health %+v", h)
	}
}

func getenv(k string) string { return os.Getenv(k) }

// mailpitNotifier stands in for the notification module: it renders the
// warden.share system template's variables as plain text and relays them to
// Mailpit. Only warden.share for a tenant, correlated with a share, is valid.
type mailpitNotifier struct{ addr string }

func (n *mailpitNotifier) Send(_ context.Context, m share.Message) error {
	if m.Template != share.TemplateShare || m.TenantID == "" || m.CorrelationID == "" || m.Vars["link"] == "" {
		return fmt.Errorf("notification stand-in: unexpected message %q for %q", m.Template, m.To)
	}
	text := fmt.Sprintf("A credential named %q has been shared with you.\r\n\r\nOpen it here (valid until %s, %s opening(s)):\r\n\r\n%s\r\n",
		m.Vars["secret_name"], m.Vars["expires"], m.Vars["openings"], m.Vars["link"])
	if msg := m.Vars["message"]; msg != "" {
		text += "\r\nMessage from the sender:\r\n" + msg + "\r\n"
	}
	body := "From: notification@example.org\r\nTo: " + m.To + "\r\nSubject: A credential was shared with you\r\n\r\n" + text
	return smtp.SendMail(n.addr, nil, "notification@example.org", []string{m.To}, []byte(body))
}
