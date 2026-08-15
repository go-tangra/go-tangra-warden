package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	adminstubpb "github.com/go-tangra/go-tangra-common/gen/go/common/admin_stub/v1"
	"github.com/go-tangra/go-tangra-common/grpcx"
	"github.com/go-tangra/go-tangra-warden/internal/cert"
	paginationV1 "github.com/tx7do/go-crud/api/gen/go/pagination/v1"
)

// AdminClient calls the admin-service gRPC API for user and role listing
type AdminClient struct {
	log  *log.Helper
	conn *grpc.ClientConn
}

// NewAdminClient creates a new AdminClient with mTLS when available.
func NewAdminClient(ctx *bootstrap.Context, certManager *cert.CertManager) (*AdminClient, func(), error) {
	l := ctx.NewLoggerHelper("warden/client/admin")

	endpoint := os.Getenv("ADMIN_GRPC_ENDPOINT")
	if endpoint == "" {
		l.Warn("ADMIN_GRPC_ENDPOINT not set, falling back to localhost:7787 (dev only)")
		endpoint = "localhost:7787"
	}

	var transportCreds grpc.DialOption
	switch {
	// REGISTRATION_INSECURE=1 means admin-service exposes its control plane on a
	// plain-gRPC port, which is the deployed default. The module still holds a
	// real client cert, so without this check the branch below picks mTLS up and
	// every call dies with "first record does not look like a TLS handshake" —
	// the module is registered (the registration client honours this same flag)
	// while its admin API calls all fail. Same contract as the registration
	// client in go-tangra-common; this client must not re-derive it differently.
	case os.Getenv("REGISTRATION_INSECURE") == "1":
		transportCreds = grpc.WithTransportCredentials(insecure.NewCredentials())
		l.Info("Admin gRPC client configured (plaintext: REGISTRATION_INSECURE=1)")

	case certManager != nil && certManager.IsTLSEnabled():
		tlsCreds, err := loadAdminClientTLS(certManager, l)
		if err != nil {
			l.Warnf("Failed to load mTLS credentials for admin client: %v, falling back to insecure", err)
			transportCreds = grpc.WithTransportCredentials(insecure.NewCredentials())
		} else {
			transportCreds = grpc.WithTransportCredentials(tlsCreds)
			l.Info("Admin gRPC client configured with mTLS")
		}

	default:
		transportCreds = grpc.WithTransportCredentials(insecure.NewCredentials())
		l.Info("Admin gRPC client configured (plaintext to admin-service)")
	}

	conn, err := grpc.NewClient(
		endpoint,
		transportCreds,
		// Present the shared module secret so the admin :7787 control plane
		// authenticates these UserService/RoleService calls.
		grpc.WithChainUnaryInterceptor(grpcx.ModuleSecretUnaryClientInterceptor()),
	)
	if err != nil {
		return nil, nil, err
	}

	cleanup := func() {
		if conn != nil {
			conn.Close()
		}
	}

	l.Infof("Admin gRPC client configured for endpoint: %s", endpoint)

	return &AdminClient{
		log:  l,
		conn: conn,
	}, cleanup, nil
}

// loadAdminClientTLS loads mTLS credentials for calling admin-service.
// Uses the module's server cert (which contains the same CA-signed identity)
// to authenticate with admin-service.
func loadAdminClientTLS(certManager *cert.CertManager, l *log.Helper) (credentials.TransportCredentials, error) {
	certsDir := os.Getenv("CERTS_DIR")
	if certsDir == "" {
		certsDir = "/app/certs"
	}

	caCertPath := filepath.Join(certsDir, "ca", "ca.crt")

	// Use the warden client cert if available, otherwise use server cert
	clientCertPath := filepath.Join(certsDir, "warden", "warden.crt")
	clientKeyPath := filepath.Join(certsDir, "warden", "warden.key")

	// Fall back to server cert if client cert not available
	if _, err := os.Stat(clientCertPath); os.IsNotExist(err) {
		clientCertPath = filepath.Join(certsDir, "warden-server", "server.crt")
		clientKeyPath = filepath.Join(certsDir, "warden-server", "server.key")
	}

	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client cert: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   "admin-service",
		MinVersion:   tls.VersionTLS12,
	}

	l.Infof("Loaded mTLS credentials for admin-service: CA=%s, Cert=%s", caCertPath, clientCertPath)
	return credentials.NewTLS(tlsConfig), nil
}

// ListUsers calls admin.service.v1.UserService/List via gRPC
func (c *AdminClient) ListUsers(ctx context.Context) (*adminstubpb.ListAdminUsersResponse, error) {
	noPaging := true
	req := &paginationV1.PagingRequest{NoPaging: &noPaging}

	resp := &adminstubpb.ListAdminUsersResponse{}
	err := c.conn.Invoke(ctx, "/admin.service.v1.UserService/List", req, resp)
	if err != nil {
		c.log.Errorf("Failed to list users from admin-service: %v", err)
		return nil, err
	}

	return resp, nil
}

// ListRoles calls admin.service.v1.RoleService/List via gRPC
func (c *AdminClient) ListRoles(ctx context.Context) (*adminstubpb.ListAdminRolesResponse, error) {
	noPaging := true
	req := &paginationV1.PagingRequest{NoPaging: &noPaging}

	resp := &adminstubpb.ListAdminRolesResponse{}
	err := c.conn.Invoke(ctx, "/admin.service.v1.RoleService/List", req, resp)
	if err != nil {
		c.log.Errorf("Failed to list roles from admin-service: %v", err)
		return nil, err
	}

	return resp, nil
}
