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
	grpcMD "google.golang.org/grpc/metadata"

	sharingpb "buf.build/gen/go/go-tangra/sharing/protocolbuffers/go/sharing/service/v1"
	sharinggrpc "buf.build/gen/go/go-tangra/sharing/grpc/go/sharing/service/v1/servicev1grpc"

	"github.com/go-tangra/go-tangra-common/grpcx"
	"github.com/go-tangra/go-tangra-warden/internal/cert"
)

// SharingClient calls the sharing-service gRPC API for creating share links.
type SharingClient struct {
	log   *log.Helper
	conn  *grpc.ClientConn
	share sharinggrpc.SharingShareServiceClient
}

// NewSharingClient creates a new SharingClient with mTLS when available.
func NewSharingClient(ctx *bootstrap.Context, certManager *cert.CertManager) (*SharingClient, func(), error) {
	l := ctx.NewLoggerHelper("warden/client/sharing")

	endpoint := os.Getenv("SHARING_GRPC_ENDPOINT")
	if endpoint == "" {
		l.Warn("SHARING_GRPC_ENDPOINT not set, falling back to localhost:9600 (dev only)")
		endpoint = "localhost:9600"
	}

	var transportCreds grpc.DialOption
	if certManager != nil && certManager.IsTLSEnabled() {
		tlsCreds, err := loadSharingClientTLS(l)
		if err != nil {
			l.Warnf("Failed to load mTLS credentials for sharing client: %v, falling back to insecure", err)
			transportCreds = grpc.WithTransportCredentials(insecure.NewCredentials())
		} else {
			transportCreds = grpc.WithTransportCredentials(tlsCreds)
			l.Info("Sharing gRPC client configured with mTLS")
		}
	} else {
		transportCreds = grpc.WithTransportCredentials(insecure.NewCredentials())
		l.Info("Sharing gRPC client configured (plaintext to sharing-service)")
	}

	conn, err := grpc.NewClient(endpoint, transportCreds)
	if err != nil {
		return nil, nil, fmt.Errorf("create sharing gRPC client: %w", err)
	}

	cleanup := func() {
		if conn != nil {
			conn.Close()
		}
	}

	l.Infof("Sharing gRPC client configured for endpoint: %s", endpoint)

	return &SharingClient{
		log:   l,
		conn:  conn,
		share: sharinggrpc.NewSharingShareServiceClient(conn),
	}, cleanup, nil
}

// loadSharingClientTLS loads mTLS credentials for calling sharing-service.
func loadSharingClientTLS(l *log.Helper) (credentials.TransportCredentials, error) {
	certsDir := os.Getenv("CERTS_DIR")
	if certsDir == "" {
		certsDir = "/app/certs"
	}

	caCertPath := filepath.Join(certsDir, "ca", "ca.crt")

	// cert.Ensure() writes the client-auth cert used for dialing peers to
	// {CERTS_DIR}/client/client.{crt,key}. Prefer that; fall back to the
	// legacy convention paths for older cert layouts.
	clientCertPath := filepath.Join(certsDir, "client", "client.crt")
	clientKeyPath := filepath.Join(certsDir, "client", "client.key")

	if _, err := os.Stat(clientCertPath); os.IsNotExist(err) {
		clientCertPath = filepath.Join(certsDir, "warden", "warden.crt")
		clientKeyPath = filepath.Join(certsDir, "warden", "warden.key")
	}
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
		ServerName:   "sharing-service",
		MinVersion:   tls.VersionTLS12,
	}

	l.Infof("Loaded mTLS credentials for sharing-service: CA=%s, Cert=%s", caCertPath, clientCertPath)
	return credentials.NewTLS(tlsConfig), nil
}

// CreateShare creates a share link for a secret via the sharing service.
func (c *SharingClient) CreateShare(ctx context.Context, req *sharingpb.CreateShareRequest) (*sharingpb.CreateShareResponse, error) {
	// Forward the caller's auth identity so sharing-service can, in turn,
	// call back into warden's GetSecret/GetSecretPassword with the original
	// user's permissions. Without this the callback runs with no user_id and
	// warden rejects it with PermissionDenied.
	resp, err := c.share.CreateShare(forwardAuthMetadata(ctx), req)
	if err != nil {
		c.log.Errorf("Failed to create share: %v", err)
		return nil, fmt.Errorf("create share: %w", err)
	}
	return resp, nil
}

// forwardAuthMetadata copies the x-md-global-* auth headers from the incoming
// gRPC context into the outgoing context. warden's SharingClient uses a raw
// gRPC connection (no Kratos client middleware), so incoming metadata is not
// propagated automatically and must be forwarded explicitly.
func forwardAuthMetadata(ctx context.Context) context.Context {
	in, ok := grpcMD.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	out := grpcMD.MD{}
	for _, key := range []string{
		grpcx.MDTenantID,
		grpcx.MDUserID,
		grpcx.MDUsername,
		grpcx.MDRoles,
		grpcx.MDClientIP,
	} {
		if vals := in.Get(key); len(vals) > 0 {
			out.Set(key, vals...)
		}
	}
	return grpcMD.NewOutgoingContext(ctx, out)
}
