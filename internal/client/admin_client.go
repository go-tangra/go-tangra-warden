package client

import (
	"context"
	"os"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	adminstubpb "github.com/go-tangra/go-tangra-warden/gen/go/warden_admin_stub/v1"
	paginationV1 "github.com/tx7do/go-crud/api/gen/go/pagination/v1"
)

// AdminClient calls the admin-service gRPC API for user listing
type AdminClient struct {
	log  *log.Helper
	conn *grpc.ClientConn
}

// NewAdminClient creates a new AdminClient
func NewAdminClient(ctx *bootstrap.Context) (*AdminClient, func(), error) {
	l := ctx.NewLoggerHelper("warden/client/admin")

	endpoint := os.Getenv("ADMIN_GRPC_ENDPOINT")
	if endpoint == "" {
		endpoint = "localhost:7787"
	}

	conn, err := grpc.NewClient(
		endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
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
