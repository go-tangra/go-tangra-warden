// Package grpcapi serves warden.v1.Secrets on the Freya channel. The peer is
// an authenticated service (mTLS); the end user comes from the platform token
// forwarded in the authorization metadata, verified by the middleware the
// app installs (authclient.KratosMiddleware). Every call applies the same
// Zanzibar check and audit as the browser API.
package grpcapi

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	wardenv1 "github.com/go-tangra/go-tangra-warden/sdk/v4/api/proto/warden/v1"
	"github.com/go-tangra/go-tangra-warden/v4/internal/authz"
	"github.com/go-tangra/go-tangra-warden/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-warden/v4/internal/vault"
)

// SecretsServer implements warden.v1.Secrets.
type SecretsServer struct {
	wardenv1.UnimplementedSecretsServer
	Secrets *secrets.Service
	Authz   *authz.Authz
}

func subjects(ctx context.Context) (authz.Subjects, error) {
	id, ok := authclient.FromContext(ctx)
	if !ok || id.UserID == "" || id.TenantID == "" {
		return authz.Subjects{}, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	return authz.SubjectsOf(id), nil
}

func grpcError(err error) error {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		return status.Error(codes.PermissionDenied, "forbidden")
	case errors.Is(err, authz.ErrNotFound):
		return status.Error(codes.NotFound, "not_found")
	case errors.Is(err, authz.ErrInput), errors.Is(err, secrets.ErrInvalid):
		return status.Error(codes.InvalidArgument, "validation_failed")
	case errors.Is(err, vault.ErrUnavailable):
		return status.Error(codes.Unavailable, "vault_unavailable")
	}
	return status.Error(codes.Unavailable, "temporarily_unavailable")
}

// Get returns metadata only.
func (s *SecretsServer) Get(ctx context.Context, req *wardenv1.GetRequest) (*wardenv1.GetResponse, error) {
	subj, err := subjects(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	v, err := s.Secrets.Get(ctx, subj, req.GetId())
	if err != nil {
		return nil, grpcError(err)
	}
	out := &wardenv1.Secret{Id: v.ID, FolderPath: v.FolderPath, Name: v.Name, Username: v.Username, HostUrl: v.HostURL, Description: v.Description, CurrentVersion: int32(v.CurrentVersion), HasTotp: v.HasTOTP} // #nosec G115 -- small counter
	if v.FolderID != nil {
		out.FolderId = *v.FolderID
	}
	return &wardenv1.GetResponse{Secret: out}, nil
}

// GetPassword reveals material (audited).
func (s *SecretsServer) GetPassword(ctx context.Context, req *wardenv1.GetPasswordRequest) (*wardenv1.GetPasswordResponse, error) {
	subj, err := subjects(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == "" || req.GetVersion() < 0 {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	m, err := s.Secrets.Reveal(ctx, subj, req.GetId(), int(req.GetVersion()))
	if err != nil {
		return nil, grpcError(err)
	}
	return &wardenv1.GetPasswordResponse{Password: m.Password, Version: int32(m.Version)}, nil // #nosec G115 -- small counter
}

// Check answers a permission question for the caller.
func (s *SecretsServer) Check(ctx context.Context, req *wardenv1.CheckRequest) (*wardenv1.CheckResponse, error) {
	subj, err := subjects(ctx)
	if err != nil {
		return nil, err
	}
	d, err := s.Authz.Check(ctx, subj, req.GetResourceType(), req.GetResourceId(), req.GetPermission())
	if err != nil {
		return nil, grpcError(err)
	}
	return &wardenv1.CheckResponse{Allowed: d.Allowed, Relation: d.Relation}, nil
}
