package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	wardenV1 "github.com/go-tangra/go-tangra-warden/gen/go/warden/service/v1"
	"github.com/go-tangra/go-tangra-warden/internal/client"
)

type UserService struct {
	wardenV1.UnimplementedWardenUserServiceServer

	log         *log.Helper
	adminClient *client.AdminClient
}

func NewUserService(ctx *bootstrap.Context, adminClient *client.AdminClient) *UserService {
	return &UserService{
		log:         ctx.NewLoggerHelper("warden/service/user"),
		adminClient: adminClient,
	}
}

func (s *UserService) ListUsers(ctx context.Context, req *wardenV1.ListWardenUsersRequest) (*wardenV1.ListWardenUsersResponse, error) {
	resp, err := s.adminClient.ListUsers(ctx)
	if err != nil {
		s.log.Errorf("Failed to list users from admin-service: %v", err)
		return nil, wardenV1.ErrorInternalServerError("failed to list users")
	}

	items := make([]*wardenV1.WardenUser, 0, len(resp.Items))
	for _, u := range resp.Items {
		items = append(items, &wardenV1.WardenUser{
			Id:            u.Id,
			Username:      u.Username,
			Realname:      u.Realname,
			Email:         u.Email,
			OrgUnitNames:  u.OrgUnitNames,
			PositionNames: u.PositionNames,
		})
	}

	return &wardenV1.ListWardenUsersResponse{
		Items: items,
		Total: int32(len(items)),
	}, nil
}

func (s *UserService) ListRoles(ctx context.Context, req *wardenV1.ListWardenRolesRequest) (*wardenV1.ListWardenRolesResponse, error) {
	resp, err := s.adminClient.ListRoles(ctx)
	if err != nil {
		s.log.Errorf("Failed to list roles from admin-service: %v", err)
		return nil, wardenV1.ErrorInternalServerError("failed to list roles")
	}

	items := make([]*wardenV1.WardenRole, 0, len(resp.Items))
	for _, r := range resp.Items {
		items = append(items, &wardenV1.WardenRole{
			Id:          r.Id,
			Name:        r.Name,
			Code:        r.Code,
			Description: r.Description,
		})
	}

	return &wardenV1.ListWardenRolesResponse{
		Items: items,
		Total: int32(len(items)),
	}, nil
}
