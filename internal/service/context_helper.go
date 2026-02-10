package service

import "github.com/go-tangra/go-tangra-common/grpcx"

var (
	getMetadataValue      = grpcx.GetMetadataValue
	getTenantIDFromContext = grpcx.GetTenantIDFromContext
	getUserIDFromContext   = grpcx.GetUserIDFromContext
	getUserIDAsUint32     = grpcx.GetUserIDAsUint32
	getUsernameFromContext = grpcx.GetUsernameFromContext
	getRolesFromContext   = grpcx.GetRolesFromContext
	isPlatformAdmin       = grpcx.IsPlatformAdmin
)
