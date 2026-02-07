package service

import (
	"context"
	"strconv"

	grpcMD "google.golang.org/grpc/metadata"
)

const (
	// Metadata keys using Kratos x-md-global- prefix for cross-service propagation.
	// These are set by the admin-service transcoder and forwarded via gRPC metadata.
	mdTenantID = "x-md-global-tenant-id"
	mdUserID   = "x-md-global-user-id"
	mdUsername  = "x-md-global-username"
	mdRoles    = "x-md-global-roles"
)

// getMetadataValue extracts a single value from gRPC incoming metadata
func getMetadataValue(ctx context.Context, key string) string {
	md, ok := grpcMD.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// getTenantIDFromContext extracts the tenant ID from gRPC metadata
func getTenantIDFromContext(ctx context.Context) uint32 {
	tenantStr := getMetadataValue(ctx, mdTenantID)
	if tenantStr == "" {
		return 0
	}

	tenantID, err := strconv.ParseUint(tenantStr, 10, 32)
	if err != nil {
		return 0
	}

	return uint32(tenantID)
}

// getUserIDFromContext extracts the user ID as a string from gRPC metadata
func getUserIDFromContext(ctx context.Context) string {
	return getMetadataValue(ctx, mdUserID)
}

// getUserIDAsUint32 extracts the user ID as uint32 pointer from gRPC metadata
func getUserIDAsUint32(ctx context.Context) *uint32 {
	userStr := getUserIDFromContext(ctx)
	if userStr == "" {
		return nil
	}

	userID, err := strconv.ParseUint(userStr, 10, 32)
	if err != nil {
		return nil
	}

	id := uint32(userID)
	return &id
}

// getUsernameFromContext extracts the username from gRPC metadata
func getUsernameFromContext(ctx context.Context) string {
	return getMetadataValue(ctx, mdUsername)
}

// getRolesFromContext extracts the roles from gRPC metadata (comma-separated)
func getRolesFromContext(ctx context.Context) []string {
	rolesStr := getMetadataValue(ctx, mdRoles)
	if rolesStr == "" {
		return nil
	}

	// Split by comma
	var roles []string
	for _, role := range splitRoles(rolesStr) {
		if role != "" {
			roles = append(roles, role)
		}
	}
	return roles
}

// splitRoles splits a comma-separated roles string
func splitRoles(rolesStr string) []string {
	if rolesStr == "" {
		return nil
	}

	var roles []string
	start := 0
	for i := 0; i < len(rolesStr); i++ {
		if rolesStr[i] == ',' {
			role := rolesStr[start:i]
			if role != "" {
				roles = append(roles, role)
			}
			start = i + 1
		}
	}
	// Add the last part
	if start < len(rolesStr) {
		role := rolesStr[start:]
		if role != "" {
			roles = append(roles, role)
		}
	}
	return roles
}

// isPlatformAdmin checks if the user has platform admin role
func isPlatformAdmin(ctx context.Context) bool {
	roles := getRolesFromContext(ctx)
	for _, role := range roles {
		if role == "platform:admin" || role == "super:admin" {
			return true
		}
	}
	return false
}
