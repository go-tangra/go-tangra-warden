import { defineStore } from 'pinia';

import {
  PermissionService,
  type ListPermissionsResponse,
  type GrantAccessResponse,
  type CheckAccessResponse,
  type ListAccessibleResourcesResponse,
  type GetEffectivePermissionsResponse,
  type ResourceType,
  type SubjectType,
  type RelationType,
  type PermissionLevel,
} from '../api/services';
import type { Paging } from '../types';

export const useWardenPermissionStore = defineStore(
  'warden-permission',
  () => {
    /**
     * Grant access to a resource
     */
    async function grantAccess(request: {
      resourceType: ResourceType;
      resourceId: string;
      relation: RelationType;
      subjectType: SubjectType;
      subjectId: string;
      expiresAt?: string;
    }): Promise<GrantAccessResponse> {
      return await PermissionService.grant(request);
    }

    /**
     * Revoke access from a resource
     */
    async function revokeAccess(request: {
      resourceType?: ResourceType;
      resourceId?: string;
      subjectType?: SubjectType;
      subjectId?: string;
      relation?: RelationType;
    }): Promise<void> {
      return await PermissionService.revoke(request);
    }

    /**
     * List permissions
     */
    async function listPermissions(
      paging?: Paging,
      formValues?: {
        resourceType?: ResourceType;
        resourceId?: string;
        subjectType?: SubjectType;
        subjectId?: string;
      } | null,
    ): Promise<ListPermissionsResponse> {
      return await PermissionService.list({
        resourceType: formValues?.resourceType,
        resourceId: formValues?.resourceId,
        subjectType: formValues?.subjectType,
        subjectId: formValues?.subjectId,
        page: paging?.page,
        pageSize: paging?.pageSize,
      });
    }

    /**
     * Check if a subject has access to a resource
     */
    async function checkAccess(
      userId: string,
      resourceType: ResourceType,
      resourceId: string,
      permission: PermissionLevel,
    ): Promise<CheckAccessResponse> {
      return await PermissionService.check({
        userId,
        resourceType,
        resourceId,
        permission,
      });
    }

    /**
     * List resources accessible by a subject
     */
    async function listAccessibleResources(
      userId: string,
      resourceType: ResourceType,
      permission: PermissionLevel,
      paging?: Paging,
    ): Promise<ListAccessibleResourcesResponse> {
      return await PermissionService.listAccessible({
        userId,
        resourceType,
        permission,
        page: paging?.page,
        pageSize: paging?.pageSize,
      });
    }

    /**
     * Get effective permissions for a subject on a resource
     */
    async function getEffectivePermissions(
      userId: string,
      resourceType: ResourceType,
      resourceId: string,
    ): Promise<GetEffectivePermissionsResponse> {
      return await PermissionService.getEffective({
        userId,
        resourceType,
        resourceId,
      });
    }

    function $reset() {}

    return {
      $reset,
      grantAccess,
      revokeAccess,
      listPermissions,
      checkAccess,
      listAccessibleResources,
      getEffectivePermissions,
    };
  },
);
