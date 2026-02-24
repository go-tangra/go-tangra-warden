/**
 * Warden Module Service Functions
 *
 * Typed service methods for the Warden API using dynamic module routing.
 * Base URL: /admin/v1/modules/warden/v1
 */

import type { components, operations } from './types';
import { wardenApi, type RequestOptions } from './client';

// ==================== Entity Type Aliases ====================

export type Folder = components['schemas']['Folder'];
export type FolderTreeNode = components['schemas']['FolderTreeNode'];
export type Secret = components['schemas']['Secret'];
export type SecretVersion = components['schemas']['SecretVersion'];
export type PermissionTuple = components['schemas']['PermissionTuple'];
export type ComponentHealth = components['schemas']['ComponentHealth'];
export type ImportError = components['schemas']['ImportError'];

// ==================== Enum Types (derived from entity fields) ====================

export type InitialPermissionGrant = components['schemas']['InitialPermissionGrant'];
export type SecretStatus = NonNullable<Secret['status']>;
export type ResourceType = NonNullable<PermissionTuple['resourceType']>;
export type RelationType = NonNullable<PermissionTuple['relation']>;
export type SubjectType = NonNullable<PermissionTuple['subjectType']>;
export type PermissionLevel = NonNullable<components['schemas']['CheckAccessRequest']['permission']>;
export type HealthStatus = NonNullable<ComponentHealth['status']>;
export type DuplicateHandling = NonNullable<components['schemas']['ImportFromBitwardenRequest']['duplicateHandling']>;

// ==================== List Response Types ====================

export type ListFoldersResponse = components['schemas']['ListFoldersResponse'];
export type ListSecretsResponse = components['schemas']['ListSecretsResponse'];
export type ListVersionsResponse = components['schemas']['ListVersionsResponse'];
export type ListPermissionsResponse = components['schemas']['ListPermissionsResponse'];
export type ListAccessibleResourcesResponse = components['schemas']['ListAccessibleResourcesResponse'];

// ==================== Get Response Types ====================

export type GetFolderResponse = components['schemas']['GetFolderResponse'];
export type GetFolderTreeResponse = components['schemas']['GetFolderTreeResponse'];
export type GetSecretResponse = components['schemas']['GetSecretResponse'];
export type GetSecretPasswordResponse = components['schemas']['GetSecretPasswordResponse'];
export type GetVersionResponse = components['schemas']['GetVersionResponse'];
export type GetEffectivePermissionsResponse = components['schemas']['GetEffectivePermissionsResponse'];
export type GetInfoResponse = components['schemas']['GetInfoResponse'];

// ==================== Create Response Types ====================

export type CreateFolderResponse = components['schemas']['CreateFolderResponse'];
export type CreateSecretResponse = components['schemas']['CreateSecretResponse'];

// ==================== Update Response Types ====================

export type UpdateFolderResponse = components['schemas']['UpdateFolderResponse'];
export type UpdateSecretResponse = components['schemas']['UpdateSecretResponse'];
export type UpdateSecretPasswordResponse = components['schemas']['UpdateSecretPasswordResponse'];

// ==================== Other Response Types ====================

export type MoveFolderResponse = components['schemas']['MoveFolderResponse'];
export type MoveSecretResponse = components['schemas']['MoveSecretResponse'];
export type SearchSecretsResponse = components['schemas']['SearchSecretsResponse'];
export type RestoreVersionResponse = components['schemas']['RestoreVersionResponse'];
export type GrantAccessResponse = components['schemas']['GrantAccessResponse'];
export type CheckAccessResponse = components['schemas']['CheckAccessResponse'];
export type HealthResponse = components['schemas']['HealthResponse'];
export type CheckVaultResponse = components['schemas']['CheckVaultResponse'];
export type ExportToBitwardenResponse = components['schemas']['ExportToBitwardenResponse'];
export type ImportFromBitwardenResponse = components['schemas']['ImportFromBitwardenResponse'];
export type ValidateBitwardenImportResponse = components['schemas']['ValidateBitwardenImportResponse'];

// ==================== Request Types ====================

export type CreateFolderRequest = components['schemas']['CreateFolderRequest'];
export type UpdateFolderRequest = components['schemas']['UpdateFolderRequest'];
export type MoveFolderRequest = components['schemas']['MoveFolderRequest'];
export type CreateSecretRequest = components['schemas']['CreateSecretRequest'];
export type UpdateSecretRequest = components['schemas']['UpdateSecretRequest'];
export type UpdateSecretPasswordRequest = components['schemas']['UpdateSecretPasswordRequest'];
export type MoveSecretRequest = components['schemas']['MoveSecretRequest'];
export type GrantAccessRequest = components['schemas']['GrantAccessRequest'];
export type CheckAccessRequest = components['schemas']['CheckAccessRequest'];
export type ExportToBitwardenRequest = components['schemas']['ExportToBitwardenRequest'];
export type ImportFromBitwardenRequest = components['schemas']['ImportFromBitwardenRequest'];
export type ValidateBitwardenImportRequest = components['schemas']['ValidateBitwardenImportRequest'];

// ==================== Helper Functions ====================

function buildQuery(params: Record<string, unknown>): string {
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      if (Array.isArray(value)) {
        value.forEach(v => searchParams.append(key, String(v)));
      } else {
        searchParams.append(key, String(value));
      }
    }
  }
  const query = searchParams.toString();
  return query ? `?${query}` : '';
}

// ==================== Folder Service ====================

export const FolderService = {
  list: async (
    params?: operations['WardenFolderService_ListFolders']['parameters']['query'],
    options?: RequestOptions
  ): Promise<ListFoldersResponse> => {
    return wardenApi.get<ListFoldersResponse>(`/folders${buildQuery(params || {})}`, options);
  },

  get: async (
    id: string,
    params?: operations['WardenFolderService_GetFolder']['parameters']['query'],
    options?: RequestOptions
  ): Promise<GetFolderResponse> => {
    return wardenApi.get<GetFolderResponse>(`/folders/${id}${buildQuery(params || {})}`, options);
  },

  create: async (
    data: CreateFolderRequest,
    options?: RequestOptions
  ): Promise<CreateFolderResponse> => {
    return wardenApi.post<CreateFolderResponse>('/folders', data, options);
  },

  update: async (
    id: string,
    data: Omit<UpdateFolderRequest, 'id'>,
    options?: RequestOptions
  ): Promise<UpdateFolderResponse> => {
    return wardenApi.put<UpdateFolderResponse>(`/folders/${id}`, { ...data, id }, options);
  },

  delete: async (
    id: string,
    params?: operations['WardenFolderService_DeleteFolder']['parameters']['query'],
    options?: RequestOptions
  ): Promise<void> => {
    return wardenApi.delete<void>(`/folders/${id}${buildQuery(params || {})}`, options);
  },

  getTree: async (
    params?: operations['WardenFolderService_GetFolderTree']['parameters']['query'],
    options?: RequestOptions
  ): Promise<GetFolderTreeResponse> => {
    return wardenApi.get<GetFolderTreeResponse>(`/folders/tree${buildQuery(params || {})}`, options);
  },

  move: async (
    id: string,
    newParentId?: string,
    options?: RequestOptions
  ): Promise<MoveFolderResponse> => {
    return wardenApi.post<MoveFolderResponse>(`/folders/${id}/move`, { id, newParentId }, options);
  },
};

// ==================== Secret Service ====================

export const SecretService = {
  list: async (
    params?: operations['WardenSecretService_ListSecrets']['parameters']['query'],
    options?: RequestOptions
  ): Promise<ListSecretsResponse> => {
    return wardenApi.get<ListSecretsResponse>(`/secrets${buildQuery(params || {})}`, options);
  },

  get: async (id: string, options?: RequestOptions): Promise<GetSecretResponse> => {
    return wardenApi.get<GetSecretResponse>(`/secrets/${id}`, options);
  },

  create: async (
    data: CreateSecretRequest,
    options?: RequestOptions
  ): Promise<CreateSecretResponse> => {
    return wardenApi.post<CreateSecretResponse>('/secrets', data, options);
  },

  update: async (
    id: string,
    data: Omit<UpdateSecretRequest, 'id'>,
    options?: RequestOptions
  ): Promise<UpdateSecretResponse> => {
    return wardenApi.put<UpdateSecretResponse>(`/secrets/${id}`, { ...data, id }, options);
  },

  delete: async (
    id: string,
    params?: operations['WardenSecretService_DeleteSecret']['parameters']['query'],
    options?: RequestOptions
  ): Promise<void> => {
    return wardenApi.delete<void>(`/secrets/${id}${buildQuery(params || {})}`, options);
  },

  getPassword: async (
    id: string,
    params?: operations['WardenSecretService_GetSecretPassword']['parameters']['query'],
    options?: RequestOptions
  ): Promise<GetSecretPasswordResponse> => {
    return wardenApi.get<GetSecretPasswordResponse>(`/secrets/${id}/password${buildQuery(params || {})}`, options);
  },

  updatePassword: async (
    id: string,
    password: string,
    comment?: string,
    options?: RequestOptions
  ): Promise<UpdateSecretPasswordResponse> => {
    return wardenApi.put<UpdateSecretPasswordResponse>(`/secrets/${id}/password`, { id, password, comment }, options);
  },

  search: async (
    params?: operations['WardenSecretService_SearchSecrets']['parameters']['query'],
    options?: RequestOptions
  ): Promise<SearchSecretsResponse> => {
    return wardenApi.get<SearchSecretsResponse>(`/secrets/search${buildQuery(params || {})}`, options);
  },

  move: async (
    id: string,
    newFolderId?: string,
    options?: RequestOptions
  ): Promise<MoveSecretResponse> => {
    return wardenApi.post<MoveSecretResponse>(`/secrets/${id}/move`, { id, newFolderId }, options);
  },

  listVersions: async (
    secretId: string,
    params?: operations['WardenSecretService_ListVersions']['parameters']['query'],
    options?: RequestOptions
  ): Promise<ListVersionsResponse> => {
    return wardenApi.get<ListVersionsResponse>(`/secrets/${secretId}/versions${buildQuery(params || {})}`, options);
  },

  getVersion: async (
    secretId: string,
    versionNumber: number,
    params?: operations['WardenSecretService_GetVersion']['parameters']['query'],
    options?: RequestOptions
  ): Promise<GetVersionResponse> => {
    return wardenApi.get<GetVersionResponse>(
      `/secrets/${secretId}/versions/${versionNumber}${buildQuery(params || {})}`,
      options
    );
  },

  restoreVersion: async (
    secretId: string,
    versionNumber: number,
    params?: operations['WardenSecretService_RestoreVersion']['parameters']['query'],
    options?: RequestOptions
  ): Promise<RestoreVersionResponse> => {
    return wardenApi.post<RestoreVersionResponse>(
      `/secrets/${secretId}/versions/${versionNumber}/restore${buildQuery(params || {})}`,
      undefined,
      options
    );
  },
};

// ==================== Permission Service ====================

export const PermissionService = {
  list: async (
    params?: operations['WardenPermissionService_ListPermissions']['parameters']['query'],
    options?: RequestOptions
  ): Promise<ListPermissionsResponse> => {
    return wardenApi.get<ListPermissionsResponse>(`/permissions${buildQuery(params || {})}`, options);
  },

  grant: async (
    data: GrantAccessRequest,
    options?: RequestOptions
  ): Promise<GrantAccessResponse> => {
    return wardenApi.post<GrantAccessResponse>('/permissions', data, options);
  },

  revoke: async (
    params?: operations['WardenPermissionService_RevokeAccess']['parameters']['query'],
    options?: RequestOptions
  ): Promise<void> => {
    return wardenApi.delete<void>(`/permissions${buildQuery(params || {})}`, options);
  },

  check: async (
    data: CheckAccessRequest,
    options?: RequestOptions
  ): Promise<CheckAccessResponse> => {
    return wardenApi.post<CheckAccessResponse>('/permissions/check', data, options);
  },

  listAccessible: async (
    params?: operations['WardenPermissionService_ListAccessibleResources']['parameters']['query'],
    options?: RequestOptions
  ): Promise<ListAccessibleResourcesResponse> => {
    return wardenApi.get<ListAccessibleResourcesResponse>(
      `/permissions/accessible${buildQuery(params || {})}`,
      options
    );
  },

  getEffective: async (
    params?: operations['WardenPermissionService_GetEffectivePermissions']['parameters']['query'],
    options?: RequestOptions
  ): Promise<GetEffectivePermissionsResponse> => {
    return wardenApi.get<GetEffectivePermissionsResponse>(
      `/permissions/effective${buildQuery(params || {})}`,
      options
    );
  },
};

// ==================== Bitwarden Transfer Service ====================

export const BitwardenTransferService = {
  export: async (
    data: ExportToBitwardenRequest,
    options?: RequestOptions
  ): Promise<ExportToBitwardenResponse> => {
    return wardenApi.post<ExportToBitwardenResponse>('/bitwarden/export', data, options);
  },

  import: async (
    data: ImportFromBitwardenRequest,
    options?: RequestOptions
  ): Promise<ImportFromBitwardenResponse> => {
    return wardenApi.post<ImportFromBitwardenResponse>('/bitwarden/import', data, options);
  },

  validate: async (
    data: ValidateBitwardenImportRequest,
    options?: RequestOptions
  ): Promise<ValidateBitwardenImportResponse> => {
    return wardenApi.post<ValidateBitwardenImportResponse>('/bitwarden/validate', data, options);
  },
};

// ==================== System Service ====================

export const SystemService = {
  health: async (options?: RequestOptions): Promise<HealthResponse> => {
    return wardenApi.get<HealthResponse>('/health', options);
  },

  getInfo: async (options?: RequestOptions): Promise<GetInfoResponse> => {
    return wardenApi.get<GetInfoResponse>('/info', options);
  },

  checkVault: async (options?: RequestOptions): Promise<CheckVaultResponse> => {
    return wardenApi.get<CheckVaultResponse>('/vault/check', options);
  },
};
