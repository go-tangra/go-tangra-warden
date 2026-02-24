import { defineStore } from 'pinia';

import {
  SecretService,
  type ListSecretsResponse,
  type GetSecretResponse,
  type CreateSecretResponse,
  type UpdateSecretResponse,
  type GetSecretPasswordResponse,
  type UpdateSecretPasswordResponse,
  type SearchSecretsResponse,
  type ListVersionsResponse,
  type GetVersionResponse,
  type RestoreVersionResponse,
  type MoveSecretResponse,
  type SecretStatus,
  type CreateSecretRequest,
  type UpdateSecretRequest,
} from '../api/services';
import { wardenApi } from '../api/client';
import type { Paging } from '../types';

export const useWardenSecretStore = defineStore('warden-secret', () => {
  /**
   * List secrets in a folder
   */
  async function listSecrets(
    paging?: Paging,
    formValues?: {
      folderId?: string;
      nameFilter?: string;
      status?: SecretStatus;
    } | null,
  ): Promise<ListSecretsResponse> {
    return await SecretService.list({
      folderId: formValues?.folderId,
      nameFilter: formValues?.nameFilter,
      status: formValues?.status,
      page: paging?.page,
      pageSize: paging?.pageSize,
    });
  }

  /**
   * Get a secret by ID (metadata only)
   */
  async function getSecret(id: string): Promise<GetSecretResponse> {
    return await SecretService.get(id);
  }

  /**
   * Get secret value/password
   */
  async function getSecretPassword(
    id: string,
    version?: number,
  ): Promise<GetSecretPasswordResponse> {
    return await SecretService.getPassword(id, { version });
  }

  /**
   * Update secret password (creates new version)
   */
  async function updateSecretPassword(
    id: string,
    password: string,
    comment?: string,
  ): Promise<UpdateSecretPasswordResponse> {
    return await SecretService.updatePassword(id, password, comment);
  }

  /**
   * Get a specific version of a secret
   */
  async function getVersion(
    secretId: string,
    versionNumber: number,
    includePassword?: boolean,
  ): Promise<GetVersionResponse> {
    return await SecretService.getVersion(secretId, versionNumber, { includePassword });
  }

  /**
   * Restore a previous version as current
   */
  async function restoreVersion(
    secretId: string,
    versionNumber: number,
    comment?: string,
  ): Promise<RestoreVersionResponse> {
    return await SecretService.restoreVersion(secretId, versionNumber, { comment });
  }

  /**
   * Create a new secret
   */
  async function createSecret(
    request: CreateSecretRequest,
  ): Promise<CreateSecretResponse> {
    return await SecretService.create(request);
  }

  /**
   * Update secret metadata
   */
  async function updateSecret(
    id: string,
    request: Omit<UpdateSecretRequest, 'id'>,
  ): Promise<UpdateSecretResponse> {
    return await SecretService.update(id, request);
  }

  /**
   * Delete a secret
   */
  async function deleteSecret(id: string, permanent?: boolean): Promise<void> {
    return await SecretService.delete(id, { permanent });
  }

  /**
   * Move secret to a different folder
   */
  async function moveSecret(id: string, newFolderId?: string): Promise<MoveSecretResponse> {
    return await SecretService.move(id, newFolderId);
  }

  /**
   * List all versions of a secret
   */
  async function listVersions(
    secretId: string,
    paging?: Paging,
  ): Promise<ListVersionsResponse> {
    return await SecretService.listVersions(secretId, {
      page: paging?.page,
      pageSize: paging?.pageSize,
    });
  }

  /**
   * Search secrets across folders
   */
  async function searchSecrets(
    query: string,
    paging?: Paging,
    formValues?: {
      folderId?: string;
      includeSubfolders?: boolean;
      status?: SecretStatus;
    } | null,
  ): Promise<SearchSecretsResponse> {
    return await SecretService.search({
      query,
      folderId: formValues?.folderId,
      includeSubfolders: formValues?.includeSubfolders,
      status: formValues?.status,
      page: paging?.page,
      pageSize: paging?.pageSize,
    });
  }

  /**
   * Export secrets to Bitwarden JSON format
   */
  async function exportToBitwarden(options?: {
    folderId?: string;
    includeSubfolders?: boolean;
  }) {
    return await wardenApi.post('/bitwarden/export', {
      folderId: options?.folderId,
      includeSubfolders: options?.includeSubfolders ?? true,
    });
  }

  /**
   * Import secrets from Bitwarden JSON format
   */
  async function importFromBitwarden(
    jsonData: string,
    options?: {
      targetFolderId?: string;
      duplicateHandling?: string;
      preserveFolders?: boolean;
      permissionRules?: Array<{
        subjectType: string;
        subjectId: string;
        relation: string;
      }>;
    },
  ) {
    return await wardenApi.post('/bitwarden/import', {
      jsonData,
      targetFolderId: options?.targetFolderId,
      duplicateHandling: options?.duplicateHandling,
      preserveFolders: options?.preserveFolders ?? true,
      permissionRules: options?.permissionRules,
    });
  }

  /**
   * Validate Bitwarden import without making changes
   */
  async function validateBitwardenImport(
    jsonData: string,
    options?: {
      targetFolderId?: string;
      preserveFolders?: boolean;
    },
  ) {
    return await wardenApi.post('/bitwarden/validate', {
      jsonData,
      targetFolderId: options?.targetFolderId,
      preserveFolders: options?.preserveFolders ?? true,
    });
  }

  function $reset() {}

  return {
    $reset,
    listSecrets,
    getSecret,
    getSecretPassword,
    updateSecretPassword,
    getVersion,
    restoreVersion,
    createSecret,
    updateSecret,
    deleteSecret,
    moveSecret,
    listVersions,
    searchSecrets,
    // Bitwarden import/export
    exportToBitwarden,
    importFromBitwarden,
    validateBitwardenImport,
  };
});
