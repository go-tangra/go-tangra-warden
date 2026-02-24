import { defineStore } from 'pinia';

import {
  FolderService,
  type ListFoldersResponse,
  type GetFolderResponse,
  type CreateFolderResponse,
  type UpdateFolderResponse,
  type GetFolderTreeResponse,
  type MoveFolderResponse,
  type CreateFolderRequest,
  type UpdateFolderRequest,
} from '../api/services';
import type { Paging } from '../types';

export const useWardenFolderStore = defineStore('warden-folder', () => {
  /**
   * List folders in a parent folder
   */
  async function listFolders(
    paging?: Paging,
    formValues?: {
      parentId?: string;
      nameFilter?: string;
    } | null,
  ): Promise<ListFoldersResponse> {
    return await FolderService.list({
      parentId: formValues?.parentId,
      nameFilter: formValues?.nameFilter,
      page: paging?.page,
      pageSize: paging?.pageSize,
    });
  }

  /**
   * Get a folder by ID
   */
  async function getFolder(
    id: string,
    includeCounts?: boolean,
  ): Promise<GetFolderResponse> {
    return await FolderService.get(id, { includeCounts });
  }

  /**
   * Create a new folder
   */
  async function createFolder(
    request: CreateFolderRequest,
  ): Promise<CreateFolderResponse> {
    return await FolderService.create(request);
  }

  /**
   * Update folder metadata
   */
  async function updateFolder(
    id: string,
    request: Omit<UpdateFolderRequest, 'id'>,
  ): Promise<UpdateFolderResponse> {
    return await FolderService.update(id, request);
  }

  /**
   * Delete a folder
   */
  async function deleteFolder(id: string, force?: boolean): Promise<void> {
    return await FolderService.delete(id, { force });
  }

  /**
   * Move a folder to a new parent
   */
  async function moveFolder(
    id: string,
    newParentId?: string,
  ): Promise<MoveFolderResponse> {
    return await FolderService.move(id, newParentId);
  }

  /**
   * Get the folder tree structure
   */
  async function getFolderTree(
    rootId?: string,
    maxDepth?: number,
    includeCounts?: boolean,
  ): Promise<GetFolderTreeResponse> {
    return await FolderService.getTree({ rootId, maxDepth, includeCounts });
  }

  function $reset() {}

  return {
    $reset,
    listFolders,
    getFolder,
    createFolder,
    updateFolder,
    deleteFolder,
    moveFolder,
    getFolderTree,
  };
});
