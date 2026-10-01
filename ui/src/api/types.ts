export interface Permissions {
  read: boolean
  write: boolean
  delete: boolean
  share: boolean
}

export interface Folder {
  id: string
  parent_id: string | null
  name: string
  path: string
  secret_count: number
  created_by?: string
  created_at: string
  updated_at: string
  permissions: Permissions
}

export interface FolderNode {
  folder: Folder
  children: FolderNode[]
}

export interface Secret {
  id: string
  folder_id: string | null
  folder_path: string
  name: string
  username: string
  host_url: string
  description: string
  metadata: Record<string, unknown>
  current_version: number
  has_totp: boolean
  created_by?: string
  updated_by?: string
  created_at: string
  updated_at: string
  permissions: Permissions
}

export interface SecretVersion {
  version: number
  comment: string
  checksum: string
  source: string
  material_missing: boolean
  created_by?: string
  created_at: string
  current: boolean
}

/** Page, size and order of a list request (go-tangra specs/032-server-side-tables). */
export interface ListParams {
  page: number
  page_size: number
  sort: string
  order: 'asc' | 'desc'
}

/** One page of a list: the rows, the records matching the filters and visible to the caller, and the request applied. */
export interface Page<T> {
  items: T[]
  total: number
  /** The page returned: a page beyond the end answers the last page. */
  page?: number
  page_size?: number
  sort?: string
  order?: 'asc' | 'desc'
}

export interface SecretInput {
  folder_id?: string | null
  name: string
  username?: string | undefined
  host_url?: string | undefined
  description?: string | undefined
  metadata?: Record<string, unknown> | undefined
  password?: string | undefined
  totp?: string | undefined
}
