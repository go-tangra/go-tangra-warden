import type { ListQueryOptions } from '@go-tangra/ui'
import type { ListParams } from '@/api/types'

// Server-paged lists (go-tangra specs/032-server-side-tables): every table
// asks the server for one page (page, page_size, sort, order) and shows the
// total; sorting orders the whole list on the server. Sort fields are the
// server's allow-list (api/openapi/warden.yaml) — never material.

export const PAGE_SIZE = 25

/** The kit list-query options and the first page of a list with these sort fields. */
export function listSpec(sortable: readonly string[], key: string, dir: 'asc' | 'desc' = 'asc', size = PAGE_SIZE): { opts: ListQueryOptions; first: ListParams } {
  return {
    opts: { sortable: [...sortable], defaultSort: { key, dir }, defaultSize: size },
    first: { page: 1, page_size: size, sort: key, order: dir },
  }
}

/** The folder view: secrets of one folder (folders are listed first, unpaged). */
export const SECRET_LIST = listSpec(['name', 'updated_at', 'created_at'], 'name')
/** Search results: name matches first (relevance), then name order. */
export const SEARCH_LIST = listSpec(['relevance', 'name', 'updated_at'], 'relevance', 'desc')
/** A secret's email shares: newest first. */
export const SHARE_LIST = listSpec(['created_at', 'expires_at'], 'created_at', 'desc', 10)
/** The audit trail: newest first within the server's default 7-day window. */
export const AUDIT_LIST = listSpec(['ts'], 'ts', 'desc', 50)
