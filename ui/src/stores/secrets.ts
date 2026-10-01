import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'
import type { ListParams, Page, Secret, SecretInput, SecretVersion } from '@/api/types'
import { SEARCH_LIST, SECRET_LIST } from '@/stores/paged'

export const useSecrets = defineStore('warden-secrets', () => {
  const items = ref<Secret[]>([])
  /** Secrets matching the folder or search and visible to the caller (server count). */
  const total = ref(0)
  /** The page the server returned (it clamps pages beyond the end). */
  const page = ref(1)
  const params = ref<ListParams>({ ...SECRET_LIST.first })
  const loading = ref(false)
  const error = ref('')
  const folderId = ref<string | null>(null)
  const query = ref('')
  let seq = 0

  /** Loads one page; resolves with it, or null when it failed or a newer request superseded it. */
  async function load(path: 'secrets' | 'secrets/search', q: Record<string, string | number | boolean | undefined>, p: ListParams): Promise<Page<Secret> | null> {
    const mine = ++seq
    loading.value = true
    error.value = ''
    params.value = { ...p }
    try {
      const res = await api<Page<Secret>>('GET', path, undefined, { query: { ...q, ...p } })
      if (mine !== seq) return null
      items.value = res.items ?? []
      total.value = res.total ?? items.value.length
      page.value = res.page ?? p.page
      return res
    } catch (e) {
      if (mine === seq) error.value = (e as Error).message
      return null
    } finally {
      if (mine === seq) loading.value = false
    }
  }

  /** One page of a folder's secrets (the root when null). */
  async function list(folder: string | null, p: ListParams = SECRET_LIST.first): Promise<Page<Secret> | null> {
    folderId.value = folder
    query.value = ''
    return load('secrets', { folder_id: folder ?? undefined, root: folder === null ? true : undefined }, p)
  }

  /** One page of search results (blank text lists the current folder). */
  async function search(q: string, p: ListParams = SEARCH_LIST.first): Promise<Page<Secret> | null> {
    if (!q.trim()) return list(folderId.value)
    query.value = q.trim()
    return load('secrets/search', { q: q.trim() }, p)
  }

  /** Reloads the current page. */
  async function refresh(): Promise<void> {
    if (query.value) await search(query.value, params.value)
    else await list(folderId.value, params.value)
  }

  async function get(id: string): Promise<Secret> {
    return api<Secret>('GET', 'secrets/' + id)
  }

  async function create(input: SecretInput): Promise<Secret> {
    const s = await api<Secret>('POST', 'secrets', input)
    await refresh()
    return s
  }

  async function update(id: string, patch: Partial<SecretInput>): Promise<Secret> {
    const s = await api<Secret>('PUT', 'secrets/' + id, patch)
    items.value = items.value.map((i) => (i.id === id ? s : i))
    return s
  }

  async function reveal(id: string, version?: number): Promise<{ password: string; version: number }> {
    return api('GET', 'secrets/' + id + '/password', undefined, { query: { version } })
  }

  async function changePassword(id: string, password: string, comment: string): Promise<number> {
    const out = await api<{ version: number }>('PUT', 'secrets/' + id + '/password', { password, comment })
    await refresh()
    return out.version
  }

  async function versions(id: string): Promise<SecretVersion[]> {
    const out = await api<{ items: SecretVersion[] }>('GET', 'secrets/' + id + '/versions')
    return out.items
  }

  async function restore(id: string, version: number, comment: string): Promise<number> {
    const out = await api<{ version: number }>('POST', 'secrets/' + id + '/versions/' + version + '/restore', { comment })
    await refresh()
    return out.version
  }

  async function move(id: string, folder: string | null): Promise<Secret> {
    const s = await api<Secret>('POST', 'secrets/' + id + '/move', { folder_id: folder })
    await refresh()
    return s
  }

  async function remove(id: string): Promise<void> {
    await api('POST', 'secrets/' + id + '/remove')
    items.value = items.value.filter((i) => i.id !== id)
    await refresh()
  }

  async function totp(id: string): Promise<{ code: string; period: number; expires_in: number }> {
    return api('GET', 'secrets/' + id + '/totp')
  }

  async function setTotp(id: string, seed: string): Promise<void> {
    await api('PUT', 'secrets/' + id + '/totp', { totp: seed })
    await refresh()
  }

  async function removeTotp(id: string): Promise<void> {
    await api('DELETE', 'secrets/' + id + '/totp')
    await refresh()
  }

  return { items, total, page, params, loading, error, folderId, query, list, search, refresh, get, create, update, reveal, changePassword, versions, restore, move, remove, totp, setTotp, removeTotp }
})
