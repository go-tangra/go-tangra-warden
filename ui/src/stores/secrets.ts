import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'
import type { Page, Secret, SecretInput, SecretVersion } from '@/api/types'

export const useSecrets = defineStore('warden-secrets', () => {
  const items = ref<Secret[]>([])
  const next = ref<string | undefined>()
  const loading = ref(false)
  const error = ref('')
  const folderId = ref<string | null>(null)
  const query = ref('')

  async function list(folder: string | null, cursor?: string): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const page = await api<Page<Secret>>('GET', 'secrets', undefined, { query: { folder_id: folder ?? undefined, root: folder === null ? true : undefined, cursor, limit: 50 } })
      items.value = cursor ? [...items.value, ...page.items] : page.items
      next.value = page.next
      folderId.value = folder
      query.value = ''
    } catch (e) {
      error.value = (e as Error).message
    } finally {
      loading.value = false
    }
  }

  async function search(q: string, cursor?: string): Promise<void> {
    if (!q.trim()) return list(folderId.value)
    loading.value = true
    error.value = ''
    try {
      const page = await api<Page<Secret>>('GET', 'secrets/search', undefined, { query: { q: q.trim(), cursor, limit: 50 } })
      items.value = cursor ? [...items.value, ...page.items] : page.items
      next.value = page.next
      query.value = q
    } catch (e) {
      error.value = (e as Error).message
    } finally {
      loading.value = false
    }
  }

  async function more(): Promise<void> {
    if (!next.value) return
    if (query.value) return search(query.value, next.value)
    return list(folderId.value, next.value)
  }

  async function refresh(): Promise<void> {
    if (query.value) return search(query.value)
    return list(folderId.value)
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

  return { items, next, loading, error, folderId, query, list, search, more, refresh, get, create, update, reveal, changePassword, versions, restore, move, remove, totp, setTotp, removeTotp }
})
