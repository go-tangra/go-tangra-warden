import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'
import type { ListParams, Page } from '@/api/types'
import { SHARE_LIST } from '@/stores/paged'

export interface Share {
  id: string
  secret_id: string
  recipient_email: string
  message?: string
  max_opens: number
  opens: number
  expires_at: string
  cidr?: string
  region?: string
  state: 'active' | 'consumed' | 'expired' | 'cancelled'
  created_at: string
}

export interface ShareInput {
  recipient_email: string
  message?: string | undefined
  validity_seconds?: number | undefined
  max_opens?: number | undefined
  cidr?: string | undefined
  region?: string | undefined
}

export const useShares = defineStore('warden-shares', () => {
  const items = ref<Share[]>([])
  /** The caller's shares of the secret (server count). */
  const total = ref(0)
  const params = ref<ListParams>({ ...SHARE_LIST.first })
  const loading = ref(false)
  const error = ref('')
  let seq = 0

  /** One page of the caller's shares of a secret (newest first by default). */
  async function list(secretId: string, p: ListParams = params.value): Promise<void> {
    const mine = ++seq
    error.value = ''
    loading.value = true
    params.value = { ...p }
    try {
      const res = await api<Page<Share>>('GET', 'secrets/' + secretId + '/shares', undefined, { query: { ...p } })
      if (mine !== seq) return
      items.value = res.items ?? []
      total.value = res.total ?? items.value.length
      if (res.page && res.page !== p.page) params.value = { ...p, page: res.page }
    } catch (e) {
      if (mine !== seq) return
      error.value = (e as Error).message
      items.value = []
      total.value = 0
    } finally {
      if (mine === seq) loading.value = false
    }
  }

  async function create(secretId: string, input: ShareInput): Promise<Share> {
    const s = await api<Share>('POST', 'secrets/' + secretId + '/shares', input)
    await list(secretId)
    return s
  }

  async function cancel(secretId: string, shareId: string): Promise<void> {
    await api('POST', 'shares/' + shareId + '/cancel')
    await list(secretId)
  }

  return { items, total, params, loading, error, list, create, cancel }
})
