import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'

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
  const error = ref('')

  async function list(secretId: string): Promise<void> {
    error.value = ''
    try {
      items.value = (await api<{ items: Share[] }>('GET', 'secrets/' + secretId + '/shares')).items
    } catch (e) {
      error.value = (e as Error).message
      items.value = []
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

  return { items, error, list, create, cancel }
})
