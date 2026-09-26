import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'

export interface Stats {
  secrets: number
  secrets_with_totp: number
  folders: number
  versions: number
  grants: Record<string, number>
  shares: Record<string, number>
  operations_24h: number
}

export interface AuditItem {
  ts: string
  event_type: string
  actor_kind: string
  actor_id?: string
  subject_kind?: string
  subject_id?: string
  /** Secret name or folder path, while the subject still exists. */
  subject_name?: string
  outcome: string
  reason?: string
  details: Record<string, unknown>
}

export interface AuditFilter {
  event_type?: string | undefined
  actor_id?: string | undefined
  from?: string | undefined
  to?: string | undefined
}

export interface GeneratorOptions {
  length: number
  lower: boolean
  upper: boolean
  digits: boolean
  symbols: boolean
}

export const CLASSES = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.<>?/~',
}

/** Client-side generator with the same rules as the server (offline preview). */
export function generateLocal(o: GeneratorOptions): string {
  const classes = (['lower', 'upper', 'digits', 'symbols'] as const).filter((k) => o[k]).map((k) => CLASSES[k])
  if (!classes.length || o.length < 8 || o.length > 128) throw new Error('validation_failed')
  const all = classes.join('')
  const pick = (alphabet: string): string => {
    const limit = 256 - (256 % alphabet.length)
    const buf = new Uint8Array(1)
    for (;;) {
      crypto.getRandomValues(buf)
      const b = buf[0] ?? 0
      if (b < limit) return alphabet[b % alphabet.length] ?? ''
    }
  }
  const out: string[] = []
  for (let i = 0; i < o.length; i++) out.push(pick(i < classes.length ? (classes[i] ?? all) : all))
  for (let i = out.length - 1; i > 0; i--) {
    const buf = new Uint8Array(1)
    let j: number
    const limit = 256 - (256 % (i + 1))
    do {
      crypto.getRandomValues(buf)
      j = buf[0] ?? 0
    } while (j >= limit)
    j %= i + 1
    ;[out[i], out[j]] = [out[j] ?? '', out[i] ?? '']
  }
  return out.join('')
}

/** Checks a password against the options (used by tests and the view). */
export function satisfies(p: string, o: GeneratorOptions): boolean {
  if (p.length !== o.length) return false
  const classes = (['lower', 'upper', 'digits', 'symbols'] as const).filter((k) => o[k]).map((k) => CLASSES[k])
  const all = classes.join('')
  return classes.every((c) => [...p].some((ch) => c.includes(ch))) && [...p].every((ch) => all.includes(ch))
}

export const useOps = defineStore('warden-ops', () => {
  const stats = ref<Stats | null>(null)
  const audit = ref<AuditItem[]>([])
  const next = ref('')
  const error = ref('')

  async function loadStats(): Promise<void> {
    error.value = ''
    try {
      stats.value = await api<Stats>('GET', 'stats')
    } catch (e) {
      error.value = (e as Error).message
    }
  }

  async function loadAudit(filter: AuditFilter, cursor?: string): Promise<void> {
    error.value = ''
    try {
      const page = await api<{ items: AuditItem[]; next_cursor?: string }>('GET', 'audit', undefined, { query: { ...filter, cursor } })
      audit.value = cursor ? [...audit.value, ...page.items] : page.items
      next.value = page.next_cursor ?? ''
    } catch (e) {
      error.value = (e as Error).message
    }
  }

  async function generate(o: GeneratorOptions): Promise<string> {
    // Only the generator options: the API refuses unknown fields.
    const { length, lower, upper, digits, symbols } = o
    const out = await api<{ password: string }>('POST', 'generate', { length, lower, upper, digits, symbols })
    return out.password
  }

  return { stats, audit, next, error, loadStats, loadAudit, generate }
})
