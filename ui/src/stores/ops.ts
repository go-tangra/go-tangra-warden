import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, ApiError } from '@/api/client'
import { AUDIT_SPAN_MESSAGE } from '@/schemas/audit'
import type { ListParams, Page } from '@/api/types'
import { AUDIT_LIST } from '@/stores/paged'

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
  /** Events matching the filter within the window (server count). */
  const auditTotal = ref(0)
  const auditLoading = ref(false)
  const error = ref('')
  /** Why the last audit page failed (a window over 90 days reads as such). */
  const auditError = ref('')
  let auditSeq = 0

  async function loadStats(): Promise<void> {
    error.value = ''
    try {
      stats.value = await api<Stats>('GET', 'stats')
    } catch (e) {
      error.value = (e as Error).message
    }
  }

  /**
   * One page of the audit trail (newest first). Without from/to the server
   * answers the last 7 days. Resolves with the page, or null when it failed
   * or a newer request superseded it.
   */
  async function loadAudit(filter: AuditFilter, p: ListParams = AUDIT_LIST.first): Promise<Page<AuditItem> | null> {
    const mine = ++auditSeq
    error.value = ''
    auditError.value = ''
    auditLoading.value = true
    try {
      const res = await api<Page<AuditItem>>('GET', 'audit', undefined, { query: { ...filter, ...p } })
      if (mine !== auditSeq) return null
      audit.value = res.items ?? []
      auditTotal.value = res.total ?? audit.value.length
      return res
    } catch (e) {
      if (mine === auditSeq) {
        error.value = (e as Error).message
        auditError.value = e instanceof ApiError && e.reason === 'validation_failed' && e.detail?.param === 'from' ? AUDIT_SPAN_MESSAGE : error.value
      }
      return null
    } finally {
      if (mine === auditSeq) auditLoading.value = false
    }
  }

  async function generate(o: GeneratorOptions): Promise<string> {
    // Only the generator options: the API refuses unknown fields.
    const { length, lower, upper, digits, symbols } = o
    const out = await api<{ password: string }>('POST', 'generate', { length, lower, upper, digits, symbols })
    return out.password
  }

  return { stats, audit, auditTotal, auditLoading, error, auditError, loadStats, loadAudit, generate }
})
