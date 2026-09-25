import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import GeneratorView from '@/views/generator/index.vue'
import SecretsView from '@/views/secrets/index.vue'
import { generateLocal, satisfies, useOps } from '@/stores/ops'
import { click, mountInLayout, stubFetch, type } from './helpers'

const stats = { secrets: 12, secrets_with_totp: 3, folders: 4, versions: 20, grants: { owner: 5, viewer: 2 }, shares: {}, operations_24h: 77 }
const events = [
  { ts: '2026-09-16T10:00:00Z', event_type: 'secret_password_read', actor_kind: 'user', actor_id: 'u1', subject_kind: 'secret', subject_id: 's1', subject_name: 'DB admin', outcome: 'ok', details: { version: 2 } },
  { ts: '2026-09-16T09:00:00Z', event_type: 'access_refused', actor_kind: 'user', actor_id: 'u2', subject_kind: 'secret', subject_id: 's1', outcome: 'refused', reason: 'no_write', details: {} },
]

describe('local generator', () => {
  it('matches the server rules: bounds, classes, uniform alphabet', () => {
    for (const o of [
      { length: 20, lower: true, upper: true, digits: true, symbols: true },
      { length: 8, lower: false, upper: false, digits: true, symbols: false },
      { length: 128, lower: true, upper: false, digits: false, symbols: true },
    ]) {
      const p = generateLocal(o)
      expect(satisfies(p, o)).toBe(true)
    }
    expect(() => generateLocal({ length: 4, lower: true, upper: false, digits: false, symbols: false })).toThrow()
    expect(() => generateLocal({ length: 20, lower: false, upper: false, digits: false, symbols: false })).toThrow()
    expect(satisfies('abc12345', { length: 8, lower: true, upper: false, digits: true, symbols: false })).toBe(true)
    expect(satisfies('abcdefgh', { length: 8, lower: true, upper: false, digits: true, symbols: false })).toBe(false)
    expect(satisfies('abc1234!', { length: 8, lower: true, upper: false, digits: true, symbols: false })).toBe(false)
    const seen = new Set<string>()
    for (let i = 0; i < 20; i++) seen.add(generateLocal({ length: 16, lower: true, upper: true, digits: true, symbols: true }))
    expect(seen.size).toBe(20)
  })
})

describe('generator view', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('generates through the service, validates options and copies', async () => {
    const bodies: unknown[] = []
    stubFetch((url, init) => {
      if (url === '/api/warden/v1/generate') {
        bodies.push(JSON.parse(String(init?.body)))
        return { status: 200, body: { password: 'Srv3rP@ssw0rd!xyz123', length: 20 } }
      }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const written: string[] = []
    Object.assign(navigator, { clipboard: { writeText: vi.fn(async (s: string) => { written.push(s) }) } })
    const w = mountInLayout(GeneratorView, {})
    await flushPromises()
    click(document.body, '[data-test="gen-go"]')
    await flushPromises()
    // Exactly the fields POST /generate accepts (additionalProperties: false);
    // the form's own `source` choice must not be sent.
    expect(bodies[0]).toEqual({ length: 20, lower: true, upper: true, digits: true, symbols: true })
    expect((document.body.querySelector('[data-test="gen-output"] input') as HTMLInputElement).value).toBe('Srv3rP@ssw0rd!xyz123')
    click(document.body, '[data-test="gen-copy"]')
    await flushPromises()
    expect(written).toEqual(['Srv3rP@ssw0rd!xyz123'])
    // No class → inline error, no request.
    const toggle = (k: string, on: boolean) => { const el = document.body.querySelector(`[data-test="gen-${k}"] input`) as HTMLInputElement; el.checked = on; el.dispatchEvent(new Event('change')) }
    for (const k of ['lower', 'upper', 'digits', 'symbols']) toggle(k, false)
    await flushPromises()
    click(document.body, '[data-test="gen-go"]')
    await flushPromises()
    expect(document.body.querySelector('[role=alert]')!.textContent).toContain('at least one')
    expect(bodies.length).toBe(1)
    // Local source never calls the service.
    toggle('lower', true)
    const src = document.body.querySelector('[data-test="gen-source"] select') as HTMLSelectElement
    src.value = 'local'
    src.dispatchEvent(new Event('change'))
    await flushPromises()
    click(document.body, '[data-test="gen-go"]')
    await flushPromises()
    expect(bodies.length).toBe(1)
    expect((document.body.querySelector('[data-test="gen-output"] input') as HTMLInputElement).value).toMatch(/^[a-z]{20}$/)
    w.unmount()
  })

  it('shows service refusals', async () => {
    stubFetch(() => ({ status: 403, body: { reason: 'forbidden' } }))
    const w = mountInLayout(GeneratorView, {})
    await flushPromises()
    click(document.body, '[data-test="gen-go"]')
    await flushPromises()
    expect(document.body.querySelector('[role=alert]')!.textContent).toContain('not allowed')
    w.unmount()
  })
})

describe('stats card and audit table', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('renders statistics and filters the audit trail', async () => {
    const calls: string[] = []
    const looked: string[][] = []
    stubFetch((url, init) => {
      calls.push(url)
      if (url === '/api/warden/v1/stats') return { status: 200, body: stats }
      if (url === '/api/v1/users/lookup') {
        looked.push((JSON.parse(String(init?.body)) as { ids: string[] }).ids)
        return { status: 200, body: { items: [{ id: 'u1', display_name: 'Alice' }] } }
      }
      if (url.startsWith('/api/warden/v1/audit')) {
        if (url.includes('event_type=access_refused')) return { status: 200, body: { items: [events[1]] } }
        if (url.includes('cursor=c1')) return { status: 200, body: { items: [events[1]] } }
        return { status: 200, body: { items: [events[0]], next_cursor: 'c1' } }
      }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const a = mountInLayout(SecretsView, {})
    await flushPromises()
    expect(document.body.querySelector('[data-test="stat-secrets"]')!.textContent).toContain('12')
    expect(document.body.textContent).toContain('owner 5')
    click(document.body, '[data-test="toggle-audit"]')
    await flushPromises()
    expect(document.body.querySelectorAll('[data-test="audit-row"]').length).toBe(1)
    expect(document.body.textContent).toContain('secret_password_read')
    expect(document.body.textContent).not.toContain('version')
    // Actors resolve to display names through one batch lookup; subjects show the resolved name.
    expect(looked).toEqual([['u1']])
    expect(document.body.querySelector('[data-test="audit-row"]')!.textContent).toContain('Alice')
    expect(document.body.querySelector('[data-test="audit-row"]')!.textContent).toContain('secret DB admin')
    ;(Array.from(document.body.querySelectorAll('button')).find((b) => b.textContent?.trim() === 'Load more') as HTMLButtonElement).click()
    await flushPromises()
    expect(document.body.querySelectorAll('[data-test="audit-row"]').length).toBe(2)
    // Only new ids are looked up; unknown ones stay as ids.
    expect(looked).toEqual([['u1'], ['u2']])
    expect(document.body.querySelectorAll('[data-test="audit-row"]')[1]!.textContent).toContain('u2')
    type(document.body, '[data-test="audit-type"]', 'access_refused')
    await flushPromises()
    click(document.body, '[data-test="audit-apply"]')
    await flushPromises()
    expect(calls.some((c) => c.includes('event_type=access_refused'))).toBe(true)
    expect(document.body.querySelectorAll('[data-test="audit-row"]').length).toBe(1)
    expect(document.body.textContent).toContain('refused (no_write)')
    a.unmount()
    // Store errors are surfaced.
    stubFetch(() => ({ status: 503, body: { reason: 'temporarily_unavailable' } }))
    const ops = useOps()
    await ops.loadStats()
    expect(ops.error).toBe('temporarily_unavailable')
    await ops.loadAudit({})
    expect(ops.error).toBe('temporarily_unavailable')
  })
})
