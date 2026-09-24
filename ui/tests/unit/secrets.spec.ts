import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import SecretsView from '@/views/secrets/index.vue'
import SecretDetails from '@/components/SecretDetails.vue'
import VersionDrawer from '@/components/VersionDrawer.vue'
import { useSecrets } from '@/stores/secrets'
import { ApiError, describe as describeError } from '@/api/client'
import { click, folder, mountInLayout, node, secret, stubFetch, type, viewer } from './helpers'
import { secretCreateSchema, secretUpdateSchema } from '@/schemas'

const infra = folder('f1', 'Infra', '/Infra')
const db = secret('s1', 'prod-db', { folder_id: 'f1', folder_path: '/Infra', has_totp: true })

describe('secrets store', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('lists, searches, pages and never asks for material in listings', async () => {
    const fetch = stubFetch((url) => {
      if (url.startsWith('/api/warden/v1/secrets/search')) return { status: 200, body: { items: [db], next: '1' } }
      if (url.startsWith('/api/warden/v1/secrets?')) return { status: 200, body: { items: [db, secret('s2', 'other')], next: url.includes('cursor') ? undefined : 'c1' } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const s = useSecrets()
    await s.list(null)
    expect(s.items.length).toBe(2)
    expect(String(fetch.mock.calls[0]?.[0])).toContain('root=true')
    await s.more()
    expect(s.items.length).toBe(4)
    expect(s.next).toBeUndefined()
    await s.search('prod')
    expect(s.items.length).toBe(1)
    expect(s.query).toBe('prod')
    await s.search('   ')
    expect(s.query).toBe('')
    for (const call of fetch.mock.calls) expect(String(call[0])).not.toContain('password')
  })

  it('creates, reveals, changes the password, lists versions and restores', async () => {
    const calls: Array<[string, string]> = []
    stubFetch((url, init) => {
      calls.push([init?.method ?? 'GET', url])
      if (url === '/api/warden/v1/secrets' && init?.method === 'POST') return { status: 201, body: db }
      if (url.startsWith('/api/warden/v1/secrets/s1/password') && init?.method === 'GET') return { status: 200, body: { password: 'WARDEN-MARKER-PW-ui', version: url.includes('version=1') ? 1 : 2 } }
      if (url === '/api/warden/v1/secrets/s1/password' && init?.method === 'PUT') return { status: 200, body: { version: 2 } }
      if (url === '/api/warden/v1/secrets/s1/versions') return { status: 200, body: { items: [{ version: 2, comment: 'rotated', checksum: 'c', source: 'api', material_missing: false, created_at: '2026-09-16T00:00:00Z', current: true }] } }
      if (url === '/api/warden/v1/secrets/s1/versions/1/restore') return { status: 200, body: { version: 3 } }
      if (url === '/api/warden/v1/secrets/s1/remove') return { status: 204, body: null }
      if (url === '/api/warden/v1/secrets/s1/totp' && init?.method === 'GET') return { status: 200, body: { code: '123456', period: 30, expires_in: 12 } }
      if (url.startsWith('/api/warden/v1/secrets?')) return { status: 200, body: { items: [db] } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const s = useSecrets()
    const created = await s.create({ name: 'prod-db', password: 'WARDEN-MARKER-PW-ui' })
    expect(created.id).toBe('s1')
    expect(calls.some((c) => c[0] === 'POST' && c[1] === '/api/warden/v1/secrets')).toBe(true)
    const m = await s.reveal('s1')
    expect(m.password).toBe('WARDEN-MARKER-PW-ui')
    expect((await s.reveal('s1', 1)).version).toBe(1)
    expect(await s.changePassword('s1', 'new', 'rotated')).toBe(2)
    expect((await s.versions('s1'))[0]?.current).toBe(true)
    expect(await s.restore('s1', 1, 'back')).toBe(3)
    expect((await s.totp('s1')).code).toBe('123456')
    await s.remove('s1')
    expect(s.items.find((i) => i.id === 's1')).toBeUndefined()
  })

  it('surfaces closed-vocabulary reasons', async () => {
    stubFetch(() => ({ status: 503, body: { reason: 'vault_unavailable' } }))
    const s = useSecrets()
    await expect(s.reveal('s1')).rejects.toBeInstanceOf(ApiError)
    expect(describeError(new ApiError(503, 'vault_unavailable'))).toContain('vault')
    expect(describeError(new ApiError(403, 'forbidden'))).toContain('not allowed')
    expect(describeError(new ApiError(409, 'conflict'))).toContain('sibling')
    expect(describeError(new ApiError(400, 'validation_failed'))).toContain('fields')
    expect(describeError(new ApiError(429, 'rate_limited'))).toContain('Too many')
    expect(describeError(new ApiError(0, 'network'))).toContain('could not be reached')
    expect(describeError(new ApiError(418, 'teapot'))).toContain('Something') // unknown reasons are never echoed
    expect(describeError(new Error('x'))).toContain('Something')
    await s.list(null)
    expect(s.error).toBe('vault_unavailable')
  })
})

describe('secrets view', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('renders the tree and the list, opens the drawer and hides the password until revealed', async () => {
    stubFetch((url) => {
      if (url === '/api/warden/v1/folders/tree') return { status: 200, body: { items: [node(infra)] } }
      if (url.startsWith('/api/warden/v1/secrets?')) return { status: 200, body: { items: url.includes('folder_id=f1') ? [db] : [] } }
      if (url === '/api/warden/v1/secrets/s1/password') return { status: 200, body: { password: 'WARDEN-MARKER-PW-ui', version: 1 } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountInLayout(SecretsView, {})
    await flushPromises()
    // The root lists its subfolder as a row; no secrets means no "empty" marker while folders show.
    expect(w.findAll('[data-test="folder-row"]').length).toBe(1)
    expect(w.find('[data-test="empty"]').exists()).toBe(false)
    await w.findAll('[role=treeitem]')[1]!.trigger('click') // Infra under the synthetic root
    await flushPromises()
    expect(w.findAll('[data-test="secret-row"]').length).toBe(1)
    expect(w.findAll('[data-test="folder-row"]').length).toBe(0)
    expect(w.find('[data-test="current-path"]').text()).toContain('Infra')
    await w.find('[data-test="secret-row"]').trigger('click')
    await flushPromises()
    const drawer = document.body.querySelector('aside[role=dialog]')!
    expect(drawer.textContent).not.toContain('WARDEN-MARKER')
    const field = drawer.querySelector('[data-test="revealed-password"] input') as HTMLInputElement
    expect(field.type).toBe('password')
    click(drawer, '[data-test="reveal"]')
    await flushPromises()
    expect((drawer.querySelector('[data-test="revealed-password"] input') as HTMLInputElement).value).toBe('WARDEN-MARKER-PW-ui')
    // Nothing revealed is persisted anywhere in the browser.
    expect(localStorage.length).toBe(0)
    expect(sessionStorage.length).toBe(0)
    // New secret button appears for a writable folder.
    expect(w.find('[data-test="new-secret"]').exists()).toBe(true)
    w.unmount()
  })

  it('hides creation without the ability', async () => {
    stubFetch(() => ({ status: 200, body: { items: [] } }))
    const w = mountInLayout(SecretsView, {}, [{ action: 'read', subject: 'Secret' }])
    await flushPromises()
    expect(w.find('[data-test="new-secret"]').exists()).toBe(false)
    w.unmount()
  })
})

describe('secret create/edit (schema + drawer)', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('the create schema needs a name and a password, refuses bad metadata JSON; the edit schema has no password', () => {
    expect(secretCreateSchema.safeParse({ name: ' new one ', password: '' }).success).toBe(false)
    expect(secretCreateSchema.safeParse({ name: 'x', password: 'p', metadata: 'not json' }).success).toBe(false)
    expect(secretCreateSchema.parse({ name: ' new one ', password: 'WARDEN-MARKER-PW-ui', folder_id: 'f1', metadata: '{"env":"prod"}' })).toEqual({ name: 'new one', password: 'WARDEN-MARKER-PW-ui', folder_id: 'f1', metadata: { env: 'prod' } })
    expect(secretCreateSchema.safeParse({ name: 'x', password: 'p', totp: 'not a seed!' }).success).toBe(false)
    expect('password' in secretUpdateSchema.shape).toBe(false)
  })

  it('creates with the password from the drawer (blocked until valid) and never echoes it', async () => {
    const posted: unknown[] = []
    stubFetch((url, init) => {
      if (url === '/api/warden/v1/secrets' && init?.method === 'POST') {
        posted.push(JSON.parse(String(init.body)))
        return { status: 201, body: secret('s9', 'new one') }
      }
      if (url === '/api/warden/v1/folders/tree') return { status: 200, body: { items: [node(infra)] } }
      return { status: 200, body: { items: [] } }
    })
    const w = mountInLayout(SecretsView, {})
    await flushPromises()
    await w.find('[data-test="new-secret"]').trigger('click')
    await flushPromises()
    const drawer = document.body.querySelector('aside[role=dialog]')!
    const save = () => (Array.from(drawer.querySelectorAll('button')).find((b) => b.textContent?.trim() === 'Create') as HTMLButtonElement).click()
    save()
    await flushPromises()
    expect(posted.length).toBe(0)
    const set = (sel: string, v: string) => { const el = drawer.querySelector<HTMLInputElement>(sel)!; el.value = v; el.dispatchEvent(new Event('input')) }
    set('input[data-field="name"]', ' new one ')
    set('input[data-field="password"]', 'WARDEN-MARKER-PW-ui')
    set('textarea[data-field="metadata"]', 'not json')
    await flushPromises()
    save()
    await flushPromises()
    expect(posted.length).toBe(0)
    expect(drawer.textContent).toContain('valid JSON')
    set('textarea[data-field="metadata"]', '{"env":"prod"}')
    await flushPromises()
    save()
    await flushPromises()
    expect(posted.length).toBe(1)
    expect(posted[0]).toMatchObject({ name: 'new one', password: 'WARDEN-MARKER-PW-ui', metadata: { env: 'prod' } })
    expect((drawer.querySelector('input[data-field="password"]') as HTMLInputElement).type).toBe('password')
    w.unmount()
  })

  it('shows the TOTP code with a countdown and lets viewers only read', async () => {
    vi.useFakeTimers()
    stubFetch((url) => {
      if (url === '/api/warden/v1/secrets/s1/totp') return { status: 200, body: { code: '654321', period: 30, expires_in: 2 } }
      if (url === '/api/warden/v1/secrets/s1/password') return { status: 200, body: { password: 'x', version: 1 } }
      return { status: 200, body: { items: [] } }
    })
    const ro = { ...db, permissions: viewer }
    const w = mountInLayout(SecretDetails, { secret: ro })
    await flushPromises()
    const panel = w.element as HTMLElement
    expect(panel.querySelector('[data-test="change-password"]')).toBeNull()
    expect(panel.querySelector('[data-test="shares-panel"]')).toBeNull()
    click(panel, '[data-test="totp-load"]')
    await flushPromises()
    expect(panel.querySelector('[data-test="totp-code"]')!.textContent).toBe('654321')
    expect(panel.querySelector('[data-test="totp-expires"]')!.textContent).toBe('2s')
    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(panel.querySelector('[data-test="totp-expires"]')!.textContent).toBe('1s')
    w.unmount()
    vi.useRealTimers()
  })

  it('reports vault outages from reveal', async () => {
    stubFetch(() => ({ status: 503, body: { reason: 'vault_unavailable' } }))
    const w = mountInLayout(SecretDetails, { secret: db })
    await flushPromises()
    click(w.element as HTMLElement, '[data-test="reveal"]')
    await flushPromises()
    expect(w.find('[data-test="drawer-error"]').text()).toContain('vault')
    w.unmount()
  })
})

describe('VersionDrawer', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('lists versions, shows one on demand and restores after confirmation', async () => {
    const restored: string[] = []
    stubFetch((url, init) => {
      if (url === '/api/warden/v1/secrets/s1/versions') return { status: 200, body: { items: [
        { version: 2, comment: 'rotated', checksum: 'c', source: 'api', material_missing: false, created_at: '2026-09-16T00:00:00Z', current: true },
        { version: 1, comment: '', checksum: 'c', source: 'create', material_missing: false, created_at: '2026-09-15T00:00:00Z', current: false },
      ] } }
      if (url === '/api/warden/v1/secrets/s1/password?version=1') return { status: 200, body: { password: 'old-one', version: 1 } }
      if (url === '/api/warden/v1/secrets/s1/versions/1/restore') {
        restored.push(String(init?.body))
        return { status: 200, body: { version: 3 } }
      }
      return { status: 200, body: { items: [] } }
    })
    const restoredTo: number[] = []
    const w = mountInLayout(VersionDrawer, { modelValue: true, secret: db, onRestored: (v: number) => restoredTo.push(v) })
    await flushPromises()
    const drawer = document.body.querySelector('[data-test="version-drawer"]')!
    expect(drawer.querySelectorAll('[data-test^="version-"]').length).toBeGreaterThanOrEqual(2)
    expect(drawer.querySelector('[data-test="version-current"]')).not.toBeNull()
    expect(drawer.textContent).not.toContain('old-one')
    click(drawer, '[data-test="version-show-1"]')
    await flushPromises()
    expect(drawer.querySelector('[data-test="version-password-1"]')!.textContent).toBe('old-one')
    click(drawer, '[data-test="version-restore-1"]')
    await flushPromises()
    const dialog = document.body.querySelector('[data-test="confirm-restore"]')!
    type(dialog, '[data-test="restore-comment"]', 'back')
    click(dialog, '[data-test="confirm-restore-yes"]')
    await flushPromises()
    expect(restored.length).toBe(1)
    expect(restored[0]).toContain('back')
    expect(restoredTo).toEqual([3])
    w.unmount()
  })
})
