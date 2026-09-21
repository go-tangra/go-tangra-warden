import { beforeEach, describe, expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import ShareDialog from '@/components/ShareDialog.vue'
import SharesPanel from '@/components/SharesPanel.vue'
import SecretDrawer from '@/components/SecretDrawer.vue'
import { useShares, type Share } from '@/stores/shares'
import { click, mountInLayout, secret, stubFetch, type, viewer } from './helpers'

const active: Share = { id: 'sh1', secret_id: 's1', recipient_email: 'friend@outside.test', max_opens: 1, opens: 0, expires_at: '2026-09-17T00:00:00Z', state: 'active', created_at: '2026-09-16T00:00:00Z' }
const consumed: Share = { ...active, id: 'sh2', opens: 1, state: 'consumed', cidr: '10.0.0.0/8' }

describe('shares store', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('lists, creates with policies and cancels; the token never appears', async () => {
    const calls: string[] = []
    stubFetch((url, init) => {
      calls.push((init?.method ?? 'GET') + ' ' + url + ' ' + (init?.body ?? ''))
      if (url === '/api/warden/v1/secrets/s1/shares' && init?.method === 'POST') return { status: 201, body: active }
      if (url === '/api/warden/v1/secrets/s1/shares') return { status: 200, body: { items: [active, consumed] } }
      if (url === '/api/warden/v1/shares/sh1/cancel') return { status: 204, body: null }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const s = useShares()
    await s.list('s1')
    expect(s.items.length).toBe(2)
    const created = await s.create('s1', { recipient_email: 'friend@outside.test', validity_seconds: 3600, max_opens: 1, cidr: '10.0.0.0/8' })
    expect(created.id).toBe('sh1')
    expect(JSON.stringify(created)).not.toContain('token')
    expect(calls.some((c) => c.startsWith('POST /api/warden/v1/secrets/s1/shares') && c.includes('"cidr":"10.0.0.0/8"'))).toBe(true)
    await s.cancel('s1', 'sh1')
    expect(calls.some((c) => c.includes('/shares/sh1/cancel'))).toBe(true)
    stubFetch(() => ({ status: 403, body: { reason: 'forbidden' } }))
    await s.list('s1')
    expect(s.items).toEqual([])
    expect(s.error).toBe('forbidden')
  })
})

describe('ShareDialog', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('validates the recipient and CIDR, sends the defaults and confirms without a link', async () => {
    const posted: Record<string, unknown>[] = []
    stubFetch((url, init) => {
      if (url === '/api/warden/v1/secrets/s1/shares' && init?.method === 'POST') {
        posted.push(JSON.parse(String(init.body)))
        return { status: 201, body: active }
      }
      return { status: 200, body: { items: [] } }
    })
    const w = mountInLayout(ShareDialog, { modelValue: true, secretId: 's1', secretName: 'db' })
    await flushPromises()
    const dialog = document.body.querySelector('[data-test="share-dialog"]')!
    expect((dialog.querySelector('[data-test="share-send"]') as HTMLButtonElement).disabled).toBe(true)
    type(dialog, '[data-test="share-email"]', 'friend@outside.test')
    type(dialog, '[data-test="share-cidr"]', 'not a cidr')
    await flushPromises()
    expect(dialog.textContent).toContain('CIDR notation')
    expect((dialog.querySelector('[data-test="share-send"]') as HTMLButtonElement).disabled).toBe(true)
    type(dialog, '[data-test="share-cidr"]', '203.0.113.0/24')
    type(dialog, '[data-test="share-message"]', 'for you')
    await flushPromises()
    click(dialog, '[data-test="share-send"]')
    await flushPromises()
    expect(posted[0]).toMatchObject({ recipient_email: 'friend@outside.test', validity_seconds: 3600, max_opens: 1, cidr: '203.0.113.0/24', message: 'for you' })
    expect(dialog.querySelector('[data-test="share-done"]')!.textContent).toContain('friend@outside.test')
    expect(dialog.textContent).not.toContain('/warden/share')
    w.unmount()
  })

  it('shows refusals', async () => {
    stubFetch((url, init) => (init?.method === 'POST' ? { status: 400, body: { reason: 'region_unavailable' } } : { status: 200, body: { items: [] } }))
    const w = mountInLayout(ShareDialog, { modelValue: true, secretId: 's1', secretName: 'db' })
    await flushPromises()
    const dialog = document.body.querySelector('[data-test="share-dialog"]')!
    type(dialog, '[data-test="share-email"]', 'a@b.co')
    await flushPromises()
    click(dialog, '[data-test="share-send"]')
    await flushPromises()
    expect(dialog.querySelector('[data-test="share-error"]')!.textContent).toContain('region_unavailable')
    w.unmount()
  })
})

describe('SharesPanel in the drawer', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('lists my shares with states and cancels active ones; hidden without share permission', async () => {
    const calls: string[] = []
    stubFetch((url, init) => {
      calls.push((init?.method ?? 'GET') + ' ' + url)
      if (url === '/api/warden/v1/secrets/s1/shares') return { status: 200, body: { items: [active, consumed] } }
      if (url === '/api/warden/v1/shares/sh1/cancel') return { status: 204, body: null }
      return { status: 200, body: { items: [] } }
    })
    const w = mountInLayout(SharesPanel, { secretId: 's1', secretName: 'db' })
    await flushPromises()
    expect(document.body.querySelector('[data-test="share-state-sh1"]')!.textContent).toBe('active')
    expect(document.body.querySelector('[data-test="share-state-sh2"]')!.textContent).toBe('consumed')
    expect(document.body.querySelector('[data-test="share-cancel-sh2"]')).toBeNull()
    click(document.body, '[data-test="share-cancel-sh1"]')
    await flushPromises()
    expect(calls.some((c) => c.includes('/shares/sh1/cancel'))).toBe(true)
    w.unmount()
    const d = mountInLayout(SecretDrawer, { modelValue: true, secret: secret('s1', 'db', { permissions: viewer }), folderId: null })
    await flushPromises()
    expect(document.body.querySelector('[data-test="shares-panel"]')).toBeNull()
    d.unmount()
    const d2 = mountInLayout(SecretDrawer, { modelValue: true, secret: secret('s1', 'db'), folderId: null })
    await flushPromises()
    expect(document.body.querySelector('[data-test="shares-panel"]')).not.toBeNull()
    d2.unmount()
  })
})
