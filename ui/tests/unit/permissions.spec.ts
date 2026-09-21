import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import PermissionDrawer from '@/components/PermissionDrawer.vue'
import PermissionsView from '@/views/permissions/index.vue'
import { grantable, usePermissions, type Grant } from '@/stores/permissions'
import { click, folder, mountInLayout, node, secret, stubFetch, type } from './helpers'

const infra = folder('f1', 'Infra', '/Infra')
const g1: Grant = { id: 'g1', resource_type: 'folder', resource_id: 'f1', subject_type: 'role', subject_id: 'ops', relation: 'viewer', granted_at: '2026-09-16T00:00:00Z', inherited: true, expired: false }
const g2: Grant = { id: 'g2', resource_type: 'secret', resource_id: 's1', subject_type: 'user', subject_id: 'u2', relation: 'editor', granted_at: '2026-09-16T00:00:00Z', expires_at: '2020-01-01T00:00:00Z', inherited: false, expired: true }
const effectiveOwner = { permissions: { read: true, write: true, delete: true, share: true }, relation: 'owner', grants: [{ grant_id: 'g0', resource_type: 'secret', resource_id: 's1', subject_type: 'user', subject_id: 'u1', relation: 'owner', inherited: false }] }
const effectiveSharer = { permissions: { read: true, write: false, delete: false, share: true }, relation: 'sharer', grants: [{ grant_id: 'g3', resource_type: 'folder', resource_id: 'f1', subject_type: 'role', subject_id: 'ops', relation: 'sharer', inherited: true }] }
const effectiveViewer = { permissions: { read: true, write: false, delete: false, share: false }, relation: 'viewer', grants: [] }

describe('permissions store', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('bounds grantable relations by the held relation', () => {
    expect(grantable('owner')).toEqual(['viewer', 'sharer', 'editor', 'owner'])
    expect(grantable('sharer')).toEqual(['viewer', 'sharer'])
    expect(grantable('viewer')).toEqual(['viewer'])
    expect(grantable('')).toEqual([])
  })

  it('loads grants and effective permissions, grants, revokes and searches subjects', async () => {
    const calls: string[] = []
    stubFetch((url, init) => {
      calls.push((init?.method ?? 'GET') + ' ' + url + ' ' + (init?.body ?? ''))
      if (url.startsWith('/api/warden/v1/grants?')) return { status: 200, body: { items: [g1, g2] } }
      if (url.startsWith('/api/warden/v1/access/effective')) return { status: 200, body: effectiveOwner }
      if (url === '/api/warden/v1/grants' && init?.method === 'POST') return { status: 201, body: { ...g1, id: 'g9' } }
      if (url === '/api/warden/v1/grants/g2/revoke') return { status: 204, body: null }
      if (url.startsWith('/api/v1/users?q=')) return { status: 200, body: { items: [{ id: 'u2', display_name: 'Bob', email: 'bob@x.test' }] } }
      if (url === '/api/v1/roles') return { status: 200, body: [{ slug: 'ops', display_name: 'Ops' }] }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const p = usePermissions()
    await p.load('secret', 's1')
    expect(p.grants.length).toBe(2)
    expect(p.effective?.relation).toBe('owner')
    await p.grant({ resource_type: 'secret', resource_id: 's1', subject_type: 'role', subject_id: 'ops', relation: 'viewer' })
    expect(calls.some((c) => c.startsWith('POST /api/warden/v1/grants ') && c.includes('"subject_id":"ops"'))).toBe(true)
    await p.revoke(g2, 'secret', 's1')
    expect(calls.some((c) => c.includes('/grants/g2/revoke'))).toBe(true)
    expect((await p.searchUsers('bo'))[0]?.email).toBe('bob@x.test')
    expect(await p.searchUsers('b')).toEqual([])
    expect((await p.roles())[0]?.slug).toBe('ops')
  })

  it('treats a forbidden grant listing as empty (viewers may still see their effective access)', async () => {
    stubFetch((url) => {
      if (url.startsWith('/api/warden/v1/grants?')) return { status: 403, body: { reason: 'forbidden' } }
      if (url.startsWith('/api/warden/v1/access/effective')) return { status: 200, body: effectiveViewer }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const p = usePermissions()
    await p.load('secret', 's1')
    expect(p.grants).toEqual([])
    expect(p.effective?.relation).toBe('viewer')
    expect(p.error).toBe('')
    stubFetch(() => ({ status: 503, body: { reason: 'temporarily_unavailable' } }))
    await p.load('secret', 's1')
    expect(p.error).toBe('temporarily_unavailable')
  })
})

describe('PermissionDrawer', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.useFakeTimers()
  })

  it('picks a user from the auth search, bounds the relation options and grants', async () => {
    const posted: Record<string, unknown>[] = []
    stubFetch((url, init) => {
      if (url.startsWith('/api/warden/v1/grants?')) return { status: 200, body: { items: [g1, g2] } }
      if (url.startsWith('/api/warden/v1/access/effective')) return { status: 200, body: effectiveSharer }
      if (url === '/api/warden/v1/grants' && init?.method === 'POST') {
        posted.push(JSON.parse(String(init.body)))
        return { status: 201, body: { ...g1, id: 'g9' } }
      }
      if (url.startsWith('/api/v1/users?q=')) return { status: 200, body: { items: [{ id: 'u2', display_name: 'Bob', email: 'bob@x.test' }] } }
      if (url === '/api/v1/users/lookup') return { status: 200, body: { items: [{ id: 'u2', display_name: 'Bob' }] } }
      if (url === '/api/v1/roles') return { status: 200, body: [{ slug: 'ops', display_name: 'Operations' }] }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const changed: number[] = []
    const w = mountInLayout(PermissionDrawer, { modelValue: true, resourceType: 'secret', resourceId: 's1', resourceName: 'db', onChanged: () => changed.push(1) })
    await flushPromises()
    const drawer = document.body.querySelector('[data-test="permission-drawer"]')!
    expect(drawer.querySelector('[data-test="effective-summary"]')!.textContent).toContain('sharer')
    expect(drawer.querySelector('[data-test="effective-sources"]')!.textContent).toContain('inherited')
    // Role slugs resolve to their display name.
    expect(drawer.querySelector('[data-test="effective-sources"]')!.textContent).toContain('Role Operations')
    expect(drawer.querySelector('[data-test="grant-g1"]')!.textContent).toContain('Role Operations')
    expect(drawer.querySelector('[data-test="grant-g2"]')!.textContent).toContain('User Bob')
    // Grant is disabled until a subject is picked.
    expect((drawer.querySelector('[data-test="grant-save"]') as HTMLButtonElement).disabled).toBe(true)
    type(drawer, '[data-test="user-query"]', 'bo')
    await flushPromises()
    vi.advanceTimersByTime(200)
    await flushPromises()
    click(drawer, '[data-test="user-hit-u2"]')
    await flushPromises()
    expect(drawer.querySelector('[data-test="user-picked"]')!.textContent).toContain('Bob')
    expect((drawer.querySelector('[data-test="grant-save"]') as HTMLButtonElement).disabled).toBe(false)
    click(drawer, '[data-test="grant-save"]')
    await flushPromises()
    expect(posted[0]).toMatchObject({ resource_type: 'secret', resource_id: 's1', subject_type: 'user', subject_id: 'u2', relation: 'viewer', expires_at: null })
    expect(changed.length).toBe(1)
    w.unmount()
  })

  it('offers only revoke-free views to viewers and refuses past expiry', async () => {
    stubFetch((url) => {
      if (url.startsWith('/api/warden/v1/grants?')) return { status: 403, body: { reason: 'forbidden' } }
      if (url.startsWith('/api/warden/v1/access/effective')) return { status: 200, body: effectiveViewer }
      if (url === '/api/v1/roles') return { status: 200, body: [] }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountInLayout(PermissionDrawer, { modelValue: true, resourceType: 'folder', resourceId: 'f1', resourceName: '/Infra' })
    await flushPromises()
    const drawer = document.body.querySelector('[data-test="permission-drawer"]')!
    expect(drawer.querySelector('[data-test="no-share"]')).not.toBeNull()
    expect(drawer.querySelector('[data-test="grant-save"]')).toBeNull()
    expect(drawer.querySelector('[data-test="no-grants"]')).not.toBeNull()
    w.unmount()
    // A sharer with a past expiry gets an inline error.
    stubFetch((url) => {
      if (url.startsWith('/api/warden/v1/grants?')) return { status: 200, body: { items: [] } }
      if (url.startsWith('/api/warden/v1/access/effective')) return { status: 200, body: effectiveOwner }
      if (url === '/api/v1/roles') return { status: 200, body: [{ slug: 'ops', display_name: 'Ops' }] }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w2 = mountInLayout(PermissionDrawer, { modelValue: true, resourceType: 'folder', resourceId: 'f1', resourceName: '/Infra' })
    await flushPromises()
    const d2 = document.body.querySelector('[data-test="permission-drawer"]')!
    click(d2, '[data-test="subject-tenant"]')
    type(d2, '[data-test="expires"]', '2000-01-01T00:00')
    await flushPromises()
    expect(d2.textContent).toContain('Expiry must be in the future')
    expect((d2.querySelector('[data-test="grant-save"]') as HTMLButtonElement).disabled).toBe(true)
    w2.unmount()
  })
})

describe('permissions view', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('lists secrets with permissions and opens the drawer for a folder or a secret', async () => {
    stubFetch((url) => {
      if (url === '/api/warden/v1/folders/tree') return { status: 200, body: { items: [node(infra)] } }
      if (url.startsWith('/api/warden/v1/secrets?')) return { status: 200, body: { items: [secret('s1', 'db', { folder_id: 'f1' })] } }
      if (url.startsWith('/api/warden/v1/grants?')) return { status: 200, body: { items: [] } }
      if (url.startsWith('/api/warden/v1/access/effective')) return { status: 200, body: effectiveOwner }
      if (url === '/api/v1/roles') return { status: 200, body: [] }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountInLayout(PermissionsView, {})
    await flushPromises()
    expect(document.body.querySelector('[data-test="manage-folder"]')).toBeNull()
    click(document.body, '[data-test="folder-f1"]')
    await flushPromises()
    expect(document.body.querySelector('[data-test="picked-path"]')!.textContent).toBe('/Infra')
    click(document.body, '[data-test="manage-secret-s1"]')
    await flushPromises()
    expect(document.body.querySelector('[data-test="permission-drawer"]')!.textContent).toContain('Access to db')
    w.unmount()
  })
})
