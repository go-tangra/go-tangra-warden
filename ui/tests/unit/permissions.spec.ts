import { beforeEach, describe, expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import PermissionsView from '@/views/permissions/index.vue'
import { grantable, usePermissions, type Grant } from '@/stores/permissions'
import { click, folder, mountInLayout, node, secret, stubFetch } from './helpers'

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

describe('permission drawer (kit + usePermissionGrants)', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('picks a user from the auth search, bounds the relation options and grants', async () => {
    const posted: Record<string, unknown>[] = []
    stubFetch((url, init) => {
      if (url === '/api/warden/v1/folders/tree') return { status: 200, body: { items: [node(infra)] } }
      if (url.startsWith('/api/warden/v1/secrets?')) return { status: 200, body: { items: [secret('s1', 'db', { folder_id: 'f1' })] } }
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
    const w = mountInLayout(PermissionsView, {})
    await flushPromises()
    click(document.body, '[data-test="manage-secret-s1"]')
    await flushPromises()
    const drawer = document.body.querySelector('[data-test="permission-drawer"]')!
    expect(drawer.textContent).toContain('Your relation: sharer')
    // Role slugs and user ids resolve to display names.
    expect(drawer.textContent).toContain('Role: Operations')
    expect(drawer.textContent).toContain('Bob')
    // Levels never exceed the holder's relation.
    expect(Array.from(drawer.querySelectorAll('#perm-level option')).map((o) => o.textContent)).toEqual(['viewer', 'sharer'])
    // Grant is disabled until a subject is picked.
    const grantBtn = () => Array.from(drawer.querySelectorAll('button')).find((b) => b.textContent?.trim() === 'Grant') as HTMLButtonElement
    expect(grantBtn().disabled).toBe(true)
    const subject = drawer.querySelector('#perm-subject') as HTMLInputElement
    subject.value = 'bo'
    subject.dispatchEvent(new Event('input'))
    await flushPromises()
    const option = Array.from(drawer.querySelectorAll('[role=option] button')).find((o) => o.textContent?.includes('Bob')) as HTMLElement
    expect(option).toBeTruthy()
    option.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }))
    await flushPromises()
    expect(grantBtn().disabled).toBe(false)
    grantBtn().click()
    await flushPromises()
    expect(posted[0]).toMatchObject({ resource_type: 'secret', resource_id: 's1', subject_type: 'user', subject_id: 'u2', relation: 'viewer' })
    w.unmount()
  })

  it('hides the grant form from viewers and lists nothing when grants are forbidden', async () => {
    stubFetch((url) => {
      if (url === '/api/warden/v1/folders/tree') return { status: 200, body: { items: [node(infra)] } }
      if (url.startsWith('/api/warden/v1/secrets?')) return { status: 200, body: { items: [secret('s1', 'db', { folder_id: 'f1' })] } }
      if (url.startsWith('/api/warden/v1/grants?')) return { status: 403, body: { reason: 'forbidden' } }
      if (url.startsWith('/api/warden/v1/access/effective')) return { status: 200, body: effectiveViewer }
      if (url === '/api/v1/roles') return { status: 200, body: [] }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountInLayout(PermissionsView, {})
    await flushPromises()
    click(document.body, '[data-test="manage-secret-s1"]')
    await flushPromises()
    const drawer = document.body.querySelector('[data-test="permission-drawer"]')!
    expect(drawer.textContent).toContain('share permission')
    expect(drawer.querySelector('#perm-subject')).toBeNull()
    expect(drawer.textContent).toContain('No grants')
    w.unmount()
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
    ;(Array.from(document.body.querySelectorAll('[role=treeitem]')).find((i) => i.textContent?.trim() === 'Infra') as HTMLElement).click()
    await flushPromises()
    expect(document.body.querySelector('[data-test="picked-path"]')!.textContent).toBe('/Infra')
    click(document.body, '[data-test="manage-secret-s1"]')
    await flushPromises()
    expect(document.body.querySelector('[data-test="permission-drawer"]')!.textContent).toContain('Access to db')
    w.unmount()
  })
})
