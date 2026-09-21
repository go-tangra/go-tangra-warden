import { beforeEach, describe, expect, it } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import SecretsView from '@/views/secrets/index.vue'
import FolderTree from '@/components/FolderTree.vue'
import { useFolders } from '@/stores/folders'
import { click, folder, mountInLayout, node, plugins, stubFetch, type, viewer } from './helpers'

const infra = folder('f1', 'Infra', '/Infra')
const db = folder('f2', 'Databases', '/Infra/Databases', 'f1')
const shared = folder('f3', 'Shared', '/Shared', null, viewer)

describe('folders store', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('loads the tree, finds nodes, flattens and mutates through the API', async () => {
    const calls: string[] = []
    stubFetch((url, init) => {
      calls.push((init?.method ?? 'GET') + ' ' + url + ' ' + (init?.body ?? ''))
      if (url === '/api/warden/v1/folders/tree') return { status: 200, body: { items: [node(infra, [node(db)]), node(shared)] } }
      if (url === '/api/warden/v1/folders' && init?.method === 'POST') return { status: 201, body: folder('f4', 'New', '/New') }
      if (url === '/api/warden/v1/folders/f2' && init?.method === 'PUT') return { status: 200, body: { ...db, name: 'DBs' } }
      if (url === '/api/warden/v1/folders/f2/move') return { status: 200, body: { ...db, parent_id: null } }
      if (url === '/api/warden/v1/folders/f2/remove') return { status: 204, body: null }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const f = useFolders()
    await f.load()
    expect(f.tree.length).toBe(2)
    expect(f.find('f2')?.folder.name).toBe('Databases')
    expect(f.find('nope')).toBeUndefined()
    expect(f.flat().map((x) => x.depth)).toEqual([0, 1, 0])
    await f.create(null, 'New')
    await f.rename('f2', 'DBs')
    await f.move('f2', null)
    await f.remove('f2', true)
    expect(calls.some((c) => c.startsWith('POST /api/warden/v1/folders ') && c.includes('"name":"New"'))).toBe(true)
    expect(calls.some((c) => c.includes('/f2/remove') && c.includes('"recursive":true'))).toBe(true)
    // Failures land in error.
    stubFetch(() => ({ status: 503, body: { reason: 'temporarily_unavailable' } }))
    await f.load()
    expect(f.error).toBe('temporarily_unavailable')
  })
})

describe('FolderTree', () => {
  it('expands, selects and marks the root', async () => {
    const w = mount(FolderTree, { props: { nodes: [node(infra, [node(db)])], selected: null }, global: { plugins: plugins() } })
    expect(w.find('[data-test="folder-f2"]').exists()).toBe(false)
    await w.find('[data-test="folder-toggle-f1"]').trigger('click')
    expect(w.find('[data-test="folder-f2"]').exists()).toBe(true)
    await w.find('[data-test="folder-f2"]').trigger('click')
    expect(w.emitted('select')?.[0]).toEqual(['f2'])
    await w.find('[data-test="folder-root"]').trigger('click')
    expect(w.emitted('select')?.[1]).toEqual([null])
    expect(w.find('[aria-selected="true"]').exists()).toBe(true)
  })
})

describe('explorer folder management', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('creates under the selection, renames, moves and deletes with recursive confirmation', async () => {
    const calls: string[] = []
    stubFetch((url, init) => {
      calls.push((init?.method ?? 'GET') + ' ' + url + ' ' + (init?.body ?? ''))
      if (url === '/api/warden/v1/folders/tree') return { status: 200, body: { items: [node(infra, [node(db)]), node(shared)] } }
      if (url.startsWith('/api/warden/v1/secrets')) return { status: 200, body: { items: [], next: null } }
      if (url === '/api/warden/v1/folders' && init?.method === 'POST') return { status: 201, body: folder('f4', 'Prod', '/Infra/Prod', 'f1') }
      if (url === '/api/warden/v1/folders/f1' && init?.method === 'PUT') return { status: 409, body: { reason: 'conflict' } }
      if (url === '/api/warden/v1/folders/f1/move') return { status: 200, body: { ...infra, parent_id: 'f3' } }
      if (url === '/api/warden/v1/folders/f1/remove') return { status: 204, body: null }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountInLayout(SecretsView, {})
    await flushPromises()
    // The right pane lists the root's subfolders like a file manager.
    expect(w.findAll('[data-test="folder-row"]').length).toBe(2)
    await w.find('[data-test="folder-f1"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="current-path"]').text()).toBe('/Infra')
    expect(w.findAll('[data-test="folder-row"]').map((r) => r.text())).toEqual(['Databases0 secret(s)—'])
    // New folder under the selection.
    click(document.body, '[data-test="folder-new"]')
    await flushPromises()
    type(document.body, '[data-test="folder-name"]', 'Prod')
    await flushPromises()
    click(document.body, '[data-test="folder-create"]')
    await flushPromises()
    expect(calls.some((c) => c.startsWith('POST /api/warden/v1/folders ') && c.includes('"parent_id":"f1"') && c.includes('"name":"Prod"'))).toBe(true)
    expect(w.find('[data-test="notice"]').text()).toContain('created')
    // Rename conflicts surface as a folder error.
    await w.find('[data-test="folder-f1"]').trigger('click')
    await flushPromises()
    click(document.body, '[data-test="folder-rename"]')
    await flushPromises()
    type(document.body, '[data-test="folder-rename-name"]', 'Shared')
    await flushPromises()
    click(document.body, '[data-test="folder-rename-go"]')
    await flushPromises()
    expect(w.find('[data-test="folder-error"]').text()).toContain('sibling')
    // Move offers every folder outside the subtree.
    click(document.body, '[data-test="folder-move"]')
    await flushPromises()
    expect(document.body.querySelector('[data-test="folder-move-dialog"]')).not.toBeNull()
    click(document.body, '[data-test="folder-move-go"]')
    await flushPromises()
    expect(calls.some((c) => c.includes('/f1/move'))).toBe(true)
    // Delete with the recursive confirmation, then the parent is selected.
    click(document.body, '[data-test="folder-delete"]')
    await flushPromises()
    const dialog = document.body.querySelector('[data-test="confirm-folder-delete"]')!
    ;(dialog.querySelector('[data-test="folder-recursive"] input') as HTMLInputElement).click()
    click(dialog, '[data-test="confirm-folder-delete-yes"]')
    await flushPromises()
    expect(calls.some((c) => c.includes('/f1/remove') && c.includes('"recursive":true'))).toBe(true)
    expect(w.find('[data-test="current-path"]').text()).toBe('')
    // A viewer-only folder disables the write controls.
    await w.find('[data-test="folder-f3"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="folder-new"]').attributes('disabled')).toBeDefined()
    expect(w.find('[data-test="folder-delete"]').attributes('disabled')).toBeDefined()
    w.unmount()
  })

  it('hides folder management without the ability', async () => {
    stubFetch((url) => {
      if (url === '/api/warden/v1/folders/tree') return { status: 200, body: { items: [node(infra)] } }
      if (url.startsWith('/api/warden/v1/secrets')) return { status: 200, body: { items: [], next: null } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountInLayout(SecretsView, {}, [{ action: 'read', subject: 'Secret' }])
    await flushPromises()
    expect(w.find('[data-test="folder-actions"]').exists()).toBe(false)
    w.unmount()
  })
})
