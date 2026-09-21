import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import BitwardenImportDialog from '@/components/BitwardenImportDialog.vue'
import SecretsView from '@/views/secrets/index.vue'
import { useTransfer } from '@/stores/transfer'
import { downloadJSON, readFile } from '@/api/download'
import { click, mountInLayout, stubFetch } from './helpers'

const validated = { folders: 3, items: 20, created: 0, renamed: 0, skipped: 2, overwritten: 0, failed: 0, collisions: [{ name: 'Service 000', folder: '/Imported/Team 0' }, { name: 'Service 001', folder: '/Imported/Team 1' }], problems: [{ index: 21, reason: 'missing password' }], warnings: ['item 20: type 2 is not a login; skipped'] }
const done = { ...validated, created: 18, renamed: 2 }
const sample = JSON.stringify({ encrypted: false, folders: [], items: [{ type: 1, name: 'x', login: { password: 'p' } }] })

async function pickFile(root: ParentNode, text: string, name = 'export.json'): Promise<void> {
  const input = root.querySelector('[data-test="import-file"] input[type="file"]') as HTMLInputElement
  const file = new File([text], name, { type: 'application/json' })
  Object.defineProperty(input, 'files', { value: [file], configurable: true })
  input.dispatchEvent(new Event('change'))
  // FileReader completes on the event loop, not the microtask queue.
  await new Promise((r) => setTimeout(r, 20))
  await flushPromises()
}

describe('transfer store and download helper', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('validates, imports with a strategy and imports backups through the API', async () => {
    const calls: string[] = []
    stubFetch((url, init) => {
      calls.push((init?.method ?? 'GET') + ' ' + url)
      if (url.startsWith('/api/warden/v1/transfer/bitwarden/validate')) return { status: 200, body: validated }
      if (url.startsWith('/api/warden/v1/transfer/bitwarden/import')) return { status: 200, body: done }
      if (url === '/api/warden/v1/backup/import') return { status: 200, body: { folders: { created: 1, skipped: 0, failed: 0 }, secrets: { created: 1, skipped: 0, failed: 0 }, versions: { created: 1, skipped: 0, failed: 0 }, grants: { created: 0, skipped: 0, failed: 0 }, warnings: [] } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const t = useTransfer()
    expect((await t.validate(sample, 'f1')).items).toBe(20)
    expect(calls[0]).toContain('folder_id=f1')
    expect((await t.importBitwarden(sample, null, 'rename')).renamed).toBe(2)
    expect(calls[1]).toContain('duplicates=rename')
    expect(calls[1]).not.toContain('folder_id')
    expect((await t.importBackup(JSON.stringify({ module: 'warden' }))).secrets.created).toBe(1)
    expect(t.busy).toBe(false)
  })

  it('downloads exports as files and refuses oversized picks', async () => {
    const created: string[] = []
    const origCreate = URL.createObjectURL
    URL.createObjectURL = vi.fn(() => 'blob:x')
    URL.revokeObjectURL = vi.fn()
    const origClick = HTMLAnchorElement.prototype.click
    HTMLAnchorElement.prototype.click = function () { created.push(this.download) }
    stubFetch((url) => (url.includes('export') ? { status: 200, body: { encrypted: false, items: [] } } : { status: 403, body: { reason: 'forbidden' } }))
    expect(await downloadJSON('/api/warden/v1/transfer/bitwarden/export', 'x.json')).toBeGreaterThan(0)
    expect(created).toEqual(['x.json'])
    await expect(downloadJSON('/api/warden/v1/backup/other', 'y.json')).rejects.toMatchObject({ reason: 'forbidden' })
    HTMLAnchorElement.prototype.click = origClick
    URL.createObjectURL = origCreate
    await expect(readFile(new File(['{}'], 'a.json'), 1)).rejects.toMatchObject({ reason: 'body_too_large' })
    expect(await readFile(new File(['{}'], 'a.json'))).toBe('{}')
  })
})

describe('BitwardenImportDialog', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('walks pick → validate (counts, collisions, problems) → strategy → import report', async () => {
    const calls: string[] = []
    stubFetch((url, init) => {
      calls.push((init?.method ?? 'GET') + ' ' + url)
      if (url === '/api/warden/v1/folders/tree') return { status: 200, body: { items: [] } }
      if (url.startsWith('/api/warden/v1/transfer/bitwarden/validate')) return { status: 200, body: validated }
      if (url.startsWith('/api/warden/v1/transfer/bitwarden/import')) return { status: 200, body: done }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const imported: unknown[] = []
    const w = mountInLayout(BitwardenImportDialog, { modelValue: true, folderId: 'f1', onImported: (r: unknown) => imported.push(r) })
    await flushPromises()
    const dialog = document.body.querySelector('[data-test="import-dialog"]')!
    expect((dialog.querySelector('[data-test="import-validate"]') as HTMLButtonElement).disabled).toBe(true)
    await pickFile(dialog, 'not json')
    expect(dialog.querySelector('[data-test="import-error"]')!.textContent).toContain('not valid JSON')
    await pickFile(dialog, sample)
    expect((dialog.querySelector('[data-test="import-validate"]') as HTMLButtonElement).disabled).toBe(false)
    click(dialog, '[data-test="import-validate"]')
    await flushPromises()
    expect(calls.some((c) => c.includes('validate?folder_id=f1'))).toBe(true)
    expect(dialog.querySelector('[data-test="count-items"]')!.textContent).toBe('20')
    expect(dialog.querySelector('[data-test="count-collisions"]')!.textContent).toBe('2')
    expect(dialog.querySelector('[data-test="collision-list"]')!.textContent).toContain('Service 000')
    expect(dialog.querySelector('[data-test="problem-list"]')!.textContent).toContain('missing password')
    ;(dialog.querySelector('[data-test="strategy-skip"] input') as HTMLInputElement).click()
    await flushPromises()
    click(dialog, '[data-test="import-go"]')
    await flushPromises()
    expect(calls.some((c) => c.includes('duplicates=skip'))).toBe(true)
    expect(dialog.querySelector('[data-test="import-result"]')!.textContent).toContain('18 created, 2 renamed')
    expect(imported.length).toBe(1)
    w.unmount()
  })

  it('shows refusals from the server', async () => {
    stubFetch((url) => (url === '/api/warden/v1/folders/tree' ? { status: 200, body: { items: [] } } : { status: 403, body: { reason: 'forbidden' } }))
    const w = mountInLayout(BitwardenImportDialog, { modelValue: true, folderId: null })
    await flushPromises()
    const dialog = document.body.querySelector('[data-test="import-dialog"]')!
    await pickFile(dialog, sample)
    click(dialog, '[data-test="import-validate"]')
    await flushPromises()
    expect(dialog.querySelector('[data-test="import-error"]')!.textContent).toContain('not allowed')
    w.unmount()
  })
})

describe('secrets view transfer actions', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('gates import, export and backup on abilities', async () => {
    stubFetch(() => ({ status: 200, body: { items: [] } }))
    const w = mountInLayout(SecretsView, {}, [{ action: 'read', subject: 'Secret' }, { action: 'export', subject: 'Transfer' }])
    await flushPromises()
    click(document.body, '[data-test="more-actions"]')
    await flushPromises()
    expect(document.body.querySelector('[data-test="action-export"]')).not.toBeNull()
    expect(document.body.querySelector('[data-test="action-import"]')).toBeNull()
    expect(document.body.querySelector('[data-test="action-backup"]')).toBeNull()
    w.unmount()
    const w2 = mountInLayout(SecretsView, {}, [{ action: 'read', subject: 'Secret' }])
    await flushPromises()
    expect(document.body.querySelector('[data-test="more-actions"]')).toBeNull()
    w2.unmount()
  })
})
