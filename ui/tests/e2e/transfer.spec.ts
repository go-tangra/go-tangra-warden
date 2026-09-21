import { expect, test } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { base, createRootFolder, deleteRootFolder, signIn } from './helpers'

// Validates and imports the sample Bitwarden fixture with "rename" through
// the dialog, then exports the folder to a downloaded file.
const password = process.env.E2E_OPERATOR_PASSWORD ?? ''
const email = process.env.E2E_OPERATOR_EMAIL ?? 'ops@example.org'
const stamp = Date.now().toString(36)
const folderName = 'Import ' + stamp
const sample = join(dirname(fileURLToPath(import.meta.url)), '../../../tests/testdata/bitwarden/sample.json')

test.describe.configure({ mode: 'serial' })

test.describe('warden transfer', () => {
  test.skip(!password, 'E2E_OPERATOR_PASSWORD not set')

  test('validates and imports the sample with rename, then exports a file', async ({ page }) => {
    await signIn(page, email, password)
    await createRootFolder(page, folderName)

    await page.goto(base + '/warden')
    await expect(page.getByTestId('warden-secrets')).toBeVisible({ timeout: 15_000 })
    await page.getByRole('button', { name: folderName, exact: true }).click()
    await page.getByTestId('more-actions').click()
    await page.getByTestId('action-import').click()
    const dialog = page.getByTestId('import-dialog')
    await dialog.getByTestId('import-file').locator('input[type="file"]').setInputFiles(sample)
    await dialog.getByTestId('import-validate').click()
    await expect(dialog.getByTestId('count-items')).toHaveText('20')
    await expect(dialog.getByTestId('count-collisions')).toHaveText('0')
    await dialog.getByTestId('strategy-rename').locator('input').check()
    await dialog.getByTestId('import-go').click()
    await expect(dialog.getByTestId('import-result')).toContainText('20 created')
    await dialog.getByTestId('import-close').click()
    await expect(page.getByTestId('notice')).toContainText('Imported')
    // The imported folders appear in the tree; the list shows the secrets after expanding.
    await page.getByRole('button', { name: 'Expand ' + folderName }).click()
    const subtree = page.locator('li', { has: page.getByRole('button', { name: folderName, exact: true }) })
    await subtree.getByRole('button', { name: 'Imported', exact: true }).click()
    await subtree.getByRole('button', { name: 'Expand Imported' }).click()
    await subtree.getByRole('button', { name: 'Team 0', exact: true }).click()
    await expect(page.getByTestId('secret-row').first()).toBeVisible()
    expect(await page.getByTestId('secret-row').count()).toBeGreaterThan(0)

    // Export the folder: a JSON file with the imported logins downloads.
    await page.getByRole('button', { name: folderName, exact: true }).click()
    const download = page.waitForEvent('download')
    await page.getByTestId('more-actions').click()
    await page.getByTestId('action-export').click()
    const file = await download
    const path = await file.path()
    const exported = JSON.parse(readFileSync(path!, 'utf8')) as { items: unknown[] }
    expect(exported.items.length).toBe(20)
    await expect(page.getByTestId('notice')).toContainText('Export downloaded')

    // Clean up recursively.
    await deleteRootFolder(page, folderName, true)
  })
})
