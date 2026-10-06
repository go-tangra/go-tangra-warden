import { expect, test } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { base, createRootFolder, deleteRootFolder, signIn } from './helpers'

// Runs against the full platform (gateway + auth + warden with its remote).
// Set E2E_BASE (default https://localhost:8443), E2E_OPERATOR_EMAIL and
// E2E_OPERATOR_PASSWORD; the operator must be bootstrapped (the helper enrols
// TOTP on the first sign-in). The owner role holds every warden permission.
const password = process.env.E2E_OPERATOR_PASSWORD ?? ''
const email = process.env.E2E_OPERATOR_EMAIL ?? 'ops@example.org'
const stamp = Date.now().toString(36)
const folderName = 'E2E ' + stamp
const secretName = 'db-' + stamp
const marker = 'WARDEN-MARKER-PW-e2e-' + stamp

test.describe.configure({ mode: 'serial' })

test.describe('warden secrets', () => {
  test.skip(!password, 'E2E_OPERATOR_PASSWORD not set')

  test('creates a folder and a secret, reveals, rotates, restores, moves and deletes', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (e) => errors.push('pageerror: ' + e.message))
    await signIn(page, email, password)
    await createRootFolder(page, folderName)
    // Accessibility of the explorer.
    const a11y = await new AxeBuilder({ page }).analyze()
    expect(a11y.violations.filter((v) => v.impact === 'critical')).toEqual([])

    await page.goto(base + '/warden')
    await expect(page.getByTestId('warden-secrets')).toBeVisible({ timeout: 15_000 })
    await page.getByRole('treeitem', { name: folderName, exact: true }).click()
    await expect(page.getByTestId('current-path')).toHaveText('/' + folderName)
    await page.getByTestId('new-secret').click()
    const drawer = page.getByTestId('secret-drawer')
    await drawer.locator('input[data-field=name]').fill(secretName)
    await drawer.locator('input[data-field=username]').fill('root')
    await drawer.locator('input[data-field=host_url]').fill('https://db.example.org')
    await drawer.locator('input[data-field=password]').fill(marker)
    await drawer.locator('input[data-field=totp]').fill('JBSWY3DPEHPK3PXP')
    await drawer.getByRole('button', { name: /^(Create|Save)$/ }).click()
    await expect(page.locator('.alert')).toContainText('Saved')
    // Creating opens the new secret's read-only view.
    const view = page.getByTestId('secret-view-drawer')
    await expect(view).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(page.getByTestId('secret-row')).toHaveCount(1)
    // The list never carries material.
    expect(await page.getByTestId('secret-row').textContent()).not.toContain(marker)

    // Open the view: reveal, TOTP code.
    await page.getByTestId('secret-row').click()
    await expect(view.getByTestId('revealed-password')).not.toHaveText(marker)
    await view.getByTestId('reveal').click()
    await expect(view.getByTestId('revealed-password')).toHaveText(marker)
    await view.getByTestId('totp-load').click()
    await expect(view.getByTestId('totp-code')).toHaveText(/^\d{6}$/)

    // Edit: rotate twice; back to the view: list versions, restore v1 → v4.
    await view.getByTestId('secret-edit').click()
    await expect(view).toBeHidden()
    await drawer.getByTestId('new-password').locator('input').fill(marker + '-2')
    await drawer.getByTestId('password-comment').locator('input').fill('rotated')
    await drawer.getByTestId('change-password').click()
    await expect(drawer.getByText('Password (version 2)')).toBeVisible()
    await drawer.getByTestId('new-password').locator('input').fill(marker + '-3')
    await drawer.getByTestId('change-password').click()
    await expect(drawer.getByText('Password (version 3)')).toBeVisible()
    await drawer.getByRole('button', { name: 'Close' }).click()
    await expect(view).toBeVisible()
    await view.getByTestId('open-versions').click()
    const versions = page.getByTestId('version-drawer')
    await expect(versions.getByTestId('version-3')).toBeVisible()
    await expect(versions.getByTestId('version-1')).toBeVisible()
    await versions.getByTestId('version-restore-1').click()
    await page.getByTestId('confirm-restore').getByTestId('restore-comment').locator('input').fill('back to v1')
    await page.getByTestId('confirm-restore-yes').click()
    await expect(page.locator('.alert')).toContainText('version 4')
    await versions.getByRole('button', { name: 'Close' }).click()
    await expect(view).toBeVisible()

    // Edit: move to the root (saving returns to the view); then delete from the view.
    await view.getByTestId('secret-edit').click()
    await drawer.locator('select[data-field=folder_id]').selectOption('')
    await drawer.getByRole('button', { name: /^(Create|Save)$/ }).click()
    await expect(page.locator('.alert')).toContainText('Saved')
    await expect(view).toBeVisible()
    await page.keyboard.press('Escape')
    await page.getByRole('treeitem', { name: 'Root' }).click()
    await expect(page.getByTestId('secret-row').filter({ hasText: secretName })).toHaveCount(1)
    await page.getByTestId('secret-row').filter({ hasText: secretName }).click()
    await view.getByTestId('secret-delete').click()
    await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click()
    await expect(page.locator('.alert')).toContainText('deleted')
    await expect(page.getByTestId('secret-row').filter({ hasText: secretName })).toHaveCount(0)

    // Clean up the folder; no browser errors during the flow.
    await deleteRootFolder(page, folderName)
    expect(errors).toEqual([])
  })
})
