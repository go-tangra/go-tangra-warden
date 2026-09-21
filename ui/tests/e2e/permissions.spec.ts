import { expect, test } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { base, createRootFolder, deleteRootFolder, signIn } from './helpers'

// Grants Viewer on a folder to a role through the permissions page, verifies
// the grant is listed with its source, then revokes it. A second browser
// context (the same operator, whose access does not depend on the grant)
// checks the effective view; a dedicated member would need a second account,
// which the platform bootstrap does not provide.
const password = process.env.E2E_OPERATOR_PASSWORD ?? ''
const email = process.env.E2E_OPERATOR_EMAIL ?? 'ops@example.org'
const stamp = Date.now().toString(36)
const folderName = 'Shared ' + stamp

test.describe.configure({ mode: 'serial' })

test.describe('warden permissions', () => {
  test.skip(!password, 'E2E_OPERATOR_PASSWORD not set')

  test('grants viewer to a role on a folder, shows the effective view elsewhere, then revokes', async ({ page, browser }) => {
    await signIn(page, email, password)
    await createRootFolder(page, folderName)

    await page.goto(base + '/warden/permissions')
    await expect(page.getByTestId('warden-permissions')).toBeVisible({ timeout: 15_000 })
    await page.getByRole('button', { name: folderName, exact: true }).click()
    await page.getByTestId('manage-folder').click()
    const drawer = page.getByTestId('permission-drawer')
    await expect(drawer.getByTestId('effective-summary')).toContainText('owner')
    await drawer.getByTestId('subject-role').click()
    await drawer.getByTestId('role-select').click()
    await page.getByRole('option', { name: /operator/i }).click()
    await drawer.getByTestId('relation-select').click()
    await page.getByRole('option', { name: 'viewer' }).click()
    await drawer.getByTestId('grant-save').click()
    await expect(drawer.getByText('Role operator').first()).toBeVisible()
    const a11y = await new AxeBuilder({ page }).analyze()
    expect(a11y.violations.filter((v) => v.impact === 'critical')).toEqual([])

    // A second browser sees the grant in the effective view of the same folder.
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true })
    const other = await ctx.newPage()
    await signIn(other, email, password)
    await other.goto(base + '/warden/permissions')
    await other.getByRole('button', { name: folderName, exact: true }).click()
    await other.getByTestId('manage-folder').click()
    await expect(other.getByTestId('permission-drawer').getByText('Role operator').first()).toBeVisible()
    await ctx.close()

    // Revoke and clean up.
    const row = drawer.locator('tr', { hasText: 'Role operator' })
    await row.getByRole('button', { name: 'Revoke' }).click()
    await expect(drawer.locator('tr', { hasText: 'Role operator' })).toHaveCount(0)
    await drawer.getByTestId('permissions-close').click()
    await deleteRootFolder(page, folderName)
  })
})
