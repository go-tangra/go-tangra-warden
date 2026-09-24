import { expect, test, type Page } from '@playwright/test'
import { base, signIn } from './helpers'

// Quickstart §4 flow for the warden remote at the three reference widths:
// folder tree, secret drawer (reveal never persists), share dialog validation,
// Bitwarden import parser negatives, generator. Needs a full platform; skips
// without operator credentials.
const password = process.env.E2E_OPERATOR_PASSWORD ?? ''
const email = process.env.E2E_OPERATOR_EMAIL ?? 'ops@example.org'
const viewports = [{ name: 'phone', width: 320, height: 640 }, { name: 'tablet', width: 768, height: 1024 }, { name: 'desktop', width: 1280, height: 800 }]

async function openNav(page: Page, group: string, entry: string): Promise<void> {
  const burger = page.getByRole('button', { name: 'Open navigation' })
  if (await burger.isVisible()) await burger.click()
  const g = page.getByTestId('nav-group-' + group)
  if ((await g.getAttribute('aria-expanded')) !== 'true') await g.click()
  await page.getByTestId('nav-' + group).filter({ hasText: entry }).first().click()
}

test.describe('warden remote', () => {
  test.skip(!password, 'E2E_OPERATOR_PASSWORD not set')
  for (const vp of viewports) {
    test(`${vp.name}: tree, secret drawer, share validation, import parser, generator`, async ({ page }) => {
      await page.setViewportSize({ width: vp.width, height: vp.height })
      const violations: string[] = []
      await page.addInitScript(() => document.addEventListener('securitypolicyviolation', (e) => console.error('CSP:' + (e as SecurityPolicyViolationEvent).violatedDirective)))
      page.on('console', (m) => { if (m.text().startsWith('CSP:')) violations.push(m.text()) })
      await page.goto(base + '/')
      await signIn(page, email, password)
      await openNav(page, 'warden', 'Secrets')
      await expect(page.getByTestId('warden-secrets')).toBeVisible()
      await expect(page.getByRole('treeitem', { name: 'Root' })).toBeVisible()
      // Create a secret; the password field is masked and never written to storage.
      const marker = 'WARDEN-E2E-' + vp.name + '-' + Date.now().toString(36)
      await page.getByTestId('new-secret').click()
      const drawer = page.getByTestId('secret-drawer')
      await drawer.getByRole('button', { name: 'Create' }).click()
      await expect(drawer.getByRole('alert').first()).toContainText('required')
      await drawer.locator('input[data-field=name]').fill('e2e ' + marker)
      const pwd = drawer.locator('input[data-field=password]')
      await expect(pwd).toHaveAttribute('type', 'password')
      await pwd.fill(marker)
      await drawer.getByRole('button', { name: 'Create' }).click()
      await expect(page.locator('.alert')).toContainText('Saved')
      await page.getByTestId('secret-row').filter({ hasText: marker }).first().click()
      await drawer.getByTestId('reveal').click()
      await expect(drawer.getByTestId('revealed-password').locator('input')).toHaveValue(marker)
      expect(await page.evaluate(() => JSON.stringify([Object.keys(localStorage), Object.keys(sessionStorage)]))).not.toContain(marker)
      // Share dialog refuses a bad recipient and CIDR client-side.
      await drawer.getByTestId('share-new').click()
      const dialog = page.getByTestId('share-dialog')
      await dialog.locator('input[data-field=recipient_email]').fill('nope')
      await dialog.locator('input[data-field=cidr]').fill('not a cidr')
      await dialog.getByTestId('share-send').click()
      await expect(dialog.getByRole('alert').first()).toBeVisible()
      await dialog.getByTestId('share-close').click()
      await page.keyboard.press('Escape')
      // Bitwarden import: an encrypted export is refused before any request.
      await page.getByTestId('more-actions').locator('button').first().click()
      const importItem = page.getByRole('menuitem', { name: 'Import from Bitwarden' })
      if (await importItem.isVisible()) {
        await importItem.click()
        const imp = page.getByTestId('import-dialog')
        await imp.locator('input[type=file]').setInputFiles({ name: 'enc.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify({ encrypted: true, items: [] })) })
        await imp.getByTestId('import-validate').click()
        await expect(imp).toContainText('Encrypted exports')
        await imp.getByTestId('import-close').click()
      } else await page.keyboard.press('Escape')
      // Generator
      await openNav(page, 'warden', 'Generator')
      await page.getByTestId('gen-go').click()
      await expect(page.getByTestId('gen-output').locator('input')).not.toHaveValue('')
      expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0)
      expect(await page.locator('main [style]').count()).toBe(0)
      expect(await page.content()).not.toContain(marker + '"') // no marker in inline state
      expect(violations).toEqual([])
    })
  }
})
