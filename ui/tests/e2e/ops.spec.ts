import { expect, test } from '@playwright/test'
import { base, signIn } from './helpers'

// Generator honours the options; statistics are visible to the operator
// (owner role) and the audit trail lists the operator's own actions.
const password = process.env.E2E_OPERATOR_PASSWORD ?? ''
const email = process.env.E2E_OPERATOR_EMAIL ?? 'ops@example.org'

test.describe('warden operations', () => {
  test.skip(!password, 'E2E_OPERATOR_PASSWORD not set')

  test('generates passwords and shows statistics and the audit trail', async ({ page }) => {
    await signIn(page, email, password)
    await page.goto(base + '/warden/generator')
    await expect(page.getByTestId('warden-generator')).toBeVisible({ timeout: 15_000 })
    await page.getByTestId('gen-symbols').locator('input').uncheck()
    await page.getByTestId('gen-go').click()
    const output = page.getByTestId('gen-output').locator('input')
    await expect(output).toHaveValue(/^[A-Za-z0-9]{20}$/)
    const value = await output.inputValue()
    await page.getByTestId('gen-source').locator('select').selectOption('local')
    await page.getByTestId('gen-go').click()
    await expect(output).toHaveValue(/^[A-Za-z0-9]{20}$/)
    await expect(output).not.toHaveValue(value)

    await page.goto(base + '/warden')
    await expect(page.getByTestId('stats-card')).toBeVisible({ timeout: 15_000 })
    await expect(page.getByTestId('stat-secrets')).toHaveText(/^\d+$/)
    await page.getByTestId('toggle-audit').click()
    await expect(page.getByTestId('audit-table')).toBeVisible()
    await expect(page.getByTestId('audit-row').first().or(page.getByText('No events'))).toBeVisible()
  })
})
