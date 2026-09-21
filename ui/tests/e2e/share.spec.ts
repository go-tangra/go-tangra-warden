import { expect, test } from '@playwright/test'
import { base, signIn } from './helpers'

// Creates a share, fetches the link from Mailpit (E2E_MAIL, default the
// gateway compose Mailpit at http://localhost:8025), opens it in a fresh
// context: the first reveal shows the password, the second is refused.
const password = process.env.E2E_OPERATOR_PASSWORD ?? ''
const email = process.env.E2E_OPERATOR_EMAIL ?? 'ops@example.org'
const mail = process.env.E2E_MAIL ?? 'http://localhost:8025'
const stamp = Date.now().toString(36)
const recipient = `friend-${stamp}@outside.test`
const marker = 'WARDEN-MARKER-PW-share-' + stamp

async function linkFromMail(): Promise<string> {
  const deadline = Date.now() + 20_000
  while (Date.now() < deadline) {
    const res = await fetch(mail + '/api/v1/search?query=' + encodeURIComponent('to:' + recipient))
    const list = (await res.json()) as { messages: { ID: string }[] }
    if (list.messages?.length) {
      const m = (await (await fetch(mail + '/api/v1/message/' + list.messages[0]!.ID)).json()) as { Text: string }
      const hit = /https:\/\/\S+\/warden\/share#[A-Za-z0-9_-]{43}/.exec(m.Text)
      if (hit) return hit[0]
    }
    await new Promise((r) => setTimeout(r, 500))
  }
  throw new Error('no share mail for ' + recipient)
}

test.describe.configure({ mode: 'serial' })

test.describe('warden external share', () => {
  test.skip(!password, 'E2E_OPERATOR_PASSWORD not set')

  test('shares a secret by email; the recipient reveals once', async ({ page, browser }) => {
    await signIn(page, email, password)
    await page.goto(base + '/warden')
    await expect(page.getByTestId('warden-secrets')).toBeVisible({ timeout: 15_000 })
    await page.getByTestId('folder-root').click()
    await page.getByTestId('new-secret').click()
    const drawer = page.getByTestId('secret-drawer')
    await drawer.getByTestId('secret-name').locator('input').fill('shared-' + stamp)
    await drawer.getByTestId('secret-password').locator('input').fill(marker)
    await drawer.getByTestId('secret-save').click()
    await expect(page.getByTestId('notice')).toContainText('Saved')
    await page.getByTestId('secret-row').filter({ hasText: 'shared-' + stamp }).click()
    await drawer.getByTestId('share-new').click()
    const dialog = page.getByTestId('share-dialog')
    await dialog.getByTestId('share-email').locator('input').fill(recipient)
    await dialog.getByTestId('share-send').click()
    await expect(dialog.getByTestId('share-done')).toContainText(recipient)
    await dialog.getByTestId('share-close').click()
    await expect(drawer.getByTestId('shares-panel')).toContainText(recipient)

    const link = await linkFromMail()
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true })
    const other = await ctx.newPage()
    await other.goto(link.replace(/^https:\/\/[^/]+/, base))
    await other.getByTestId('share-open').click()
    await expect(other.getByTestId('share-password')).toHaveText(marker)
    // The token was dropped from the address bar; a second open in a new page is refused.
    expect(other.url()).not.toContain('#')
    const again = await ctx.newPage()
    await again.goto(link.replace(/^https:\/\/[^/]+/, base))
    await again.getByTestId('share-open').click()
    await expect(again.getByTestId('share-error')).toBeVisible()
    await ctx.close()

    // The owner sees the share consumed and cleans up.
    await page.reload()
    await expect(page.getByTestId('warden-secrets')).toBeVisible({ timeout: 15_000 })
    await page.getByTestId('folder-root').click()
    await page.getByTestId('secret-row').filter({ hasText: 'shared-' + stamp }).click()
    await expect(drawer.getByTestId('shares-panel')).toContainText('consumed')
    await drawer.getByTestId('secret-delete').click()
    await page.getByTestId('confirm-delete-yes').click()
    await expect(page.getByTestId('notice')).toContainText('deleted')
  })
})
