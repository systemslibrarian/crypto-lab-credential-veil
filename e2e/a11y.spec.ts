import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']

// The age-predicate proofs run real pairings in the page — give them room.
test.setTimeout(360_000)

async function driveDemos(page: Page): Promise<void> {
  await page.addStyleTag({ content: `*,*::before,*::after{animation:none!important;transition:none!important}` })

  // wait for issuer setup to finish (buttons enable when ready)
  await expect(page.locator('#baseline-run')).toBeEnabled({ timeout: 60_000 })

  // exhibit 1 — baseline exposure
  await page.locator('#baseline-run').click()
  await expect(page.locator('#baseline-out .indicator-alarm')).toBeVisible({ timeout: 30_000 })

  // exhibit 2 — selective disclosure + full step-through + both break-it paths
  await page.locator('#sd-run').click()
  await expect(page.locator('#sd-out .result-pair')).toBeVisible({ timeout: 60_000 })
  for (let i = 0; i < 4; i++) {
    await page.locator('#sd-step').click()
    await expect(page.locator('#sd-steps li')).toHaveCount(i + 1, { timeout: 60_000 })
  }
  await page.locator('#sd-tamper').click()
  await expect(page.locator('#sd-break-out .result-pair')).toBeVisible({ timeout: 60_000 })
  await page.locator('#sd-honest').click()
  await expect(page.locator('#sd-break-out .indicator-ok')).toBeVisible({ timeout: 60_000 })

  // exhibit 3 — both unlinkability views (scan ends on the alarm baseline)
  await page.locator('#unlink-bbs').click()
  await expect(page.locator('#unlink-out .present-grid')).toBeVisible({ timeout: 120_000 })
  await page.locator('#unlink-ed').click()
  await expect(page.locator('#unlink-out .indicator-alarm')).toBeVisible({ timeout: 60_000 })

  // exhibit 4 — all three age-predicate paths (accept, refuse, forged reject)
  await page.locator('#age-adult').click()
  await expect(page.locator('#age-out .result-pair')).toBeVisible({ timeout: 180_000 })
  await page.locator('#age-minor').click()
  await expect(page.locator('#age-out .indicator-ok')).toBeVisible({ timeout: 60_000 })
  await page.locator('#age-forge').click()
  await expect(page.locator('#age-out .verifier-view')).toBeVisible({ timeout: 180_000 })

  // exhibit 5 — revoke, then verifier check (valid-proof + revoked-verdict pair)
  await page.locator('#revoke-toggle').click()
  await expect(page.locator('#revoke-out .bit-grid')).toBeVisible()
  await page.locator('#revoke-check').click()
  await expect(page.locator('#revoke-out .result-pair')).toBeVisible({ timeout: 120_000 })

  // open all progressive disclosure
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => {
      d.open = true
    })
  })
  await page.waitForTimeout(400)
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze()
  expect(
    violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    })),
  ).toEqual([])
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.')
  await driveDemos(page)
  await scan(page)
})

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.')
  await page.locator('#cl-theme-toggle').click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await driveDemos(page)
  await scan(page)
})
