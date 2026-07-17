import { defineConfig, devices } from '@playwright/test'

/**
 * E2E accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 * Run `npm run build` first (CI does).
 */
export default defineConfig({
  testDir: './e2e',
  forbidOnly: !!process.env.CI,
  // One retry everywhere: rare browser-level wedges under sustained multi-
  // browser crypto load (a renderer starved mid-drive) are environment flakes,
  // not app regressions — the page itself self-heals (see src/worker/client.ts).
  retries: 1,
  // One worker, always: each test drives multi-second pairing math in the
  // page, and two such pages in parallel can starve/crash a browser renderer
  // (observed with webkit+firefox concurrently). Serial is slower but stable.
  workers: 1,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4351/crypto-lab-credential-veil/',
    // Pin the emulated color scheme to dark so the default scan is dark and
    // the shared-header toggle deterministically moves to light.
    colorScheme: 'dark',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
    // Mobile viewport: same engine as chromium, but exercises the collapsed
    // header, touch targets, and narrow-layout contrast under the axe scan.
    { name: 'mobile-chrome', use: { ...devices['Pixel 7'] } },
  ],
  webServer: {
    command: 'npm run preview -- --port 4351 --strictPort',
    url: 'http://localhost:4351/crypto-lab-credential-veil/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})
