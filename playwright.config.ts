import { defineConfig, devices } from '@playwright/test'

/**
 * E2E accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 * Run `npm run build` first (CI does).
 */
export default defineConfig({
  testDir: './e2e',
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4351/crypto-lab-credential-veil/',
    // Pin the emulated color scheme to dark so the default scan is dark and
    // the shared-header toggle deterministically moves to light.
    colorScheme: 'dark',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'npm run preview -- --port 4351 --strictPort',
    url: 'http://localhost:4351/crypto-lab-credential-veil/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})
