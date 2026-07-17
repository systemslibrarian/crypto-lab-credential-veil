import { defineConfig } from 'vitest/config'

export default defineConfig({
  base: '/crypto-lab-credential-veil/',
  test: {
    include: ['src/**/*.test.ts'],
  },
})
