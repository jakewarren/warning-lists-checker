// Imported from 'vitest/config', not 'vite' — the base defineConfig type does
// not accept the `test` key and would fail `tsc --noEmit`.
import { defineConfig } from 'vitest/config'

export default defineConfig({
  base: './',
  build: { target: 'es2022' },
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
})
