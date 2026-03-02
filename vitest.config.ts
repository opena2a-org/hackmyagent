import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    include: ['src/**/*.test.ts', '__tests__/**/*.test.ts', '__tests__/**/*.ts'],
    testTimeout: 10000,
    hookTimeout: 10000,
  },
});
