// Config for the nested run in __tests__/harness/collection-starts-no-scan.test.ts.
// The fixture lives under __tests__/helpers/, which the main config excludes,
// so it only ever runs through this file.
import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  root: fileURLToPath(new URL('../../..', import.meta.url)),
  test: {
    globals: false,
    environment: 'node',
    include: ['__tests__/helpers/collection-fixture/*.fixture.ts'],
  },
});
