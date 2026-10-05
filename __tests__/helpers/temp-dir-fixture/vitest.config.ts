// Config for the nested run in __tests__/harness/temp-dir-cleanup.test.ts. The
// fixture lives under __tests__/helpers/, which the main config excludes, so it
// only ever runs through this file. It keeps the main setup file because that
// is where the file-level removal pass is registered.
import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  root: fileURLToPath(new URL('../../..', import.meta.url)),
  test: {
    globals: false,
    environment: 'node',
    include: ['__tests__/helpers/temp-dir-fixture/*.fixture.ts'],
    setupFiles: ['./vitest.setup.ts'],
  },
});
