import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    include: ['src/**/*.test.ts', '__tests__/**/*.test.ts', '__tests__/**/*.ts'],
    // `__tests__/**/*.ts` sweeps in every file under `__tests__`, including
    // shared test infrastructure, which vitest then fails as "No test suite
    // found in file". Helpers are not test files.
    //
    // Spread the defaults rather than replacing them: assigning `exclude`
    // drops vitest's own list (node_modules, dist, .idea, .git, .cache), and
    // dropping the `dist` entry would hand the runner the compiled copy of
    // every suite alongside the source.
    exclude: [...configDefaults.exclude, '__tests__/helpers/**'],
    // 23 test files spawn `dist/cli.js` and run a real scan. A full scan of
    // the kitchen-sink corpus fixture takes a few seconds idle and comfortably
    // over ten under parallel load, so a 10s cap made every one of them a
    // load-sensitive flake — reproduced twice under CPU contention, on
    // `opena2a-citation-and-next-steps-target` and on the pre-existing
    // `check-skill-quick-scan-label`, both timing out at exactly 10000ms.
    //
    // The cap has to sit ABOVE the inner `spawnSync` budget, not below it:
    // `spawnSync` blocks the event loop, so vitest cannot interrupt one. A cap
    // under the spawn budget still waits out the whole spawn and only then
    // reports an unhelpful "Test timed out", which is how the layering was
    // inverted here. 60s covers the spawn tests with several times the
    // headroom they need — a CLI scan that runs longer than that is broken,
    // not slow — while staying tight enough that a genuinely hung unit test
    // still fails quickly. The handful of files whose own spawn budgets
    // exceed 60s carry an explicit higher `{ timeout }` on their describe.
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
