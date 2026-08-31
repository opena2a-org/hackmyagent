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
    // Keeps the spawn tests off the developer's home directory. Without it a
    // scan of a two-file fixture inherits every finding in a populated
    // ~/.openclaw, which is what made five files red on main locally while CI
    // was green. Reasoning in vitest.setup.ts; contract pinned by
    // __tests__/harness/hermetic-home.test.ts.
    setupFiles: ['./vitest.setup.ts'],
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
    // inverted here.
    //
    // 60s was the previous cap, on the claim that a longer scan is broken
    // rather than slow. Measured false under full-suite parallelism
    // (2026-08-29): the suite packs ~5600s of test time into ~660s wall, and
    // scans that take 13-20s in isolation contend past 60s — three different
    // spawn-test files flaked at exactly 60000ms across three otherwise-green
    // full-suite runs on an idle machine. 180s covers a contended scan with
    // headroom while a genuinely hung unit test still fails in minutes, not
    // hours. A file whose own spawn budget meets or exceeds this cap carries
    // an explicit higher `{ timeout }` on its describe (secure-unread-input-
    // gate: spawn budget 240s, describe timeout 300s).
    // hookTimeout matches testTimeout for the same reason: several files run
    // their scan spawns in beforeAll (fix-marker-under-prefix timed out its
    // hook at exactly 60000ms in the run after testTimeout alone was raised).
    testTimeout: 180_000,
    hookTimeout: 180_000,
    // The OPENA2A_CORPUS_DETERMINISTIC default that used to sit here as
    // `env: { ... }` now lives in vitest.setup.ts, which sets it only when it is
    // unset. That conditional form is the reason it moved: a deliberate
    // `OPENA2A_CORPUS_DETERMINISTIC=0` has to survive to reach the infra-merge
    // path, and vitest's `env` block overrides the environment unconditionally,
    // which would have made the non-vacuity case in
    // __tests__/harness/hermetic-home.test.ts assert against a flag it could no
    // longer turn off. Do not reinstate it here.
  },
});
