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
    // `secure` merges findings from AI infrastructure it auto-detects under the
    // user's HOME (`~/.openclaw`, `~/.nemoclaw`, `~/.openshell`) into the scan of
    // the requested directory. Every suite that scans a temporary fixture — and
    // 23 of them spawn the real CLI — therefore has a finding count, a score and
    // an output SIZE that depend on the machine it runs on rather than on the
    // fixture.
    //
    // Measured, with no source change: 250 SKILL.md files appeared under a real
    // `~/.openclaw` and seven suites went from green to red in one morning. One
    // of them died on truncated JSON, because the fixture's `--json` output had
    // grown to 1.36MB and passed `execFileSync`'s 1MB default buffer.
    //
    // This is the flag `secure` already documents for the case ("a developer's
    // real ~/.nemoclaw / ~/.openclaw cannot leak machine state into fixture
    // scores"), set in one place rather than in each suite that noticed. Any
    // suite that wants to exercise the infrastructure merge must set it back to
    // '0' for its own spawn — there is no such suite today.
    env: { OPENA2A_CORPUS_DETERMINISTIC: '1' },
  },
});
