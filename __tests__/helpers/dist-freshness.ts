/**
 * #285 process note — spawn suites gated on `existsSync(dist/cli.js)`, not on
 * freshness.
 *
 * During the 0.25.1 mutation pass `dist/` was stale for part of the work, so
 * roughly half the new coverage was passing against an older binary: the
 * tests exercised code that was no longer the code under review, and a
 * mutation applied to `src/` could not turn them red. A spawn test that runs
 * a stale binary is worse than no test, because it reports success.
 *
 * `assertDistFresh` fails loudly when any TypeScript source is newer than the
 * built CLI. It is deliberately a hard failure rather than a rebuild: a test
 * run should not silently mutate the tree it is measuring.
 */
import { existsSync, statSync, readdirSync } from 'node:fs';
import path from 'node:path';

const SRC = path.resolve(__dirname, '../../src');
const CLI = path.resolve(__dirname, '../../dist/cli.js');

function newestSourceMtime(dir: string): { mtime: number; file: string } {
  let newest = { mtime: 0, file: '' };
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      const nested = newestSourceMtime(full);
      if (nested.mtime > newest.mtime) newest = nested;
    } else if (entry.name.endsWith('.ts')) {
      const m = statSync(full).mtimeMs;
      if (m > newest.mtime) newest = { mtime: m, file: full };
    }
  }
  return newest;
}

/**
 * Throw unless `dist/cli.js` is at least as new as every file under `src/`.
 * Call this in `beforeAll` of any suite that spawns the built CLI.
 */
export function assertDistFresh(): void {
  if (!existsSync(CLI)) {
    throw new Error('dist/cli.js missing — run `npm run build` before this suite');
  }
  const built = statSync(CLI).mtimeMs;
  const newest = newestSourceMtime(SRC);
  if (newest.mtime > built) {
    const rel = path.relative(path.resolve(__dirname, '../..'), newest.file);
    throw new Error(
      `dist/cli.js is STALE — ${rel} is newer than the build.\n`
      + 'This suite spawns the built CLI, so it would have measured code that is no '
      + 'longer under test and reported a pass regardless.\n'
      + 'Run `npm run build` and re-run.',
    );
  }
}

export { CLI as BUILT_CLI };
