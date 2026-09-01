// Regression tests for HMA Registry-query key in the PyPI check path.
//
// Background: the Registry stores PyPI packages under their bare name
// (e.g. `anthropic`), not under a `pip:` / `pypi:` prefix. Until this
// PR, `checkPyPiPackage` called `queryRegistry(\`pip:${name}\`)`, which
// always missed for Registry-indexed PyPI packages. Combined with
// hackmyagent#197 (which honors --no-scan for pip:/pypi: targets), the
// CLI returned `found: false` for known packages like `anthropic` when
// run as `hma check pip:anthropic --no-scan --json`.
//
// Two layers, matching the pattern in check-not-found-json.test.ts:
//
// 1. Deterministic lock-in: read src/cli.ts and assert the PyPI path
//    calls queryRegistry with the bare name. Catches the exact
//    regression class deterministically on CI. (Lock-in tests are the
//    discipline from MEMORY's "ai pr reviewers hallucinate" entry —
//    future reviewers shouldn't re-add the prefix on a flawed reading
//    of "make pip: queries explicit.")
//
// 2. Spawned smoke test: invokes the built dist/cli.js against a
//    Registry-known PyPI package, asserts the JSON output reports
//    found:true. Needs network and a built dist, both of which release.yml
//    provides before it runs the suite.

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// #285 — this suite spawns the built CLI. Without this it would happily
// measure a binary older than `src/` and report a pass.
beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = join(__dirname, '..', '..');
const CLI_TS = join(REPO_ROOT, 'src', 'cli.ts');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');

function canRunSpawn(): boolean {
  return existsSync(CLI);
}

describe('PyPI Registry-query key (lock-in: closes pip-prefix bug)', () => {
  it('checkPyPiPackage queries Registry with bare name, not pip:-prefixed', () => {
    const src = readFileSync(CLI_TS, 'utf8');

    // Locate checkPyPiPackage. Its body owns the only queryRegistry call
    // in the PyPI path.
    const startIdx = src.indexOf('async function checkPyPiPackage');
    expect(startIdx, 'checkPyPiPackage function not found in src/cli.ts').toBeGreaterThan(-1);

    // Slice through the end of the function. The next top-level
    // `async function ` declaration marks the boundary.
    const afterStart = src.slice(startIdx + 'async function checkPyPiPackage'.length);
    const nextFnRel = afterStart.search(/\nasync function /);
    const body = nextFnRel === -1 ? afterStart : afterStart.slice(0, nextFnRel);

    // Forbidden: prefixed queries. These would route to a Registry key
    // that doesn't exist (Registry stores PyPI under bare names).
    expect(body, 'queryRegistry call must not use pip:${name} (Registry stores PyPI under bare name)').not.toMatch(/queryRegistry\(\s*`pip:\$\{/);
    expect(body, 'queryRegistry call must not use pypi:${name} either').not.toMatch(/queryRegistry\(\s*`pypi:\$\{/);

    // Required: at least one queryRegistry call passing bare `name`.
    expect(body, 'checkPyPiPackage must call queryRegistry(name) with the bare package name').toMatch(/queryRegistry\(\s*name\s*\)/);
  });
});

describe('PyPI Registry-query end-to-end (smoke, local-only)', () => {
  it.runIf(canRunSpawn())(
    'check pip:anthropic --no-scan returns Registry record (found:true)',
    () => {
      // Live-Registry test. `anthropic` is stably indexed in the
      // OpenA2A Registry under its bare PyPI name. Pre-fix this would
      // return found:false because HMA queried `pip:anthropic`, a key
      // the Registry doesn't store.
      const res = spawnSync(
        'node',
        [CLI, 'check', 'pip:anthropic', '--no-scan', '--json', '--ci'],
        { encoding: 'utf8', timeout: 10_000 },
      );

      // --no-scan + Registry hit = exit 0 (mirrors the npm path).
      expect(res.status, `unexpected exit ${res.status}; stderr: ${res.stderr}`).toBe(0);

      const stdout = (res.stdout || '').trim();
      expect(stdout.length).toBeGreaterThan(0);

      const parsed = JSON.parse(stdout);
      expect(parsed.found).toBe(true);
      expect(parsed.name).toBe('anthropic');
      // packageType for `anthropic` is `ai_tool` per the Registry's
      // canonical record. If this assertion ever flakes, treat as a
      // Registry-data drift signal rather than masking it with a
      // looser match.
      expect(parsed.packageType).toBe('ai_tool');
    },
  );
});
