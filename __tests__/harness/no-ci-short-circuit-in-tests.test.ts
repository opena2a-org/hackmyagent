/**
 * HMA-18 — no suite may gate itself on "am I running in CI?".
 *
 * Twelve files under `__tests__/` carried a helper of the shape
 *
 *     if (<the CI variable> === 'true' || <the GitHub Actions variable> === 'true')
 *       return false;
 *
 * so the helper reported "cannot run" on a runner and the spawn-class
 * assertions it guarded never executed. The stated reason was that those tests
 * need a built `dist/`. `.github/workflows/release.yml` runs `npm ci`,
 * `npm run build`, `npm test` in that order, so the artifact IS present in the
 * publish job: the short-circuit removed the assertions at exactly the moment a
 * version is published, and a green `npm test` in that job meant strictly less
 * than it appeared to.
 *
 * WHY THIS TEST IS SPELLED THE WAY IT IS
 *
 *   The pattern is assembled at runtime from fragments rather than written out
 *   as a literal. This file is scanned by its own first case — the sweep is
 *   over every file under `__tests__/`, with no self-exclusion, because an
 *   exclusion list is the first place a re-introduction would hide. Writing the
 *   forbidden text literally here would make the gate fail on itself.
 *
 *   The second case is the "deleted, not relocated" half. Removing the CI
 *   clause is only correct if each helper's REMAINING precondition survives
 *   untouched — a helper that lost `existsSync(CLI)` along with the clause
 *   would spawn a CLI that is not there and fail for the wrong reason. The
 *   preconditions are authored here, deliberately, not derived from the files
 *   under test.
 *
 *   The third case pins the number of declaration sites per file, measured at
 *   base commit a598f61. Deleting a gate and deleting the tests it gated both
 *   drive the skipped count to zero; only this case tells them apart.
 */

import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const REPO_ROOT = join(__dirname, '..', '..');
const TESTS_ROOT = join(REPO_ROOT, '__tests__');

/**
 * `process` `.env.` `CI` / `GITHUB_ACTIONS`, assembled so this file does not
 * contain the text it forbids. Mirrors the contract's grep:
 * `process\.env\.(CI\b|GITHUB_ACTIONS)`.
 */
const ENV_READ = ['process', 'env', ''].join('\\.');
const CI_SHORT_CIRCUIT = new RegExp(`${ENV_READ}(CI\\b|GITHUB_ACTIONS)`);

/** Every file under `__tests__/`, at any depth. No exclusions but the obvious. */
function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules') continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

/**
 * The precondition each helper is left holding once the CI clause is gone.
 * A file that no longer contains its row has had more removed than the
 * short-circuit.
 */
const REMAINING_PRECONDITION: ReadonlyArray<readonly [string, string]> = [
  ['__tests__/checker/check-not-found-json.test.ts', 'return existsSync(CLI);'],
  ['__tests__/checker/check-pip-prefix-registry-query.test.ts', 'return existsSync(CLI);'],
  ['__tests__/checker/check-secure-cross-analyzer-parity.test.ts', 'return existsSync(CLI);'],
  ['__tests__/cli/check-skill-quick-scan-label.test.ts', 'existsSync(CLI) && existsSync(FIXTURE)'],
  ['__tests__/cli/opena2a-citation-and-next-steps-target.test.ts', 'return existsSync(CLI);'],
  ['__tests__/cli/output-hygiene.test.ts', 'return existsSync(CLI);'],
  ['__tests__/hardening/credential-scan-source-extensions.test.ts', 'existsSync(CLI)'],
  ['__tests__/hardening/rollback-created-files.test.ts', 'return existsSync(CLI);'],
  ['__tests__/oasb/e2e/E2E-003.live-network-detection.test.ts', "execSync('which ss'"],
  ['__tests__/registry/secure-publish-wire-parity.test.ts', 'return existsSync(CLI);'],
  ['__tests__/ui/artifact-intent.test.ts', 'existsSync(CLI) && existsSync(fixture)'],
  ['__tests__/ui/verdict-band.test.ts', 'existsSync(CLI) && existsSync(FIXTURE)'],
];

/**
 * `it`/`test`/`describe` call sites, counted at base commit a598f61. Equality,
 * not a floor: a drop means a case was deleted to reach a skip count of zero,
 * and a silent rise means a case was added under cover of this change.
 */
const DECLARATION_SITES: ReadonlyArray<readonly [string, number]> = [
  ['__tests__/checker/check-not-found-json.test.ts', 12],
  ['__tests__/checker/check-pip-prefix-registry-query.test.ts', 4],
  ['__tests__/checker/check-secure-cross-analyzer-parity.test.ts', 11],
  ['__tests__/cli/check-skill-quick-scan-label.test.ts', 5],
  ['__tests__/cli/opena2a-citation-and-next-steps-target.test.ts', 11],
  ['__tests__/cli/output-hygiene.test.ts', 18],
  ['__tests__/hardening/credential-scan-source-extensions.test.ts', 6],
  ['__tests__/hardening/rollback-created-files.test.ts', 20],
  ['__tests__/oasb/e2e/E2E-003.live-network-detection.test.ts', 2],
  ['__tests__/registry/secure-publish-wire-parity.test.ts', 5],
  ['__tests__/ui/artifact-intent.test.ts', 17],
  ['__tests__/ui/verdict-band.test.ts', 13],
];

const DECLARATION_SITE = /(^|[^.\w])(it|test|describe)(\.\w+)?\(/g;

describe('HMA-18 the CI short-circuit is gone from the test tree', () => {
  it('HMA-18.AC1 no file under __tests__/ gates itself on the CI or GITHUB_ACTIONS variable', () => {
    const offenders = walk(TESTS_ROOT)
      .filter((f) => CI_SHORT_CIRCUIT.test(readFileSync(f, 'utf8')))
      .map((f) => relative(REPO_ROOT, f))
      .sort();

    expect(
      offenders,
      `these files still read the CI environment. A test that asks whether it is running on a ` +
        `runner and answers by not running is not a test: release.yml builds before it runs ` +
        `npm test, so the dist these suites wait for is present, and the assertions are absent ` +
        `at the one moment a version is published.\n${offenders.join('\n')}`,
    ).toEqual([]);
  });

  it('HMA-18.AC2 every helper the clause was cut from keeps its remaining precondition', () => {
    for (const [file, precondition] of REMAINING_PRECONDITION) {
      const source = readFileSync(join(REPO_ROOT, file), 'utf8');
      expect(
        source.includes(precondition),
        `${file} no longer contains \`${precondition}\`. Only the CI clause was in scope; the ` +
          `dist/fixture precondition is what keeps the suite honest when the artifact really is ` +
          `absent, and removing it turns a legitimate guard into a spurious failure.`,
      ).toBe(true);
    }
  });

  it('HMA-18.AC4 no test case was deleted from the files the clause was cut from', () => {
    for (const [file, expected] of DECLARATION_SITES) {
      const source = readFileSync(join(REPO_ROOT, file), 'utf8');
      const found = (source.match(DECLARATION_SITE) ?? []).length;
      expect(
        found,
        `${file} declares ${found} it/test/describe call sites; base commit a598f61 declared ` +
          `${expected}. Deleting the gate and deleting the gated tests both zero the skip count. ` +
          `This change is only the former.`,
      ).toBe(expected);
    }
  });
});
