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
 *   The third case holds a floor under the number of declaration sites per
 *   file, starting from base commit a598f61. Deleting a gate and deleting the
 *   tests it gated both drive the skipped count to zero; only this case tells
 *   them apart. It is a floor, not an equality, because deletion is the
 *   property: a test added to one of these files is not a short-circuit. The
 *   same case refuses an unconditional skip in those files, so a count that
 *   rises or holds cannot hide a case that no longer runs.
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
 *
 * Where the build was a suite's only precondition, the row names
 * `beforeAll(assertDistFresh)` rather than an existence check: the same
 * precondition, now an error that names `npm run build` instead of a skip
 * (dist-only-gates-are-named-errors.test.ts). Dropping it outright still
 * fails this row.
 */
const REMAINING_PRECONDITION: ReadonlyArray<readonly [string, string]> = [
  ['__tests__/checker/check-not-found-json.test.ts', 'return existsSync(CLI);'],
  ['__tests__/checker/check-pip-prefix-registry-query.test.ts', 'beforeAll(assertDistFresh)'],
  ['__tests__/checker/check-secure-cross-analyzer-parity.test.ts', 'beforeAll(assertDistFresh)'],
  ['__tests__/cli/check-skill-quick-scan-label.test.ts', 'existsSync(CLI) && existsSync(FIXTURE)'],
  ['__tests__/cli/opena2a-citation-and-next-steps-target.test.ts', 'return existsSync(CLI);'],
  ['__tests__/cli/output-hygiene.test.ts', 'beforeAll(assertDistFresh)'],
  ['__tests__/hardening/credential-scan-source-extensions.test.ts', 'beforeAll(assertDistFresh)'],
  ['__tests__/hardening/rollback-created-files.test.ts', 'beforeAll(assertDistFresh)'],
  ['__tests__/oasb/e2e/E2E-003.live-network-detection.test.ts', "execSync('which ss'"],
  ['__tests__/registry/secure-publish-wire-parity.test.ts', 'beforeAll(assertDistFresh)'],
  ['__tests__/ui/artifact-intent.test.ts', 'existsSync(CLI) && existsSync(fixture)'],
  ['__tests__/ui/verdict-band.test.ts', 'existsSync(CLI) && existsSync(FIXTURE)'],
];

/**
 * `it`/`test`/`describe` call sites per file, counted at base commit a598f61,
 * the commit the CI clause was cut from. A recorded fact, not a setting: each
 * floor below starts here, and a floor under it needs a reason.
 */
const BASE_A598F61: Readonly<Record<string, number>> = {
  '__tests__/checker/check-not-found-json.test.ts': 12,
  '__tests__/checker/check-pip-prefix-registry-query.test.ts': 4,
  '__tests__/checker/check-secure-cross-analyzer-parity.test.ts': 11,
  '__tests__/cli/check-skill-quick-scan-label.test.ts': 5,
  '__tests__/cli/opena2a-citation-and-next-steps-target.test.ts': 11,
  '__tests__/cli/output-hygiene.test.ts': 18,
  '__tests__/hardening/credential-scan-source-extensions.test.ts': 6,
  '__tests__/hardening/rollback-created-files.test.ts': 20,
  '__tests__/oasb/e2e/E2E-003.live-network-detection.test.ts': 2,
  '__tests__/registry/secure-publish-wire-parity.test.ts': 5,
  '__tests__/ui/artifact-intent.test.ts': 17,
  '__tests__/ui/verdict-band.test.ts': 13,
};

type DeclarationRow = readonly [file: string, floor: number, reason?: string];

/**
 * `[file, floor, reason?]`. A floor, not an equality: a drop means a case was
 * deleted, which is what deleting the gated tests looks like, while a rise is a
 * test added under review. An equality refused every regression test added to
 * these files and caught no deletion a floor misses.
 *
 * A floor below the file's a598f61 count is admitted only with a non-empty
 * reason in the row, edited in the same change, so the reviewer reads the
 * decrease and why. The verdict reads the files in the checkout and nothing
 * else: no history, no pull request text, no label, no environment.
 */
const DECLARATION_SITES: ReadonlyArray<DeclarationRow> = [
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

/**
 * An unconditional skip or todo. A floor alone reads a new skip wrapper as a
 * rise and an `it` turned into a skip as no change, and both disable a gated
 * case without deleting it, so these files carry none. A case that cannot run
 * on a machine is gated on the file's existing precondition instead.
 */
const UNCONDITIONAL_SKIP = /(^|[^.\w])(it|test|describe)\.(skip|todo)\(/g;

export interface DeclarationVerdict {
  /** Declaration sites, counted the way the floors were. */
  found: number;
  /** Unconditional skip and todo sites. Any one fails the file. */
  skips: number;
  /** `line N: <text>` for each line carrying a skip site. */
  skipSites: string[];
  ok: boolean;
}

/**
 * The AC4 verdict on one file's source: at least `floor` declaration sites and
 * no unconditional skip. The live check and the cells below share it, so a
 * cell that reads red reads red for the same reason a pinned file would.
 */
export function declarationVerdict(source: string, floor: number): DeclarationVerdict {
  const found = (source.match(DECLARATION_SITE) ?? []).length;
  const skips = (source.match(UNCONDITIONAL_SKIP) ?? []).length;
  const skipSites = source
    .split('\n')
    .flatMap((line, i) => (line.match(UNCONDITIONAL_SKIP) ? [`line ${i + 1}: ${line.trim()}`] : []));
  return { found, skips, skipSites, ok: found >= floor && skips === 0 };
}

/** A pinned file that does not exist throws: a rename is a row edit, never a skip. */
function pinnedVerdict(file: string, floor: number): DeclarationVerdict {
  return declarationVerdict(readFileSync(join(REPO_ROOT, file), 'utf8'), floor);
}

/**
 * What is wrong with the table itself: a floor under its a598f61 count with no
 * reason, a row with no a598f61 count, or an a598f61 file with no row. The last
 * two keep a rename or a dropped row from removing a file's floor unread.
 */
function tableProblems(
  rows: ReadonlyArray<DeclarationRow>,
  base: Readonly<Record<string, number>>,
): string[] {
  const problems: string[] = [];
  for (const [file, floor, reason] of rows) {
    const original = base[file];
    if (original === undefined) {
      problems.push(`${file} has a floor but no a598f61 count; a renamed file moves both.`);
    } else if (floor < original && !reason?.trim()) {
      problems.push(`${file} has a floor of ${floor}, under its a598f61 count of ${original}, and no reason.`);
    }
  }
  for (const file of Object.keys(base)) {
    if (!rows.some(([row]) => row === file)) problems.push(`${file} has an a598f61 count but no floor.`);
  }
  return problems;
}

function describeFailure(file: string, floor: number, verdict: DeclarationVerdict): string {
  const lines = [`${file} declares ${verdict.found} it/test/describe call sites against a floor of ${floor}.`];
  if (verdict.found < floor) {
    lines.push(
      `A case was deleted. Deleting the gate and deleting the gated tests both zero the skip count; ` +
        `only the former is in scope here. If the deletion is intended, lower this file's row in ` +
        `DECLARATION_SITES in the same change and give it a reason: ` +
        `['${file}', ${verdict.found}, '<why the case was removed>'].`,
    );
  }
  if (verdict.skips > 0) {
    lines.push(
      `It carries ${verdict.skips} unconditional skip or todo site(s), which stop a gated case from ` +
        `running without deleting it. Run the case, or gate it on the file's existing precondition:`,
      ...verdict.skipSites.map((site) => `  ${site}`),
    );
  }
  return lines.join('\n');
}

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
    const problems = tableProblems(DECLARATION_SITES, BASE_A598F61);
    expect(problems, `DECLARATION_SITES is out of step with BASE_A598F61:\n${problems.join('\n')}`).toEqual([]);

    const failures = DECLARATION_SITES.flatMap(([file, floor]) => {
      const verdict = pinnedVerdict(file, floor);
      return verdict.ok ? [] : [describeFailure(file, floor, verdict)];
    });
    expect(failures, failures.join('\n\n')).toEqual([]);
  });

  describe('the AC4 verdict, from a three-site base', () => {
    const FLOOR = 3;
    const BASE = ["describe('suite', () => {", "  it('a', () => {});", "  it('b', () => {});", '});'];
    // The skip shapes are assembled, for the reason the environment pattern
    // above is: a census of skip sites over `__tests__/` would count them.
    const skipped = (fn: string, modifier: 'skip' | 'todo') => `${fn}.${modifier}(`;
    const verdictOf = (lines: string[]) => declarationVerdict(lines.join('\n'), FLOOR);

    it('unchanged: green', () => {
      expect(verdictOf(BASE)).toMatchObject({ found: 3, skips: 0, ok: true });
    });

    it('one case deleted: red', () => {
      expect(verdictOf([BASE[0], BASE[1], BASE[3]])).toMatchObject({ found: 2, skips: 0, ok: false });
    });

    it('a plain case added: green', () => {
      const added = [...BASE.slice(0, 3), "  it('c', () => {});", BASE[3]];
      expect(verdictOf(added)).toMatchObject({ found: 4, skips: 0, ok: true });
    });

    it('a new skip wrapper around the suite: red', () => {
      const wrapped = [`${skipped('describe', 'skip')}'wrapper', () => {`, ...BASE, '});'];
      expect(verdictOf(wrapped)).toMatchObject({ found: 4, skips: 1, ok: false });
    });

    it('a case turned into a skip: red', () => {
      const converted = [BASE[0], `  ${skipped('it', 'skip')}'a', () => {});`, BASE[2], BASE[3]];
      expect(verdictOf(converted)).toMatchObject({ found: 3, skips: 1, ok: false });
      expect(verdictOf(converted).skipSites).toEqual([`line 2: ${skipped('it', 'skip')}'a', () => {});`]);
    });

    it('a todo added: red', () => {
      const todo = [...BASE.slice(0, 3), `  ${skipped('it', 'todo')}'c');`, BASE[3]];
      expect(verdictOf(todo)).toMatchObject({ found: 4, skips: 1, ok: false });
    });

    it('a pinned path that does not exist: error, not a pass', () => {
      expect(() => pinnedVerdict('__tests__/harness/no-such-pinned-file.test.ts', FLOOR)).toThrow(/ENOENT/);
    });

    it('a floor under its a598f61 count needs a reason, and a dropped or renamed row is refused', () => {
      const base = { 'a.test.ts': 5, 'b.test.ts': 2 };
      expect(tableProblems([['a.test.ts', 5], ['b.test.ts', 3]], base)).toEqual([]);
      expect(tableProblems([['a.test.ts', 4, 'case e moved to c.test.ts'], ['b.test.ts', 2]], base)).toEqual([]);
      expect(tableProblems([['a.test.ts', 4], ['b.test.ts', 2]], base)).toHaveLength(1);
      expect(tableProblems([['a.test.ts', 4, '  '], ['b.test.ts', 2]], base)).toHaveLength(1);
      expect(tableProblems([['a.test.ts', 5]], base)).toEqual(['b.test.ts has an a598f61 count but no floor.']);
      expect(tableProblems([['a.test.ts', 5], ['renamed.test.ts', 2]], base)).toHaveLength(2);
    });
  });
});
