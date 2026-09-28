/**
 * #615 — `secure -b oasb-1 --verbose` must list every unverified control its
 * header counts, give the header the rows' own reasons, and not print a 0%
 * figure for a category in which nothing was measured.
 *
 * Measured on 6d6685e: `Unverified: 44 controls require manual/forward
 * verification` over 9 `[?]` rows, 8 categories collapsed to `N/A (no controls
 * at this level)`. #458 step 3 restored the rows and the label; the header
 * still said all 44 need a person while 23 are automated controls whose check
 * produced nothing on the tree, the legend said the same, and the category
 * grain of `--format json` / `--format asp` read `"compliance": 0` beside
 * `"passed": 0, "failed": 0`.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

let root: string;
let home: string;
let oneFile: string;

function run(args: string[]) {
  const res = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 240_000,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home },
  });
  return { status: res.status, stdout: res.stdout ?? '', out: `${res.stdout ?? ''}${res.stderr ?? ''}` };
}

function parseJson(stdout: string): any {
  return JSON.parse(stdout.slice(stdout.indexOf('{')));
}

const L3_QUICK = ['-b', 'oasb-1', '-l', 'L3', '--scan-depth', 'quick', '--no-machine-posture'];

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-615-'));
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-615-home-'));
  // One file every depth reads, so the run is measured (an unread tree is
  // Not Assessed) while most categories still hold no measured control.
  oneFile = path.join(root, 'one-file');
  fs.mkdirSync(oneFile);
  fs.writeFileSync(path.join(oneFile, '.gitignore'), 'node_modules\n');
});

afterAll(() => {
  for (const d of [root, home]) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

describe('#615: --verbose accounts for every unverified control, with the right reason', () => {
  for (const [label, target] of [['empty directory', () => fs.mkdtempSync(path.join(root, 'empty-'))], ['one read file', () => oneFile]] as const) {
    it(`${label}: one [?] row per counted control, and the header split matches the rows`, () => {
      const res = run(['secure', target(), ...L3_QUICK, '--verbose']);
      const header = res.out.match(/^Unverified: (\d+) controls? \((.*)\)$/m);
      expect(header, res.out).not.toBeNull();
      const counted = Number(header![1]);

      const rows = res.out.split('\n').filter((l) => /^\s+\[\?\] /.test(l));
      expect(rows.length).toBe(counted);

      const manualRows = rows.filter((l) => l.endsWith('(manual/forward)')).length;
      const noDataRows = rows.filter((l) => l.endsWith('(no scanner data)')).length;
      expect(manualRows + noDataRows).toBe(counted);
      // The fixture has both kinds, so both halves of the split are exercised.
      expect(manualRows).toBeGreaterThan(0);
      expect(noDataRows).toBeGreaterThan(0);
      expect(header![2]).toBe(
        `${manualRows} require manual/forward verification, ${noDataRows} automated with no scanner data`,
      );

      expect(res.out).not.toContain('no controls at this level');
      expect(res.out).not.toContain('Legend: [?] = Manual/Forward verification required');
    });
  }
});

describe('#615: a category with no measured control carries no compliance figure', () => {
  it('--format json: null at 0/0, a number wherever a control was measured', () => {
    const body = parseJson(run(['secure', oneFile, ...L3_QUICK, '--format', 'json']).stdout);
    const cats: Array<{ category: string; compliance: number | null; passed: number; failed: number }> = body.categories;
    const unmeasured = cats.filter((c) => c.passed + c.failed === 0);
    const measured = cats.filter((c) => c.passed + c.failed > 0);
    expect(unmeasured.length).toBeGreaterThan(0);
    expect(measured.length).toBeGreaterThan(0);
    for (const c of unmeasured) expect(c.compliance, c.category).toBeNull();
    for (const c of measured) expect(typeof c.compliance, c.category).toBe('number');
  });

  it('--format asp: the category grain follows the same rule', () => {
    const body = parseJson(run(['secure', oneFile, ...L3_QUICK, '--ci', '--format', 'asp']).stdout);
    const cats: Array<{ name: string; compliance: number | null; passed: number; failed: number }> = body.categories;
    expect(cats.length).toBeGreaterThan(0);
    const unmeasured = cats.filter((c) => c.passed + c.failed === 0);
    expect(unmeasured.length).toBeGreaterThan(0);
    for (const c of unmeasured) expect(c.compliance, c.name).toBeNull();
  });
});
