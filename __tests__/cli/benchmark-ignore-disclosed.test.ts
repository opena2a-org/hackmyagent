/**
 * `secure -b` with `--ignore`: the suppression is disclosed, and the
 * compliance figure, the rating and the category line never move on it
 * unnamed.
 *
 * Measured on a package manifest with no lock file: DEP-001 fails, and it is
 * the check for controls 6.1-6.4 (Supply Chain Integrity, L1). Without
 * `--ignore` the category reads `0/4 (0%)` and the rating Not Passing at exit
 * 1. With `--ignore DEP-001` the four controls left the denominator with
 * nothing in the text report naming them, and the JSON controls read plain
 * `unverified`.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

let root: string;
let home: string;
let tree: string;

beforeAll(() => {
  root = tempDir('hma-bench-ignore-');
  home = tempDir('hma-home-');
  tree = path.join(root, 'manifest-only');
  fs.mkdirSync(tree);
  fs.writeFileSync(path.join(tree, 'package.json'), '{"name":"benchignore","version":"1.0.0","dependencies":{}}\n');
  fs.writeFileSync(path.join(tree, '.gitignore'), 'node_modules\n');
});

afterAll(() => {
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
});

function run(args: string[]) {
  const res = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home },
  });
  return { status: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

const BASE = ['--no-machine-posture', '--static-only'];
const SUPPLY = 'Supply Chain Integrity';
const jsonOf = (s: string) => JSON.parse(s.slice(s.indexOf('{')));

describe('secure -b with --ignore discloses what it left unscored', () => {
  it('CONTROL: without --ignore DEP-001 fails 6.1-6.4 and nothing is marked suppressed', () => {
    const res = run(['secure', tree, '-b', 'oasb-1', ...BASE]);
    expect(res.stdout).toContain(`[-] ${SUPPLY}: 0/4 (0%)`);
    expect(res.stdout).not.toContain('Suppressed:');
    expect(res.stdout).not.toContain('suppressed');
    expect(res.stderr).not.toContain('suppressed control');
    expect(res.status).toBe(1);
  });

  it('text: Supply Chain is not shown as passed, and each suppressed control is named with the flag', () => {
    const res = run(['secure', tree, '-b', 'oasb-1', ...BASE, '--ignore', 'DEP-001']);
    expect(res.stdout).not.toMatch(new RegExp(`\\[\\+\\] ${SUPPLY}`));
    expect(res.stdout).toContain(`[.] ${SUPPLY}: N/A (4 suppressed)`);
    for (const id of ['6.1', '6.2', '6.3', '6.4']) {
      expect(res.stdout).toMatch(new RegExp(`\\[s\\] ${id.replace('.', '\\.')}: .* \\(suppressed: DEP-001 by --ignore\\)`));
    }
    expect(res.stdout).toMatch(/^Rating: .*\(4 suppressed controls not scored\)$/m);
    expect(res.stdout).toMatch(/^Compliance: .*; 4 suppressed controls not scored\)$/m);
    expect(res.stdout).toContain('Suppressed: 4 controls not scored');
    expect(res.stdout).toMatch(/Withheld: 1 finding not read by the benchmark: DEP-001 \(\w+, --ignore\)/);
    // The gate says what the figure it reads was computed without.
    expect(res.stderr).toContain('Benchmark compliance leaves out 4 suppressed controls (6.1, 6.2, 6.3, 6.4) set aside by --ignore');
  });

  it('--fail-below: the line beside the threshold names the suppressed controls', () => {
    const res = run(['secure', tree, '-b', 'oasb-1', ...BASE, '--ignore', 'DEP-001', '--fail-below', '50', '--json']);
    expect(res.stderr).toContain('--fail-below are computed without them');
  });

  it('json: the controls are marked suppressed, counted, and the withheld rows ride beside them', () => {
    const doc = jsonOf(run(['secure', tree, '-b', 'oasb-1', ...BASE, '--ignore', 'DEP-001', '--json']).stdout);
    expect(doc.suppressedControls).toBe(4);
    expect(doc.suppressed.map((r: { checkId: string }) => r.checkId)).toEqual(['DEP-001']);
    const cat = doc.categories.find((c: { category: string }) => c.category === SUPPLY);
    expect(cat.suppressed).toBe(4);
    expect(cat.passed).toBe(0);
    for (const c of cat.controls) {
      expect(c.status).toBe('unverified');
      expect(c.suppressed).toEqual({ checkIds: ['DEP-001'], suppressedBy: ['ignore-flag'], findings: 1 });
    }
  });

  it('CONTROL json: without --ignore there is no suppression key anywhere', () => {
    const doc = jsonOf(run(['secure', tree, '-b', 'oasb-1', ...BASE, '--json']).stdout);
    expect(doc).not.toHaveProperty('suppressedControls');
    expect(doc).not.toHaveProperty('suppressed');
    for (const cat of doc.categories) {
      expect(cat).not.toHaveProperty('suppressed');
      for (const c of cat.controls) expect(c).not.toHaveProperty('suppressed');
    }
  });

  it('.hmaignore path rule: the out-of-scope row rides in json and the controls name the rule in text', () => {
    const scoped = path.join(root, 'path-rule');
    fs.mkdirSync(scoped);
    fs.copyFileSync(path.join(tree, 'package.json'), path.join(scoped, 'package.json'));
    fs.copyFileSync(path.join(tree, '.gitignore'), path.join(scoped, '.gitignore'));
    // DEP-001 reports against the lock file it looked for.
    fs.writeFileSync(path.join(scoped, '.hmaignore'), 'package-lock.json\n');

    const doc = jsonOf(run(['secure', scoped, '-b', 'oasb-1', ...BASE, '--json']).stdout);
    expect(doc.outOfScope.map((r: { checkId: string; suppressedBy: string }) => `${r.checkId}:${r.suppressedBy}`))
      .toEqual(['DEP-001:hmaignore-path']);
    expect(doc.suppressedControls).toBe(4);
    const cat = doc.categories.find((c: { category: string }) => c.category === SUPPLY);
    expect(cat.passed).toBe(0);
    for (const c of cat.controls) {
      expect(c.status).toBe('unverified');
      expect(c.suppressed).toEqual({ checkIds: ['DEP-001'], suppressedBy: ['hmaignore-path'], findings: 1 });
    }

    const text = run(['secure', scoped, '-b', 'oasb-1', ...BASE]);
    expect(text.stdout).not.toMatch(new RegExp(`\\[\\+\\] ${SUPPLY}`));
    expect(text.stdout).toContain(`[.] ${SUPPLY}: N/A (4 suppressed)`);
    expect(text.stdout).toContain('[s] 6.1: ');
    expect(text.stdout).toContain('(suppressed: DEP-001 by .hmaignore path rule)');
    expect(text.stdout).toMatch(/Withheld: 1 finding not read by the benchmark: DEP-001 \(\w+, \.hmaignore path rule\)/);
    expect(text.stderr).toContain('set aside by .hmaignore path rule');
  });

  it('oasb-2: the composite carries the same disclosure in text and json', () => {
    const text = run(['secure', tree, '-b', 'oasb-2', ...BASE, '--ignore', 'DEP-001']);
    expect(text.stdout).toMatch(/Infrastructure Score \(OASB-1\): .*\(4 suppressed controls not scored\)/);
    expect(text.stdout).toContain(`[.] ${SUPPLY}: N/A (4 suppressed)`);
    expect(text.stderr).toContain('Infrastructure Score (OASB-1) leaves out 4 suppressed controls');
    const doc = jsonOf(run(['secure', tree, '-b', 'oasb-2', ...BASE, '--ignore', 'DEP-001', '--json']).stdout);
    expect(doc.suppressed.map((r: { checkId: string }) => r.checkId)).toEqual(['DEP-001']);
    expect(doc.infraResult.suppressedControls).toBe(4);
  });
});
