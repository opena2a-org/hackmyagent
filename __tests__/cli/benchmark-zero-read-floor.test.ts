/**
 * The zero-read floor: a benchmark over a scan that read no file is not
 * measured.
 *
 * Once DEP-001 read the package manifest as its subject, an empty directory
 * carried no failing L1 control at all (6.1-6.4 not-applicable, the rest
 * unverified or passing on not-there), so the OASB-1 ladder rated it
 * `Certified` at 100% (3/3 verified controls), exit 0, where 0.33.0 printed
 * `Not Passing 43% (3/7)`. Three hazard probes passing on a tree with no
 * file in it is not a measurement of the tree.
 *
 * The contract, keyed on the `coverage.filesExamined` figure the scanner
 * already ledgers (`secure --json` carries it):
 *
 *   filesExamined === 0 -> `Rating: Not Assessed`, reason
 *                          `no file was read from <dir>`, every level
 *                          compliance `null`, control statuses unchanged
 *                          (the not-applicable and unverified records are
 *                          true records), exit 2 through the existing
 *                          not-measured floor, `--fail-below` not evaluated;
 *                          every level, depth and format, and the MCP
 *                          benchmark tool;
 *   filesExamined >= 1  -> unchanged: a README-only tree prints exactly what
 *                          it printed before this floor existed.
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
let empty: string;
let oneFile: string;

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-zero-read-'));
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-'));
  empty = path.join(root, 'empty');
  fs.mkdirSync(empty);
  oneFile = path.join(root, 'one-file');
  fs.mkdirSync(oneFile);
  fs.writeFileSync(path.join(oneFile, 'README.md'), '# fixture\n');
});

afterAll(() => {
  for (const d of [root, home]) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function run(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, 'secure', ...args, '--no-machine-posture'], {
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

function json(stdout: string): any {
  return JSON.parse(stdout.slice(stdout.indexOf('{')));
}

const LEVELS: Record<string, string[]> = {
  L1: ['-l', 'L1'],
  L3: ['-l', 'L3'],
};

describe('zero-read floor: an empty directory is not assessed', { timeout: 600_000 }, () => {
  it('T1 text: default depth prints Rating: Not Assessed with the zero-read reason, compliance not measured, exit 2', () => {
    const r = run([empty, '-b', 'oasb-1']);
    expect(r.stdout).toContain('Rating: Not Assessed\n');
    expect(r.stdout).toContain('Compliance: not measured (');
    expect(r.stdout).toContain(`no file was read from ${empty}`);
    expect(r.stdout).not.toContain('Certified');
    expect(r.stderr).toContain(`Benchmark rating is Not Assessed: no file was read from ${empty}`);
    expect(r.status).toBe(2);
  });

  it('T1 json: rating Not Assessed, compliance and every level null, control statuses kept, exit 2', () => {
    const r = run([empty, '-b', 'oasb-1', '--format', 'json']);
    const body = json(r.stdout);
    expect(body.rating).toBe('Not Assessed');
    expect(body.compliance).toBeNull();
    expect(body.l1Compliance).toBeNull();
    expect(body.l2Compliance).toBeNull();
    expect(body.l3Compliance).toBeNull();
    // The records are true records: the floor withholds the rating, not the
    // statuses. Measured on this tree: 3 hazard probes pass on not-there,
    // 6.1-6.4 are not-applicable, the rest unverified.
    expect([body.passedControls, body.failedControls, body.unverifiedControls, body.notApplicableControls]).toEqual([3, 0, 19, 4]);
    expect(r.status).toBe(2);
  });

  it.each(Object.keys(LEVELS))('T2 -l %s: Not Assessed, null compliance, exit 2 in text and json', (lv) => {
    const text = run([empty, '-b', 'oasb-1', ...LEVELS[lv]]);
    expect(text.stdout).toContain('Rating: Not Assessed\n');
    expect(text.status).toBe(2);
    const body = json(run([empty, '-b', 'oasb-1', ...LEVELS[lv], '--format', 'json']).stdout);
    expect(body.rating).toBe('Not Assessed');
    expect(body.compliance).toBeNull();
    expect(body.l1Compliance).toBeNull();
  });

  it('T2 --scan-depth quick: Not Assessed, null compliance, exit 2', () => {
    const text = run([empty, '-b', 'oasb-1', '--scan-depth', 'quick']);
    expect(text.stdout).toContain('Rating: Not Assessed\n');
    expect(text.status).toBe(2);
    const body = json(run([empty, '-b', 'oasb-1', '--scan-depth', 'quick', '--format', 'json']).stdout);
    expect(body.rating).toBe('Not Assessed');
    expect(body.compliance).toBeNull();
  });

  it('T2 -b oasb-2: the infrastructure side is not measured and the composite is withheld, exit 2 raised', () => {
    const r = run([empty, '-b', 'oasb-2']);
    expect(r.stdout).toContain('Infrastructure Score (OASB-1): not measured');
    expect(r.stdout).toContain('Rating: Not Assessed\n');
    expect(r.stdout).not.toContain('Certified');
    expect(r.stderr).toContain(`no file was read from ${empty}`);
    // Conformance NONE exits 1 and outranks the raised floor on this arm
    // (its recorded precedence); the floor is still raised and said.
    expect(r.stderr).toContain('Exit code raised to 2');
    const body = json(run([empty, '-b', 'oasb-2', '--format', 'json']).stdout);
    expect(body.infraScore).toBeNull();
    expect(body.compositeScore).toBeNull();
    expect(body.infraResult.rating).toBe('Not Assessed');
  });

  it('T5 html, asp and sarif carry the withheld rating with no null%, undefined or NaN', () => {
    for (const format of ['html', 'asp', 'sarif']) {
      const r = run([empty, '-b', 'oasb-1', '--format', format]);
      expect(r.stdout, format).not.toMatch(/null%|undefined|NaN/);
      expect(r.status, format).toBe(2);
      if (format === 'asp') {
        const body = json(r.stdout);
        expect(body.securityPosture.rating).toBe('Not Assessed');
        expect(body.securityPosture.compliance).toBeNull();
      }
      if (format === 'html') {
        expect(r.stdout).toContain('Not Assessed');
        expect(r.stdout).not.toContain('Certified');
      }
    }
  });

  it('--fail-below is not evaluated over the withheld figure', () => {
    const r = run([empty, '-b', 'oasb-1', '--fail-below', '80']);
    expect(r.stderr).toContain('--fail-below 80 not evaluated');
    expect(r.stderr).not.toContain('below threshold');
    expect(r.status).toBe(2);
  });
});

describe('zero-read floor: a tree from which one file was read is unaffected', { timeout: 600_000 }, () => {
  // Measured on this branch before the floor existed: a README-only tree
  // reads one file and rates exactly as the empty tree used to.
  it('T4 text and json: Certified 100% (3/3 verified controls), exit 0', () => {
    const text = run([oneFile, '-b', 'oasb-1']);
    expect(text.stdout).toContain('Rating: Certified\n');
    expect(text.stdout).toContain('Compliance: 100% (3/3 verified controls)');
    expect(text.stdout).not.toContain('no file was read');
    expect(text.status).toBe(0);
    const body = json(run([oneFile, '-b', 'oasb-1', '--format', 'json']).stdout);
    expect(body.rating).toBe('Certified');
    expect(body.compliance).toBe(100);
    expect(body.l1Compliance).toBe(100);
    expect([body.passedControls, body.failedControls, body.unverifiedControls, body.notApplicableControls]).toEqual([3, 0, 19, 4]);
  });
});
