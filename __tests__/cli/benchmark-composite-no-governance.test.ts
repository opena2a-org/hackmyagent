/**
 * #489 — `secure -b oasb-2` over a tree with no governance file.
 *
 * The composite arm printed `Governance Score (OASB-2): 0/100` and
 * `Conformance: NONE` and exited 1 over a tree where no governance file was
 * read, while `scan-soul` reported NOT MEASURED at exit 2 on the same tree
 * (#390). With the infrastructure side measured it also averaged the unread
 * 0 into a composite score. Nothing was graded, so the governance score, the
 * conformance level and the composite are withheld, and the run exits 2.
 *
 * Cells marked RED-ON-BASE fail on the ec10772 dist; PIN cells pass on both.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

const EXIT_UNMEASURED = 2;
const QUICK = ['--scan-depth', 'quick', '--no-machine-posture'];

let root: string;
let home: string;
/** No file at all: both sides unmeasured. */
let empty: string;
/** One file the quick-depth hardening scan reads, and no governance file: OASB-1 measured, OASB-2 not. */
let infraOnly: string;
/** A zero-byte SOUL.md: found, read, nothing to grade. */
let emptySoul: string;
/** A SOUL.md that was read and conforms to nothing: a measured failure. */
let bareSoul: string;

beforeAll(() => {
  assertDistFreshIfPresent();
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-oasb2-nogov-'));
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-'));
  empty = path.join(root, 'empty');
  fs.mkdirSync(empty);
  infraOnly = path.join(root, 'infra-only');
  fs.mkdirSync(infraOnly);
  fs.writeFileSync(path.join(infraOnly, '.gitignore'), 'node_modules\n');
  emptySoul = path.join(root, 'empty-soul');
  fs.mkdirSync(emptySoul);
  fs.writeFileSync(path.join(emptySoul, '.gitignore'), 'node_modules\n');
  fs.writeFileSync(path.join(emptySoul, 'SOUL.md'), '');
  bareSoul = path.join(root, 'bare-soul');
  fs.mkdirSync(bareSoul);
  fs.writeFileSync(path.join(bareSoul, '.gitignore'), 'node_modules\n');
  fs.writeFileSync(path.join(bareSoul, 'SOUL.md'), 'name: demo\n');
});

afterAll(() => {
  for (const d of [root, home]) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function run(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home },
  });
  return { status: r.status, out: r.stdout ?? '', err: r.stderr ?? '' };
}

function json(stdout: string): any {
  return JSON.parse(stdout.slice(stdout.indexOf('{')));
}

describe('#489 secure -b oasb-2 does not grade a governance file it did not read', { timeout: 600_000 }, () => {
  it('RED-ON-BASE text, empty tree: governance and conformance read not measured, no 0/100, no NONE, exit 2', () => {
    const r = run(['secure', empty, '-b', 'oasb-2', ...QUICK]);
    expect(r.out).toMatch(/Governance Score \(OASB-2\):\s+not measured\n/);
    expect(r.out).toMatch(/Conformance:\s+not measured\n/);
    expect(r.out).toMatch(/Composite Score:\s+not measured \(OASB-1 not assessed, OASB-2 governance not measured\)/);
    expect(r.out).not.toContain('0/100');
    expect(r.out).not.toMatch(/Conformance:\s+NONE/);
    // The nine-domain table is withheld with the score it summed to.
    expect(r.out).not.toContain('Governance Domains');
    expect(r.out).toContain('NOT MEASURED — No governance file was found');
    expect(r.out).toContain('Searched: SOUL.md');
    expect(r.err).not.toContain('OASB-2 conformance is NONE');
    expect(r.err).toContain('OASB-2 governance is not measured');
    expect(r.status).toBe(EXIT_UNMEASURED);
  });

  it('RED-ON-BASE json, empty tree: govScore, conformance and govResult are null, govCoverage says why, exit 2', () => {
    const r = run(['secure', empty, '-b', 'oasb-2', ...QUICK, '--format', 'json']);
    const body = json(r.out);
    expect(body.govScore).toBeNull();
    expect(body.conformance).toBeNull();
    expect(body.compositeScore).toBeNull();
    expect(body.govResult).toBeNull();
    expect(body.govCoverage).toMatchObject({
      measured: false,
      examined: 0,
      unit: 'governance control',
      reason: 'nothing-to-examine',
    });
    expect(r.status).toBe(EXIT_UNMEASURED);
  });

  it('RED-ON-BASE: a measured infrastructure side is not averaged with an unread governance 0', () => {
    const text = run(['secure', infraOnly, '-b', 'oasb-2', ...QUICK]);
    expect(text.out).toMatch(/Infrastructure Score \(OASB-1\):\s+\d+%/);
    expect(text.out).toMatch(/Composite Score:\s+not measured \(OASB-2 governance not measured\)/);
    expect(text.status).toBe(EXIT_UNMEASURED);
    const body = json(run(['secure', infraOnly, '-b', 'oasb-2', ...QUICK, '--format', 'json']).out);
    expect(typeof body.infraScore).toBe('number');
    expect(body.govScore).toBeNull();
    expect(body.compositeScore).toBeNull();
  });

  it('RED-ON-BASE: --fail-below is not evaluated against a composite that was not measured', () => {
    const r = run(['secure', infraOnly, '-b', 'oasb-2', ...QUICK, '--fail-below', '50']);
    expect(r.err).toContain('--fail-below 50 not evaluated: the composite score was not measured (OASB-2 governance not measured).');
    expect(r.err).not.toMatch(/below threshold/);
    expect(r.status).toBe(EXIT_UNMEASURED);
  });

  it('RED-ON-BASE: a zero-byte SOUL.md is found but has nothing to grade, exit 2', () => {
    const r = run(['secure', emptySoul, '-b', 'oasb-2', ...QUICK]);
    expect(r.out).toContain('NOT MEASURED — SOUL.md was found but is empty');
    expect(r.out).toMatch(/Governance Score \(OASB-2\):\s+not measured\n/);
    expect(r.status).toBe(EXIT_UNMEASURED);
  });

  it('RED-ON-BASE: agrees with scan-soul on the same tree with no governance file', () => {
    const soul = run(['scan-soul', infraOnly]);
    const composite = run(['secure', infraOnly, '-b', 'oasb-2', ...QUICK]);
    expect(soul.status).toBe(EXIT_UNMEASURED);
    expect(composite.status).toBe(soul.status);
  });

  it('PIN: a governance file that was read and conforms to nothing still fails at Conformance NONE, exit 1', () => {
    const r = run(['secure', bareSoul, '-b', 'oasb-2', ...QUICK]);
    expect(r.out).toMatch(/Governance Score \(OASB-2\):\s+0\/100\n/);
    expect(r.out).toMatch(/Conformance:\s+NONE\n/);
    expect(r.out).toContain('Governance Domains (scan-soul):');
    expect(r.err).toContain('OASB-2 conformance is NONE');
    expect(r.err).not.toContain('OASB-2 governance is not measured');
    expect(r.status).toBe(1);
    const body = json(run(['secure', bareSoul, '-b', 'oasb-2', ...QUICK, '--format', 'json']).out);
    expect(body.govScore).toBe(0);
    expect(body.conformance).toBe('none');
    expect(body.govResult).not.toBeNull();
  });

  it('RED-ON-BASE json: a governance file that was read reports its coverage as measured', () => {
    const body = json(run(['secure', bareSoul, '-b', 'oasb-2', ...QUICK, '--format', 'json']).out);
    expect(body.govCoverage).toMatchObject({ measured: true, unit: 'governance control' });
    expect(body.govCoverage.examined).toBeGreaterThan(0);
  });
});
