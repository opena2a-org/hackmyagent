/**
 * #649 — `eval oracle --format` is validated instead of falling back to text.
 *
 * Before: the action branched `opts.format === 'json' ? json : text` with no
 * validation, so `--format bogus`, `--format sarif` or `--format ''` printed
 * the text report and exited 0. Now any format other than text or json exits
 * 1 with the invalid-format error before the eval runs.
 *
 * RED-ON-BASE cells fail on the c3df135c dist; PIN cells pass on both.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

let oracleDir: string;
let home: string;

beforeAll(() => {
  oracleDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-649-'));
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-'));
});

afterAll(() => {
  for (const d of [oracleDir, home]) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function run(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, 'eval', 'oracle', ...args], {
    encoding: 'utf8',
    timeout: 60_000,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

describe('#649 eval oracle refuses a format it cannot render', { timeout: 120_000 }, () => {
  for (const format of ['bogus', 'sarif', '']) {
    it(`RED-ON-BASE: --format '${format}' exits 1 before the eval runs`, () => {
      const r = run(['--oracle-dir', oracleDir, '--format', format]);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain(`Error: Invalid format '${format}'. Use: text, json`);
      expect(r.stdout).not.toMatch(/Running oracle eval/);
      expect(r.stdout).not.toMatch(/Oracle Accuracy Eval/);
    });
  }

  it('RED-ON-BASE: an invalid format is named even when the oracle dir is also missing', () => {
    const r = run(['--oracle-dir', path.join(oracleDir, 'absent'), '--format', 'bogus']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("Error: Invalid format 'bogus'. Use: text, json");
  });

  it('PIN: --format json prints the JSON report', () => {
    const r = run(['--oracle-dir', oracleDir, '--format', 'json']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/"overall"/);
  });

  it('PIN: the default format prints the text report', () => {
    const r = run(['--oracle-dir', oracleDir]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Oracle Accuracy Eval/);
  });

  it('PIN: a missing oracle dir with a valid format keeps its own error', () => {
    const r = run(['--oracle-dir', path.join(oracleDir, 'absent'), '--format', 'json']);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/Error: oracle-dir not found: /);
  });
});
