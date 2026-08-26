/**
 * #632 / #633 — the `-b` gate validates on presence, and each benchmark arm
 * refuses the formats it cannot render.
 *
 * Before: `-b ''` skipped the benchmark validator and the arm switch (both
 * tested truthiness), so a CI template over an unset variable
 * ran the ordinary report and exited 0 where a benchmark verdict was asked
 * for. `-b oasb-1 --format asff` fell to the text report (the OASB-1 arm's
 * switch has no asff case), and the OASB-2 composite arm branches on json
 * only, so `--format sarif|html|asff` printed its prose too — a machine
 * format request answered with a human one, nothing in the exit code to say
 * so (#563's class). The level validator also excluded the composite arm,
 * which consumes the level: `-b oasb-2 -l L9` died on
 * `RATING_LADDER[level] is not iterable`.
 *
 * RED-ON-BASE cells fail on the 2a39b72 dist; PIN cells pass on both.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const QUICK = ['--scan-depth', 'quick', '--no-machine-posture'];

let dir: string;

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-632-'));
  fs.writeFileSync(path.join(dir, 'package.json'), '{ "name": "fx632", "version": "1.0.0", "private": true }\n');
  fs.writeFileSync(path.join(dir, 'index.js'), 'module.exports = () => 1;\n');
});

afterAll(() => {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
});

function run(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, 'secure', dir, ...args, ...QUICK], {
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-')) },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

function jsonBody(stdout: string): any {
  const start = stdout.search(/[[{]/);
  expect(start).toBeGreaterThanOrEqual(0);
  return JSON.parse(stdout.slice(start));
}

describe('#632 -b validates on presence, not truthiness', { timeout: 300_000 }, () => {
  it("RED-ON-BASE: -b '' is refused as an unknown benchmark, and no report is printed", () => {
    const r = run(['-b', '']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("Unknown benchmark ''");
    expect(r.stderr).toContain('Available: oasb-1, oasb-2');
    expect(r.stdout).not.toMatch(/Scan depth/);
    expect(r.stdout).not.toMatch(/Security\s+━/);
  });

  it('PIN: -b bogus is still refused with the same line', () => {
    const r = run(['-b', 'bogus']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("Unknown benchmark 'bogus'");
  });

  it('RED-ON-BASE: -b oasb-2 -l L9 is refused by the level validator, not by the rating ladder', () => {
    const r = run(['-b', 'oasb-2', '-l', 'L9']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("Invalid level 'L9'");
    expect(r.stderr).toContain('Use: L1, L2, or L3');
    expect(r.stderr).not.toContain('not iterable');
    expect(r.stdout).not.toMatch(/Scan depth/);
  });
});

describe('#633 each benchmark arm refuses the formats it cannot render', { timeout: 300_000 }, () => {
  it('RED-ON-BASE: -b oasb-1 --format asff is refused with the formats the arm renders', () => {
    const r = run(['-b', 'oasb-1', '--format', 'asff']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('--format asff is not available with -b oasb-1');
    expect(r.stderr).toContain('Use: text, json, sarif, html, asp');
    expect(r.stdout).not.toContain('OASB-1:');
    expect(r.stdout).not.toContain('"Findings"');
  });

  it('RED-ON-BASE: the refusal names the benchmark as typed (spelling parity with #630)', () => {
    const r = run(['-b', 'OASB-1', '--format', 'asff']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('--format asff is not available with -b OASB-1');
    expect(r.stdout).not.toContain('OASB-1:');
  });

  it.each(['sarif', 'html', 'asff'])('RED-ON-BASE: -b oasb-2 --format %s is refused; the composite arm renders text and json only', (format) => {
    const r = run(['-b', 'oasb-2', '--format', format]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain(`--format ${format} is not available with -b oasb-2`);
    expect(r.stderr).toContain('Use: text, json');
    expect(r.stdout).not.toContain('OASB Composite');
  });

  it('PIN: -b oasb-2 --format json still emits the composite document', () => {
    const r = run(['-b', 'oasb-2', '--format', 'json']);
    expect(r.stderr).not.toContain('not available with -b');
    expect(jsonBody(r.stdout).benchmark).toBe('OASB');
  });

  it('PIN: -b oasb-1 --format sarif still emits a SARIF log', () => {
    const r = run(['-b', 'oasb-1', '--format', 'sarif']);
    expect(r.stderr).not.toContain('not available with -b');
    expect(Array.isArray(jsonBody(r.stdout).runs)).toBe(true);
    expect([0, 1, 2]).toContain(r.status);
  });

  it('PIN: -b oasb-1 --format asp still emits the Agent Security Profile', () => {
    const r = run(['-b', 'oasb-1', '--format', 'asp']);
    expect(r.stderr).not.toContain('not available with -b');
    expect(jsonBody(r.stdout).specVersion).toBe('1.0.0');
  });

  it('PIN: --format asff without -b still emits ASFF (the non-benchmark arm renders it)', () => {
    const r = run(['--format', 'asff']);
    expect(r.stderr).not.toContain('not available with -b');
    // ASFF, not just JSON: the Security Hub document shape carries SchemaVersion.
    const body = jsonBody(r.stdout);
    expect(JSON.stringify(body)).toContain('SchemaVersion');
  });
});

describe('the same class on the other optional strings of the secure gate: presence, not truthiness', { timeout: 300_000 }, () => {
  it("RED-ON-BASE: --fail-below '' is a range error, not a silently removed floor", () => {
    const r = run(['--fail-below', '']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('--fail-below must be a number between 0 and 100');
  });

  it("RED-ON-BASE: -b oasb-1 -l '' is an invalid level, not L1", () => {
    const r = run(['-b', 'oasb-1', '-l', '']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("Invalid level ''");
    expect(r.stdout).not.toMatch(/Rating: /);
  });

  it("RED-ON-BASE: --format '' is an invalid format, not the text report", () => {
    const r = run(['--format', '']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("Invalid format ''");
    expect(r.stdout).not.toMatch(/Security\s+━/);
  });

  it("RED-ON-BASE: --scan-depth '' is an invalid depth, not a standard scan", () => {
    // Raw spawn: the shared helper appends its own --scan-depth, which Commander would let win.
    const r = spawnSync(process.execPath, [CLI, 'secure', dir, '--no-machine-posture', '--scan-depth', ''], {
      encoding: 'utf8',
      timeout: 240_000,
      maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-')) },
    });
    expect(r.status).toBe(1);
    expect(r.stderr ?? '').toContain("Invalid scan depth ''");
    expect(r.stdout ?? '').not.toMatch(/Security\s+━/);
  });

  it('PIN: -b OASB-2 --format asp keeps the #563 line — the asp gate reads the normalized name', () => {
    const r = run(['-b', 'OASB-2', '--format', 'asp']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('--format asp');
    expect(r.stderr).toContain('-b oasb-1');
    expect(r.stdout).not.toContain('OASB Composite');
  });
});
