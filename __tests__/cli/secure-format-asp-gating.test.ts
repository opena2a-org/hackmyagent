/**
 * #563 — `secure --format asp` outside benchmark mode rendered the TEXT report.
 *
 * The Agent Security Profile is produced only by the OASB-1 benchmark arm (the
 * OASB-2 composite has no profile renderer either), but the format validator
 * accepted `asp` for any run, so a CI job that asked for a machine format got a
 * human one — and nothing in the exit code said so. The flag is now refused
 * where the other format errors are raised, with the flag it needs named; with
 * `-b oasb-1` it still produces the ASP document.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

let dir: string;

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-563-'));
  fs.writeFileSync(path.join(dir, 'package.json'), '{ "name": "fx563", "version": "1.0.0", "private": true }\n');
  fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n.env\n');
  fs.writeFileSync(path.join(dir, 'index.js'), 'module.exports = () => 1;\n');
});

afterAll(() => {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
});

function run(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-')) },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

describe('#563 secure --format asp is a benchmark format', () => {
  it('without -b it is refused with the flag it needs, and no report is printed', () => {
    const r = run(['secure', dir, '--ci', '--format', 'asp']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('--format asp');
    expect(r.stderr).toContain('-b oasb-1');
    // Neither the text report nor an ASP document reached stdout.
    expect(r.stdout).not.toMatch(/Security\s+━/);
    expect(r.stdout).not.toContain('"specVersion"');
  });

  it('with -b it still produces the Agent Security Profile document', () => {
    const r = run(['secure', dir, '--ci', '-b', 'oasb-1', '--format', 'asp']);
    const body = JSON.parse(r.stdout.slice(r.stdout.indexOf('{')));
    expect(body.specVersion).toBe('1.0.0');
    expect(body.generator?.name).toBe('HackMyAgent');
    expect(body.securityPosture?.benchmark).toBe('OASB-1');
    expect([0, 1, 2]).toContain(r.status);
  });

  it('with -b oasb-2 it is refused too: the composite arm has no profile renderer', () => {
    const r = run(['secure', dir, '--ci', '-b', 'oasb-2', '--format', 'asp']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('-b oasb-1');
    expect(r.stdout).not.toContain('"specVersion"');
    expect(r.stdout).not.toMatch(/Compliance/);
  });

  it('an unknown format is still refused by the same validator', () => {
    const r = run(['secure', dir, '--ci', '--format', 'xyz']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("Invalid format 'xyz'");
  });

  it('--help names asp with its condition, and the flag it cites is registered', () => {
    const r = run(['secure', '--help']);
    expect(r.status).toBe(0);
    // Commander wraps option descriptions; compare on collapsed whitespace.
    const flat = r.stdout.replace(/\s+/g, ' ');
    expect(flat).toMatch(/asp with -b oasb-1/);
    expect(flat).toMatch(/asp +Agent Security Profile \(with -b oasb-1\)/);
    expect(flat).toMatch(/-b, --benchmark <name>/);
    // Commander appends its own default; the description must not repeat it.
    expect(flat).not.toMatch(/\(default: text\) \(default: "text"\)/);
  });
});
