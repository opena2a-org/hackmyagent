/**
 * #647 — `secure -o <file>` with the text format is refused instead of
 * ignored.
 *
 * Before: no text arm wrote `-o`. The OASB-1 arm cleared the output in its
 * text case, the composite arm and the ordinary arm printed and returned, so
 * `secure <dir> -o out.txt` (with or without `-b`) exited with the report on
 * stdout and no file, nothing said. Now the text format with `-o` exits 1
 * before any scan, and the machine formats still write the file.
 *
 * RED-ON-BASE cells fail on the 044301c5 dist; PIN cells pass on both.
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
let outDir: string;

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-647-'));
  outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-647-out-'));
  fs.writeFileSync(path.join(dir, 'package.json'), '{ "name": "fx647", "version": "1.0.0", "private": true }\n');
  fs.writeFileSync(path.join(dir, 'index.js'), 'module.exports = () => 1;\n');
});

afterAll(() => {
  for (const d of [dir, outDir]) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
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

const REFUSAL = /Error: -o\/--output writes the json, sarif, html, asp and asff reports; the text report prints to stdout\. Use --format json -o /;

const ARMS: Array<{ name: string; args: string[] }> = [
  { name: 'ordinary', args: [] },
  { name: 'OASB-1', args: ['-b', 'oasb-1'] },
  { name: 'OASB-2 composite', args: ['-b', 'oasb-2'] },
];

describe('#647 -o with the text format is refused on every arm', { timeout: 300_000 }, () => {
  for (const arm of ARMS) {
    it(`RED-ON-BASE: ${arm.name} arm, -o with the default text format exits 1 before any scan`, () => {
      const out = path.join(outDir, `${arm.name.replace(/\W+/g, '-')}-default.txt`);
      const r = run([...arm.args, '-o', out]);
      expect(r.status).toBe(1);
      expect(r.stderr).toMatch(REFUSAL);
      expect(r.stdout).not.toMatch(/Scan depth/);
      expect(fs.existsSync(out)).toBe(false);
    });
  }

  it('RED-ON-BASE: an explicit --format text is refused the same way', () => {
    const out = path.join(outDir, 'explicit.txt');
    const r = run(['--format', 'text', '--output', out]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(REFUSAL);
    expect(r.stderr).toContain(`-o ${out}`);
  });

  it('PIN: --format json -o still writes the report to the file', () => {
    const out = path.join(outDir, 'report.json');
    const r = run(['--format', 'json', '-o', out]);
    expect(r.stderr).not.toMatch(REFUSAL);
    expect(r.stderr).toContain(`Report written to ${out}`);
    expect(fs.existsSync(out)).toBe(true);
    expect(() => JSON.parse(fs.readFileSync(out, 'utf8'))).not.toThrow();
  });

  it('PIN: --json -o with -b oasb-2 still writes the composite report', () => {
    const out = path.join(outDir, 'composite.json');
    const r = run(['-b', 'oasb-2', '--json', '-o', out]);
    expect(r.stderr).not.toMatch(REFUSAL);
    expect(fs.existsSync(out)).toBe(true);
  });

  it('PIN: an invalid format keeps its own message when -o rides along', () => {
    const r = run(['--format', 'pdf', '-o', path.join(outDir, 'x.pdf')]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("Error: Invalid format 'pdf'");
    expect(r.stderr).not.toMatch(REFUSAL);
  });

  it('RED-ON-BASE: --help scopes -o to the formats that write it', () => {
    const r = spawnSync(process.execPath, [CLI, 'secure', '--help'], {
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off' },
    });
    const flat = (r.stdout ?? '').replace(/\s+/g, ' ');
    expect(flat).toContain('Write the json, sarif, html, asp or asff report to a file instead of stdout (not with text)');
  });
});
