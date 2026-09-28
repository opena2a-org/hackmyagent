/**
 * #648 — the `secure` option gate refuses the flags it used to drop, and the
 * version footer stays off a refused run's stdout.
 *
 * Before:
 *  1. `-l L9` / `-c anything` without `-b` exited 0 with the ordinary report;
 *     nothing reads either flag outside the benchmark arms.
 *  2. `-b oasb-1 -c bogus-cat` was validated inside the report generator,
 *     after the scan had run and printed its header.
 *  3. `--aws-account-id` / `--aws-region` with any format but asff were
 *     dropped without a word.
 *  4. (`--json` with a different `--format` was refused by #605; pinned here.)
 *  5. `Scanned with hackmyagent vX` was printed to stdout under no report on
 *     refused text-mode runs (`-b bogus`, `-l L9`, `--fail-below 200`).
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
const FOOTER = 'Scanned with hackmyagent';

let dir: string;
let outDir: string;

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-648-'));
  outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-648-out-'));
  fs.writeFileSync(path.join(dir, 'package.json'), '{ "name": "fx648", "version": "1.0.0", "private": true }\n');
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

describe('#648 item 1: -l and -c without -b are refused', { timeout: 300_000 }, () => {
  it('RED-ON-BASE: -l L9 without -b exits 1 before any scan', () => {
    const r = run(['-l', 'L9']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('Error: -l/--level is read only in benchmark mode. Add -b oasb-1 or -b oasb-2, or drop the flag.');
    expect(r.stdout).toBe('');
  });

  it('RED-ON-BASE: a valid -l L2 without -b is refused too (nothing reads it)', () => {
    const r = run(['-l', 'L2']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('-l/--level is read only in benchmark mode');
  });

  it('RED-ON-BASE: -c without -b exits 1, and both flags are named together', () => {
    const one = run(['-c', 'anything']);
    expect(one.status).toBe(1);
    expect(one.stderr).toContain('Error: -c/--category is read only in benchmark mode.');
    const both = run(['-l', 'L2', '-c', 'anything']);
    expect(both.status).toBe(1);
    expect(both.stderr).toContain('Error: -l/--level, -c/--category are read only in benchmark mode. Add -b oasb-1 or -b oasb-2, or drop them.');
  });

  it('PIN: without -l the ordinary arm still runs (the Commander default is not a user flag)', () => {
    const r = run(['--format', 'json']);
    expect(r.stderr).not.toContain('read only in benchmark mode');
    expect(r.stdout.trim().startsWith('{')).toBe(true);
  });
});

describe('#648 item 2: an unknown category is refused at the gate', { timeout: 300_000 }, () => {
  it('RED-ON-BASE: -b oasb-1 -c bogus-cat exits 1 before the scan prints anything', () => {
    const r = run(['-b', 'oasb-1', '-c', 'bogus-cat']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("Error: Unknown category 'bogus-cat'.");
    expect(r.stderr).toContain('Available categories: Identity & Provenance, ');
    expect(r.stdout + r.stderr).not.toMatch(/Scan depth/);
    expect(r.stderr).not.toMatch(/Scanning /);
  });

  it('RED-ON-BASE: the composite arm consumes -c too and refuses the same way', () => {
    const r = run(['-b', 'oasb-2', '-c', 'bogus-cat']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("Error: Unknown category 'bogus-cat'.");
    expect(r.stdout + r.stderr).not.toMatch(/Scan depth/);
  });

  it('PIN: a real category, in any case, still runs the benchmark', () => {
    const r = run(['-b', 'oasb-1', '-c', 'credential protection', '--format', 'json']);
    expect(r.stderr).not.toContain('Unknown category');
    expect(r.stdout.trim().startsWith('{')).toBe(true);
  });

  it('PIN: -b oasb-2 -l L9 keeps the level message', () => {
    const r = run(['-b', 'oasb-2', '-l', 'L9']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("Invalid level 'L9'");
  });
});

describe('#648 item 3: --aws-* are refused outside the asff format', { timeout: 300_000 }, () => {
  it('RED-ON-BASE: --aws-region with the text format exits 1 before any scan', () => {
    const r = run(['--aws-region', 'us-east-1']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('Error: --aws-region fills a field of the asff report only. Use --format asff (without -b), or drop the flag.');
    expect(r.stdout).toBe('');
  });

  it('RED-ON-BASE: both --aws-* flags with --format json are named together', () => {
    const r = run(['--format', 'json', '--aws-account-id', '123456789012', '--aws-region', 'us-east-1']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('Error: --aws-account-id, --aws-region fill fields of the asff report only.');
  });

  it('PIN: --format asff with both flags writes them into the findings', () => {
    const out = path.join(outDir, 'report.asff.json');
    const r = run(['--format', 'asff', '--aws-account-id', '123456789012', '--aws-region', 'eu-west-1', '-o', out]);
    expect(r.stderr).not.toContain('of the asff report only');
    const body = fs.readFileSync(out, 'utf8');
    expect(body).toContain('123456789012');
    expect(body).toContain('eu-west-1');
  });
});

describe('#648 item 4 (fixed by #605): --json with a different --format', { timeout: 300_000 }, () => {
  it('PIN: -b oasb-1 --json --format asff is refused, not rendered as json', () => {
    const r = run(['-b', 'oasb-1', '--json', '--format', 'asff']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('--json is shorthand for --format json and contradicts');
  });
});

describe('#648 item 5: the version footer follows a report, never a refusal', { timeout: 300_000 }, () => {
  const refused: Array<{ name: string; args: string[] }> = [
    { name: '-b bogus', args: ['-b', 'bogus'] },
    { name: "-b ''", args: ['-b', ''] },
    { name: '-b oasb-1 -l L9', args: ['-b', 'oasb-1', '-l', 'L9'] },
    { name: '--fail-below 200', args: ['--fail-below', '200'] },
  ];
  for (const c of refused) {
    it(`RED-ON-BASE: ${c.name} leaves stdout empty`, () => {
      const r = run(c.args);
      expect(r.status).toBe(1);
      expect(r.stderr).toMatch(/Error: /);
      expect(r.stdout).not.toContain(FOOTER);
      expect(r.stdout).toBe('');
    });
  }

  it('PIN: a text scan still closes with the footer', () => {
    const r = run([]);
    expect(r.stdout).toContain(FOOTER);
  });
});
