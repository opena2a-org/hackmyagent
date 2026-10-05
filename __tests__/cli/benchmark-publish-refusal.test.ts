/**
 * #646 — the publish and contribute flags are refused with `-b`.
 *
 * Before: both benchmark arms of `secure` return before the publish and
 * contribute steps run, so `--publish`, `--ci-publish`, `--registry-report`,
 * `--version-id` and `--contribute` were accepted with `-b oasb-1|oasb-2`
 * and dropped: no attempt, no `publish` key in the json document, nothing on
 * stderr, exit 0 or the benchmark verdict. Now each is refused where the
 * other `-b` flag errors are raised, before any scan runs.
 *
 * RED-ON-BASE cells fail on the 044301c5 dist; PIN cells pass on both.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

// A registry URL nothing listens on: if a flag is ever honoured instead of
// refused, the attempt fails fast and locally rather than reaching a service.
const OFFLINE = ['--registry-url', 'http://localhost:9'];
const QUICK = ['--scan-depth', 'quick', '--no-machine-posture'];

let dir: string;

beforeAll(() => {
  dir = tempDir('hma-646-');
  fs.writeFileSync(path.join(dir, 'package.json'), '{ "name": "fx646", "version": "1.0.0", "private": true }\n');
  fs.writeFileSync(path.join(dir, 'index.js'), 'module.exports = () => 1;\n');
});

afterAll(() => {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
});

function run(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, 'secure', dir, ...args, ...OFFLINE, ...QUICK], {
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: tempDir('hma-home-') },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

const REFUSAL = /not available with -b .*a benchmark run sends nothing to the Registry\. Run secure without -b/;

const FLAGS: Array<{ flag: string; args: string[] }> = [
  { flag: '--publish', args: ['--publish'] },
  { flag: '--ci-publish', args: ['--ci-publish'] },
  { flag: '--registry-report', args: ['--registry-report'] },
  { flag: '--version-id', args: ['--version-id', 'v-646'] },
  { flag: '--contribute', args: ['--contribute'] },
];

describe('#646 publish and contribute flags are refused with -b', { timeout: 300_000 }, () => {
  for (const { flag, args } of FLAGS) {
    it(`RED-ON-BASE: -b oasb-1 ${flag} exits 1 naming the flag, and no report is printed`, () => {
      const r = run(['-b', 'oasb-1', '--format', 'json', ...args]);
      expect(r.status).toBe(1);
      expect(r.stderr).toMatch(REFUSAL);
      expect(r.stderr).toContain(`Error: ${flag} is not available with -b oasb-1`);
      expect(r.stdout.trim()).toBe('');
    });
  }

  it('RED-ON-BASE: the composite arm refuses too, and names the benchmark as typed', () => {
    const r = run(['-b', 'OASB-2', '--publish']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('Error: --publish is not available with -b OASB-2');
    expect(r.stdout).not.toMatch(/Scan depth/);
  });

  it('RED-ON-BASE: several dropped flags are named in one line', () => {
    const r = run(['-b', 'oasb-1', '--publish', '--contribute']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('Error: --publish, --contribute are not available with -b oasb-1');
  });

  it('PIN: --no-contribute asks for what a benchmark run already does and is accepted', () => {
    const r = run(['-b', 'oasb-1', '--format', 'json', '--no-contribute']);
    expect(r.stderr).not.toMatch(REFUSAL);
    expect(r.stdout).toMatch(/"benchmark"\s*:/);
  });

  it('PIN: a format the arm cannot render keeps its own message when a dropped flag rides along', () => {
    const r = run(['-b', 'oasb-2', '--format', 'sarif', '--publish']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('Error: --format sarif is not available with -b oasb-2. Use: text, json');
    expect(r.stderr).not.toMatch(REFUSAL);
  });

  it('RED-ON-BASE: --help qualifies each refused flag', () => {
    const r = spawnSync(process.execPath, [CLI, 'secure', '--help'], {
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off' },
    });
    const help = r.stdout ?? '';
    for (const { flag } of FLAGS) {
      const line = help.split('\n').find((l) => l.trimStart().startsWith(flag + ' ') || l.trimStart().startsWith(flag + ','));
      expect(line, `${flag} line in secure --help`).toBeDefined();
    }
    const flat = help.replace(/\s+/g, ' ');
    expect(flat).toContain('Push scan results to the OpenA2A Registry (not with -b)');
    expect(flat).toContain('Registry version ID to report against (not with -b)');
    expect(flat).toContain('(overrides config; not with -b)');
  });
});
