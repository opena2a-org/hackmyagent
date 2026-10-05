/**
 * #360 — a collapsed group in the default report sends the reader to the files
 * its findings are in.
 *
 * Findings that share a name and a directory are folded under the one that is
 * printed. The fold line used to name the PRINTED finding's file, so the same
 * `eval()` in `lib/cbom.js`, `lib/scanner.js` and `lib/scanner-tls.js`
 * rendered as `+ 2 more critical in cbom.js`, measured on `044301c5`. Neither
 * folded finding is in `cbom.js`.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

const FILES = ['cbom', 'scanner', 'scanner-tls'];
const SOURCE = [
  'module.exports = (req) => {',
  '  return eval(req.body.code);',
  '};',
  '',
].join('\n');

let root: string;

beforeAll(() => {
  root = tempDir('hma-360-');
  fs.mkdirSync(path.join(root, 'lib'));
  for (const f of FILES) fs.writeFileSync(path.join(root, 'lib', `${f}.js`), SOURCE);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'hma-360', version: '1.0.0' }));
});

afterAll(() => {
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
});

function run(args: string[]): string {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    cwd: root,
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: tempDir('hma-home-'),
    },
  });
  return `${r.stdout ?? ''}${r.stderr ?? ''}`;
}

describe('#360 secure names the files of a collapsed group', () => {
  it('names the folded files, not the printed finding\'s file', () => {
    const out = run(['secure', '.']);
    const fold = out.split('\n').find((l) => /\+ \d+ more \w+ in /.test(l));
    // Non-vacuity: the three findings must actually have been folded.
    expect(fold, `no collapse line in the report:\n${out}`).toBeDefined();

    const printed = FILES.find((f) => out.includes(`lib/${f}.js:2`));
    expect(printed, 'no eval() finding header was printed').toBeDefined();
    const folded = FILES.filter((f) => f !== printed).map((f) => `${f}.js`);

    const where = /\+ 2 more \w+ in (.+?)\s{2}\(run with --verbose/.exec(fold!);
    expect(where, `unexpected collapse line: ${fold}`).not.toBeNull();
    expect(where![1].split(', ').sort()).toEqual(folded.sort());
  });

  it('--verbose prints every finding the fold stood for', () => {
    const out = run(['secure', '.', '--verbose']);
    for (const f of FILES) expect(out).toContain(`lib/${f}.js:2`);
  });
});
