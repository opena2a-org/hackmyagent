/**
 * #516 — `--static-only` must not reopen the completeness gate #499 closed.
 *
 * Measured on `18da406`, one fixture: a benign `src/util.js`, a benign
 * `src/greet.js` at mode 000, a `.gitignore` and a `package.json`.
 *
 *   --scan-depth quick                   ->  93/100  exit 2   src/greet.js named
 *   --scan-depth quick --static-only     ->  98/100  exit 0   nothing named
 *   --scan-depth standard                ->  88/100  exit 2   src/greet.js named
 *   --scan-depth standard --static-only  ->  88/100  exit 2   src/greet.js named
 *
 * At quick depth the NanoMind semantic layer is the only component that
 * discovers and opens a source file, and `--static-only` turns that layer off,
 * so the unreadable file left no record and the gate had nothing to settle on.
 * At standard depth a static check reads the path itself, which is why that row
 * was already right.
 *
 * The readable half is BENIGN on purpose: a readable file carrying a finding of
 * its own exits non-zero in every cell and cannot show the difference.
 *
 * `chmod 000` does not deny root, so the end-to-end cases probe for real
 * unreadability and skip when they cannot get it. The discovery contract is
 * pinned unconditionally in
 * `__tests__/nanomind-core/static-only-discovery-unread-record.test.ts`.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const CLI = path.join(__dirname, '..', '..', 'dist', 'cli.js');

/** The run did not examine everything it found. */
const EXIT_INCOMPLETE = 2;

const DEPTHS = ['quick', 'standard'] as const;
const MODES: [string, string[]][] = [
  ['default', []],
  ['--static-only', ['--static-only']],
];
const MATRIX: [string, string, string[]][] = DEPTHS.flatMap((depth) =>
  MODES.map(([mode, flags]): [string, string, string[]] => [depth, mode, flags]),
);

let root: string;
/** Paths whose modes must be restored before the tree can be removed. */
const restore: string[] = [];

function secureJson(dir: string, depth: string, flags: string[]) {
  const res = spawnSync(
    process.execPath,
    [CLI, 'secure', dir, '--scan-depth', depth, ...flags, '--format', 'json'],
    {
      encoding: 'utf-8',
      timeout: 240_000,
      env: {
        ...process.env,
        NO_COLOR: '1',
        OPENA2A_TELEMETRY: 'off',
        HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-')),
      },
    },
  );
  const stdout = res.stdout ?? '';
  let body: any = null;
  try {
    body = JSON.parse(stdout.slice(stdout.indexOf('{')));
  } catch {
    body = null;
  }
  const unread: string[] = (body?.findings ?? [])
    .filter((f: any) => f.checkId === 'SCAN-UNREAD-001' && !f.passed)
    .map((f: any) => String(f.file))
    .sort();
  return { status: res.status, body, unread };
}

function makeTree(name: string): string {
  const dir = path.join(root, name);
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'src', 'util.js'), 'export function add(a, b) {\n  return a + b;\n}\n');
  fs.writeFileSync(path.join(dir, 'src', 'greet.js'), 'export function greet(name) {\n  return "Hello, " + name;\n}\n');
  fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n.env\n*.pem\n*.key\n');
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"fx","version":"1.0.0","private":true}\n');
  return dir;
}

/** Make a path unreadable and PROVE it. Returns false when the OS declined. */
function makeUnreadable(file: string): boolean {
  fs.chmodSync(file, 0o000);
  restore.push(file);
  try {
    fs.readFileSync(file);
    return false; // root, or a filesystem without permission support
  } catch {
    return true;
  }
}

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-516-'));
});

afterAll(() => {
  for (const p of restore) {
    try { fs.chmodSync(p, 0o644); } catch { /* already gone */ }
  }
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
});

describe('#516 an unreadable input gates the run with or without --static-only', { timeout: 600_000 }, () => {
  it.each(MATRIX)('%s %s: exits 2 and names src/greet.js', (depth, mode, flags) => {
    const dir = makeTree(`unread-${depth}-${mode.replace(/^-+/, '')}`);
    if (!makeUnreadable(path.join(dir, 'src', 'greet.js'))) {
      console.warn('skipped: this process can read a mode-000 file (running as root?)');
      return;
    }
    const res = secureJson(dir, depth, flags);
    expect(res.body).not.toBeNull();
    expect(res.status).toBe(EXIT_INCOMPLETE);
    expect(res.unread).toEqual([path.join('src', 'greet.js')]);
  }, 240_000);

  it.each(DEPTHS)('%s: --static-only reports the same unread inputs as the default run', (depth) => {
    // A flag that turns an analyzer off may not shrink the set of inputs the
    // run says it discovered and could not read.
    const dir = makeTree(`parity-${depth}`);
    if (!makeUnreadable(path.join(dir, 'src', 'greet.js'))) {
      console.warn('skipped: this process can read a mode-000 file (running as root?)');
      return;
    }
    const withAnalyzer = secureJson(dir, depth, []);
    const staticOnly = secureJson(dir, depth, ['--static-only']);
    expect(withAnalyzer.unread.length).toBeGreaterThan(0);
    expect(staticOnly.unread).toEqual(withAnalyzer.unread);
    expect(staticOnly.body?.coverage?.unreadableInputs).toEqual(withAnalyzer.body?.coverage?.unreadableInputs);
  }, 240_000);

  it.each(MATRIX)('%s %s CONTROL: the same tree fully readable exits 0', (depth, mode, flags) => {
    // Without this the matrix would pass on a change that gated every tree.
    const dir = makeTree(`readable-${depth}-${mode.replace(/^-+/, '')}`);
    const res = secureJson(dir, depth, flags);
    expect(res.body).not.toBeNull();
    expect(res.unread).toEqual([]);
    expect(res.status).toBe(0);
  }, 240_000);
});
