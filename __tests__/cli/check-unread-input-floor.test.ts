/**
 * #508 — `check <local path>` over a tree holding an input it could not read.
 *
 * Before: the unreadable file left BOTH sides of the coverage fraction
 * (`examined 1 / total 1`), `measured: true` asserted a complete run, and the
 * command exited 0 — chmod 000 on a credential file was a one-command bypass.
 * After: the run keeps its band over what it read, the record carries the
 * denominator, and the exit code is 2 unless a high or critical band already
 * settled 1. A target FILE that itself cannot be read is unmeasured rather
 * than reported on its readable sibling.
 *
 * `chmod 000` does not deny root, so every case proves unreadability first and
 * skips with a warning when it cannot get it. The exit-code cells are red on
 * the build before the fix.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const EXIT_PASS = 0;
const EXIT_FAIL = 1;
const EXIT_UNMEASURED = 2;

let root: string;
const restore: string[] = [];

function run(args: string[]) {
  const res = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 240_000,
    env: {
      ...process.env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-')),
    },
  });
  return { status: res.status, out: `${res.stdout ?? ''}${res.stderr ?? ''}`, stdout: res.stdout ?? '' };
}

function json(args: string[]) {
  const res = run([...args, '--json']);
  return { status: res.status, body: JSON.parse(res.stdout.slice(res.stdout.indexOf('{'))) as any };
}

/** Two benign sources, a package.json and a .gitignore — nothing to find. */
function tree(name: string): string {
  const dir = path.join(root, name);
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n.env\n*.pem\n*.key\n');
  fs.writeFileSync(path.join(dir, 'package.json'), '{ "name": "fx508", "version": "1.0.0", "private": true }\n');
  fs.writeFileSync(path.join(dir, 'src', 'util.js'), 'function add(a,b){return a+b;}\nmodule.exports={add};\n');
  fs.writeFileSync(path.join(dir, 'src', 'greet.js'), 'module.exports = (n) => `hi ${n}`;\n');
  return dir;
}

/** Make a path unreadable and PROVE it. Returns false when the OS declined. */
function makeUnreadable(file: string): boolean {
  fs.chmodSync(file, 0o000);
  restore.push(file);
  try {
    fs.readFileSync(file);
    return false;
  } catch {
    return true;
  }
}

let unreadable = false;
function cannotProbe(): boolean {
  if (!unreadable) console.warn('skipped: this process can read a mode-000 file (running as root?)');
  return !unreadable;
}

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-508-'));
  const probe = path.join(root, 'probe');
  fs.writeFileSync(probe, 'x');
  unreadable = makeUnreadable(probe);
});

afterAll(() => {
  for (const p of restore) {
    try { fs.chmodSync(p, 0o644); } catch { /* already gone */ }
  }
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
});

describe('#508 check settles a floor over a tree it could not fully read', () => {
  it('CONTROL: the fully readable tree is measured completely and exits 0', () => {
    const { status, body } = json(['check', tree('clean')]);
    expect(status).toBe(EXIT_PASS);
    expect(body.measured).toBe(true);
    expect(body.coverage.examined).toBe(body.coverage.total);
    expect(body.coverage.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
  });

  it('--json: one unread input puts the file on the denominator, keeps the band, and exits 2', () => {
    if (cannotProbe()) return;
    const dir = tree('mixed');
    makeUnreadable(path.join(dir, 'src', 'greet.js'));
    const { status, body } = json(['check', dir]);
    expect(status).toBe(EXIT_UNMEASURED);
    expect(body.measured).toBe(true);
    expect(body.risk).not.toBeNull();
    expect(body.coverage.total).toBe(body.coverage.examined + 1);
    expect(body.coverage.unreadableInputs.count).toBe(1);
    expect(body.coverage.unreadableInputs.codes.EACCES).toBe(1);
    // #508 wiring — the record is not only counted: each unread path carries
    // its own SCAN-UNREAD-001 finding through the same builder `secure` uses,
    // and the remedy re-runs THIS command, not `secure`.
    const unread = (body.details ?? []).filter((f: any) => f.checkId === 'SCAN-UNREAD-001');
    expect(unread).toHaveLength(1);
    expect(unread[0].file).toBe('src/greet.js');
    expect(unread[0].fix).toContain('check');
    expect(unread[0].fix).not.toContain('secure');
  });

  it('a .hmaignore path rule cannot scope the unread disclosure away — the carve-out secure ships', () => {
    if (cannotProbe()) return;
    const dir = tree('scoped');
    fs.writeFileSync(path.join(dir, '.hmaignore'), 'src/\n');
    makeUnreadable(path.join(dir, 'src', 'greet.js'));
    const { status, body } = json(['check', dir]);
    expect(status).toBe(EXIT_UNMEASURED);
    const unread = (body.details ?? []).filter((f: any) => f.checkId === 'SCAN-UNREAD-001');
    expect(unread).toHaveLength(1);
    const scoped = (body.outOfScope ?? []).filter((f: any) => f.checkId === 'SCAN-UNREAD-001');
    expect(scoped).toHaveLength(0);
  });

  it('an explicit !SCAN-UNREAD-001 check rule suppresses the finding; the exit floor reads the record', () => {
    if (cannotProbe()) return;
    const dir = tree('checkid');
    fs.writeFileSync(path.join(dir, '.hmaignore'), '!SCAN-UNREAD-001\n');
    makeUnreadable(path.join(dir, 'src', 'greet.js'));
    const { status, body } = json(['check', dir]);
    expect(status).toBe(EXIT_UNMEASURED);
    const unread = (body.details ?? []).filter((f: any) => f.checkId === 'SCAN-UNREAD-001');
    expect(unread).toHaveLength(0);
  });

  it('text: the header carries the denominator and the unread path is named with a runnable check', () => {
    if (cannotProbe()) return;
    const dir = tree('mixed-text');
    makeUnreadable(path.join(dir, 'src', 'greet.js'));
    const { status, out } = run(['check', dir]);
    expect(status).toBe(EXIT_UNMEASURED);
    expect(out).toMatch(/\d+ of \d+ files analyzed · 1 could not be read/);
    expect(out).toContain('Not read');
    expect(out).toContain('src/greet.js');
    expect(out).toContain('(EACCES)');
    expect(out).toContain('upper bound');
    expect(out).toMatch(/Verify: ls -l /);
    // #508 wiring — the per-path finding renders on the text channel too.
    expect(out).toContain('Input Discovered But Not Read');
    // The band is still printed: withholding it would hand one file the
    // power to blank the assessment.
    expect(out).toMatch(/Quick scan/);
  });

  it('a found credential beside the unread file still exits 1: it outranks the unread input', () => {
    if (cannotProbe()) return;
    const dir = tree('token');
    fs.writeFileSync(path.join(dir, 'src', 'token.js'), `const T = "ghp_${'a'.repeat(36)}";\nmodule.exports={T};\n`);
    makeUnreadable(path.join(dir, 'src', 'greet.js'));
    const { status, body } = json(['check', dir]);
    expect(status).toBe(EXIT_FAIL);
    expect(['high', 'critical']).toContain(body.risk);
    expect(body.coverage.unreadableInputs.count).toBe(1);
  });

  it('a target FILE that cannot itself be read is unmeasured, not reported on its readable sibling', () => {
    if (cannotProbe()) return;
    const dir = tree('target');
    const file = path.join(dir, 'src', 'greet.js');
    makeUnreadable(file);
    const { status, body } = json(['check', file]);
    expect(status).toBe(EXIT_UNMEASURED);
    expect(body.coverage.measured).toBe(false);
    expect(body.coverage.reason).toBe('target-unreadable');
    // The target-unreadable arm builds this record itself in `src/cli.ts`; it
    // gains `directories: 0` with that arm's edit (#588 rendering set), not here.
    expect(body.coverage.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 } });
    const text = run(['check', file]);
    expect(text.status).toBe(EXIT_UNMEASURED);
    expect(text.out).toContain('NOT MEASURED');
    expect(text.out).toContain('(EACCES)');
    expect(text.out).toMatch(/Verify: ls -l /);
  });

  it('--help names the third cause of exit 2', () => {
    const { status, out } = run(['check', '--help']);
    expect(status).toBe(0);
    expect(out).toContain('not measured, or not completely measured');
    expect(out).toContain('could not be read');
  });
});
