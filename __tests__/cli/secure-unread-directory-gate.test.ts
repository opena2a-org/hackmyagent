/**
 * `secure` must not report a passing verdict over a directory it could list but
 * not enter (#515) — the #438 gate, one `chmod` over from the file case #499
 * closed.
 *
 * Measured on `0e0cecf` (0.32.0 plus the #499/#508 work), one fixture and one
 * `chmod`. The tree holds a benign `util.js`, a `.gitignore`, a `package.json`
 * and `cfg/secrets.js` containing an `sk-` API key:
 *
 *   cfg/ mode 755, quick     ->  69/100  exit 1   (the credential is found)
 *   cfg/ mode 600, quick     ->  98/100  exit 0   (nothing about cfg/ at all)
 *   cfg/ mode 600, standard  ->  93/100  exit 2   (a static check's readFile
 *                                                   recorded it — quick has no
 *                                                   such reader)
 *
 * Mode 600 on a directory is readable but not traversable: `readdir` lists
 * `secrets.js`, then `stat` and `readFile` on it reject `EACCES`. The semantic
 * walker's size gate swallowed that rejection, so a file the scan had already
 * DISCOVERED left the assessment with no ledger record and no finding. The score
 * went UP because coverage went DOWN.
 *
 * ## Why this suite is shaped the way it is
 *
 * Every gate assertion is paired with a control, because a gate that fires on
 * everything is not a gate: the SAME tree traversable must keep exit 1, and the
 * readable half is BENIGN on purpose — a readable half carrying a finding of its
 * own would exit 1 either way and every exit-code assertion here would pass
 * without the gate existing at all. The `.gitignore` is present so GIT-001's
 * `walkComplete` escalation cannot supply the non-zero exit for us.
 *
 * `chmod` does not deny root, so the suite probes for real non-traversability
 * and skips when it cannot get it. The ledger-level rule is pinned
 * unconditionally in `__tests__/nanomind-core/discover-files-unread-record.test.ts`.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { TestContext } from 'vitest';
import { execSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const CLI = path.join(__dirname, '..', '..', 'dist', 'cli.js');

/** Measured, and the result is one the command promises to fail on. */
const EXIT_FAIL = 1;
/** The run did not examine everything it found. */
const EXIT_INCOMPLETE = 2;

const SK_KEY = `sk-proj-${'A'.repeat(48)}`;

let root: string;
/** Paths whose modes must be restored before the tree can be removed. */
const restore: Array<{ p: string; mode: number }> = [];

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
  // `stdout` is the machine channel: the JSON parse reads it alone, so a
  // load-induced stderr byte cannot corrupt the body (HMA-28). The merged
  // `out` stays for text assertions that want the message on either channel.
  return { status: res.status, stdout: res.stdout ?? '', out: `${res.stdout ?? ''}${res.stderr ?? ''}` };
}

/**
 * The OS would not deny access to this process (root, or a filesystem without
 * permission bits): there is nothing to test, and a silent green here reads as
 * coverage that does not exist. Skip, loudly.
 */
function osDeclined(ctx: TestContext): never {
  console.warn('[secure-unread-directory-gate] the OS declined to deny access to this process (root?): SKIPPING, not passing');
  ctx.skip();
  throw new Error('unreachable: ctx.skip() throws');
}

function json(args: string[]) {
  const res = run([...args, '--json']);
  try {
    return { status: res.status, body: JSON.parse(res.stdout.slice(res.stdout.indexOf('{'))) as any };
  } catch {
    return { status: res.status, body: null as any };
  }
}

/**
 * Build the fixture. The readable half is BENIGN and carries a `.gitignore`;
 * see the header for why both matter.
 */
function makeTree(name: string): string {
  const dir = path.join(root, name);
  fs.mkdirSync(path.join(dir, 'cfg'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'util.js'), 'function add(a,b){return a+b;}\nmodule.exports={add};\n');
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"fx515","version":"1.0.0"}\n');
  fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n.env\n*.pem\n*.key\n');
  fs.writeFileSync(path.join(dir, 'cfg', 'secrets.js'), `const K = "${SK_KEY}";\nmodule.exports={K};\n`);
  return dir;
}

/**
 * Make a directory listable but not traversable, and PROVE it: the child must
 * still be listed and its `stat` must reject. Returns false when the OS
 * declined (root, or a filesystem without permission support).
 */
function makeNonTraversable(dir: string, child: string): boolean {
  fs.chmodSync(dir, 0o600);
  restore.push({ p: dir, mode: 0o755 });
  try {
    const listed = fs.readdirSync(dir).includes(child);
    if (!listed) return false;
    fs.statSync(path.join(dir, child));
    return false; // stat succeeded: nothing is being denied
  } catch {
    return true;
  }
}

/** Make a file unreadable and PROVE it. */
function makeUnreadable(file: string): boolean {
  fs.chmodSync(file, 0o000);
  restore.push({ p: file, mode: 0o644 });
  try {
    fs.readFileSync(file);
    return false;
  } catch {
    return true;
  }
}

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-515-'));
});

afterAll(() => {
  // Restore BEFORE removing, or the tree cannot be removed. In afterAll rather
  // than a try/finally in the test body: a vitest timeout skips a `finally`.
  for (const { p, mode } of restore) {
    try { fs.chmodSync(p, mode); } catch { /* already gone */ }
  }
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
});

describe('#515 secure over a directory it can list but not enter', () => {
  it('control: the same tree traversable finds the credential and exits 1 at quick depth', () => {
    const dir = makeTree('control');
    const res = json(['secure', dir, '--scan-depth', 'quick']);
    expect(res.body).not.toBeNull();
    expect(res.status).toBe(EXIT_FAIL);
    expect(res.body.coverage.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
    expect(res.body.findings.some((f: any) => /^AST-CRED-/.test(f.checkId) && f.file === 'cfg/secrets.js')).toBe(true);
  }, 300_000);

  it('quick depth: a listed-but-unstattable file is an unread input — exit 2, counted, named', (ctx: TestContext) => {
    const dir = makeTree('dir600-quick');
    if (!makeNonTraversable(path.join(dir, 'cfg'), 'secrets.js')) osDeclined(ctx);

    const res = json(['secure', dir, '--scan-depth', 'quick']);
    expect(res.body).not.toBeNull();
    expect(res.status).toBe(EXIT_INCOMPLETE);

    // Counted on the same channel a failed readFile uses.
    expect(res.body.coverage.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 0 });

    // Named, with the file the walker discovered — not the directory, not a
    // count. The path is what the user acts on.
    const unread = res.body.findings.filter((f: any) => f.checkId === 'SCAN-UNREAD-001');
    expect(unread.map((f: any) => f.file)).toEqual(['cfg/secrets.js']);

    // The credential was NOT read, so no credential finding may claim it was.
    expect(res.body.findings.some((f: any) => /^AST-CRED-/.test(f.checkId))).toBe(false);

    // The remedy is on the DIRECTORY. `chmod u+r cfg/secrets.js` fails with
    // the same EACCES the scan did (measured: "Permission denied"), so a
    // finding printing it would be a dead end in exactly this case.
    expect(unread[0].fix).toMatch(/^chmod u\+x cfg && /);
    expect(unread[0].fix).not.toContain('u+r');
    expect(unread[0].guidance).toContain('can be listed but not entered');
  }, 300_000);

  it('the printed remedy runs and clears the obstruction', (ctx: TestContext) => {
    const dir = makeTree('dir600-remedy');
    if (!makeNonTraversable(path.join(dir, 'cfg'), 'secrets.js')) osDeclined(ctx);

    const res = json(['secure', dir, '--scan-depth', 'quick']);
    expect(res.body).not.toBeNull();
    const unread = res.body.findings.find((f: any) => f.checkId === 'SCAN-UNREAD-001');
    expect(unread).toBeDefined();
    // Run the chmod clause exactly as printed, from the target directory the
    // citation is relative to. A remedy that cannot run is a dead end.
    const clause = String(unread.fix).split(' && ')[0];
    const m = /^chmod u\+x (\S+)$/.exec(clause);
    expect(m).not.toBeNull();
    const ran = spawnSync('chmod', ['u+x', m![1]], { cwd: dir, encoding: 'utf-8' });
    expect(ran.status).toBe(0);
    // The obstruction is gone: the child is now stat-able, and a re-run finds
    // the credential the first run could not reach.
    expect(() => fs.statSync(path.join(dir, 'cfg', 'secrets.js'))).not.toThrow();
    const again = json(['secure', dir, '--scan-depth', 'quick']);
    expect(again.status).toBe(EXIT_FAIL);
    expect(again.body.coverage.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
  }, 300_000);

  it('the text channel leads with the unread input rather than a clean verdict', (ctx: TestContext) => {
    const dir = makeTree('dir600-text');
    if (!makeNonTraversable(path.join(dir, 'cfg'), 'secrets.js')) osDeclined(ctx);

    const res = run(['secure', dir, '--scan-depth', 'quick']);
    expect(res.status).toBe(EXIT_INCOMPLETE);
    expect(res.out).toMatch(/cfg\/secrets\.js/);
    // The verdict names the incompleteness; on the base build this line read
    // "Usable with caveats" with no mention of the file.
    expect(res.out).toMatch(/Not Read/);
  }, 300_000);

  it('standard depth still exits 2 (the static reader recorded it before; the walker now agrees)', (ctx: TestContext) => {
    const dir = makeTree('dir600-standard');
    if (!makeNonTraversable(path.join(dir, 'cfg'), 'secrets.js')) osDeclined(ctx);

    const res = json(['secure', dir, '--scan-depth', 'standard']);
    expect(res.body).not.toBeNull();
    expect(res.status).toBe(EXIT_INCOMPLETE);
    // ONE record for one file, although two readers (static readFile and the
    // semantic walker's stat) both failed on it: the ledger dedups by path.
    expect(res.body.coverage.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 0 });
    expect(res.body.findings.filter((f: any) => f.checkId === 'SCAN-UNREAD-001')).toHaveLength(1);
  }, 300_000);

  it('parity: chmod 600 on the directory and chmod 000 on the file produce the same exit code at quick depth', (ctx: TestContext) => {
    const viaDir = makeTree('parity-dir');
    const viaFile = makeTree('parity-file');
    if (!makeNonTraversable(path.join(viaDir, 'cfg'), 'secrets.js')) osDeclined(ctx);
    if (!makeUnreadable(path.join(viaFile, 'cfg', 'secrets.js'))) osDeclined(ctx);

    const a = json(['secure', viaDir, '--scan-depth', 'quick']);
    const b = json(['secure', viaFile, '--scan-depth', 'quick']);
    expect(a.body).not.toBeNull();
    expect(b.body).not.toBeNull();
    expect(a.status).toBe(EXIT_INCOMPLETE);
    expect(a.status).toBe(b.status);
    expect(a.body.coverage.unreadableInputs).toEqual(b.body.coverage.unreadableInputs);
    // Same gate, different cause, different remedy: the directory case names
    // the directory; the file case keeps `chmod u+r <file>`.
    const fixOf = (r: any) => r.body.findings.find((f: any) => f.checkId === 'SCAN-UNREAD-001').fix;
    expect(fixOf(a)).toMatch(/^chmod u\+x cfg && /);
    expect(fixOf(b)).toMatch(/^chmod u\+r cfg\/secrets\.js && /);
  }, 300_000);

  it('check <local path>: the same record through the same builder, with the same directory remedy', (ctx: TestContext) => {
    const dir = makeTree('via-check');
    if (!makeNonTraversable(path.join(dir, 'cfg'), 'secrets.js')) osDeclined(ctx);

    const res = json(['check', dir, '--offline']);
    expect(res.body).not.toBeNull();
    expect(res.status).toBe(EXIT_INCOMPLETE);
    expect(res.body.coverage.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 0 });
    const unread = (res.body.details ?? []).filter((f: any) => f.checkId === 'SCAN-UNREAD-001');
    expect(unread.map((f: any) => f.file)).toEqual(['cfg/secrets.js']);
    // The remedy names the DIRECTORY and re-runs the command the user ran —
    // `chmod u+r cfg/secrets.js` is a dead end here (same EACCES the scan got),
    // and until this cell existed the check arm printed exactly that.
    expect(unread[0].fix).toMatch(/^chmod u\+x cfg && /);
    expect(unread[0].fix).toContain(' check ');
    expect(unread[0].fix).not.toContain('chmod u+r ');

    // The printed clause runs, and the re-run no longer reports an unread input.
    execSync(unread[0].fix.split(' && ')[0], { cwd: dir });
    const after = json(['check', dir, '--offline']);
    expect(after.body).not.toBeNull();
    expect(after.body.coverage.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
    expect(after.status).not.toBe(EXIT_INCOMPLETE);
  }, 300_000);
});
