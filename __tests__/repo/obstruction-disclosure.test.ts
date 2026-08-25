/**
 * #588 — a directory the scan cannot list is disclosed, on every channel,
 * on both arms, at every depth. The fault-injection matrix for the directory
 * kind of unread input, and the acceptance rows the unit ships against.
 *
 * Obstructions (real modes, precondition PROVEN per cell, loud skip when the
 * OS declines to deny — root, or a filesystem without permission bits):
 *   - `chmod 000 cfg/` with a credential file inside it;
 *   - `chmod 000 cfg/` nested two deep (`lib/cfg/`);
 *   - `chmod 600 a/` with the file at `a/b/c/secrets.js` — `a/` lists, `a/b/`
 *     cannot be entered, so the lost input is the DIRECTORY `a/b/` and the
 *     remedy is on `a/` (#515 shape, the directory kind);
 *   - `chmod 000 <root>` — the scan target itself.
 * Arms: `secure --scan-depth quick`, `secure` (standard), `check --offline`.
 * Channels: `--json` (all), text (all), SARIF and `--ci` (`secure` only —
 * `check` offers neither flag; those cells are "channel not offered", not a
 * silent skip).
 *
 * Pinned per cell: exit 2 (the unread-input floor; a critical/high over what
 * WAS read still wins with 1, which is why every fixture's readable half is
 * benign); `coverage.unreadableInputs.count > 0` and `.directories >= 1`, never
 * an estimate of what the directory hid; one `SCAN-UNREAD-001` naming the
 * directory with a trailing separator, `fixable: false`, kind `directory`;
 * `score(T + O) <= score(T)`.
 *
 * Mutation pins: the root is ONE finding, not one per probe; files inside the
 * lost directory leave `count` unchanged; the cause split holds in BOTH
 * directions (an unlistable directory never escalates GIT-001/GIT-002; the
 * depth bound still does — pinned in `__tests__/hardening/scanner.test.ts`);
 * the printed remedy runs as printed and clears in ONE step with no second
 * finding carrying a different remedy; `secure --fix` does not reach exit 0
 * over an unread input; and the direction row — `secure` and `check` agree.
 *
 * Text-channel wording that `src/cli.ts` renders (the `Not listed <dir>/`
 * line and the header that must not fold a directory into a files count) is
 * pinned here as todo cells until that edit lands; they are not skipped.
 */
import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import type { TestContext } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const CLI = path.join(__dirname, '..', '..', 'dist', 'cli.js');
const EXIT_INCOMPLETE = 2;
const SK_KEY = `sk-proj-${'A'.repeat(48)}`;

let root: string;
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
  return { status: res.status, out: `${res.stdout ?? ''}${res.stderr ?? ''}` };
}

function json(args: string[]) {
  const res = run([...args, '--json']);
  try {
    return { status: res.status, body: JSON.parse(res.out.slice(res.out.indexOf('{'))) as any };
  } catch {
    return { status: res.status, body: null as any };
  }
}

function osDeclined(ctx: TestContext): never {
  console.warn('[obstruction-disclosure] the OS declined to deny access to this process (root?): SKIPPING, not passing');
  ctx.skip();
  throw new Error('unreachable: ctx.skip() throws');
}

/** A benign readable half with a complete `.gitignore`, and `cfg/secrets.js`. */
function makeTree(name: string, opts: { gitignore?: boolean; nestedUnder?: string; credential?: boolean } = {}): string {
  const dir = path.join(root, armTag ? `${armTag}-${name}` : name);
  const cfgParent = opts.nestedUnder ? path.join(dir, opts.nestedUnder) : dir;
  fs.mkdirSync(path.join(cfgParent, 'cfg'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'util.js'), 'function add(a,b){return a+b;}\nmodule.exports={add};\n');
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"fx588","version":"1.0.0"}\n');
  if (opts.gitignore !== false) {
    fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n.env\nsecrets.json\n*.pem\n*.key\n');
  }
  if (opts.credential !== false) {
    fs.writeFileSync(path.join(cfgParent, 'cfg', 'secrets.js'), `const K = "${SK_KEY}";\nmodule.exports={K};\n`);
  }
  return dir;
}

/** `chmod 000` a directory and PROVE it cannot be listed. */
function makeUnlistable(dir: string): boolean {
  fs.chmodSync(dir, 0o000);
  restore.push({ p: dir, mode: 0o755 });
  try {
    fs.readdirSync(dir);
    return false; // listed: nothing is being denied
  } catch {
    return true;
  }
}

/** `chmod 600` a directory and PROVE it lists but cannot be entered. */
function makeNonTraversable(dir: string, child: string): boolean {
  fs.chmodSync(dir, 0o600);
  restore.push({ p: dir, mode: 0o755 });
  try {
    if (!fs.readdirSync(dir).includes(child)) return false;
    fs.statSync(path.join(dir, child));
    return false;
  } catch {
    return true;
  }
}

function unreadFindings(body: any): any[] {
  const list: any[] = Array.isArray(body?.findings) ? body.findings : (body?.details ?? []);
  return list.filter((f) => f.checkId === 'SCAN-UNREAD-001');
}

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-588-'));
});

/** Every cell restores its own modes, so no fixture blocks another arm's `mkdir` or the final `rm`. */
afterEach(() => {
  for (const { p, mode } of restore.splice(0).reverse()) {
    try { fs.chmodSync(p, mode); } catch { /* already gone */ }
  }
});

afterAll(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

let armTag = '';

const ARMS: Array<{ name: string; args: string[]; secure: boolean }> = [
  { name: 'secure quick', args: ['secure', '--scan-depth', 'quick'], secure: true },
  { name: 'secure standard', args: ['secure', '--scan-depth', 'standard'], secure: true },
  { name: 'check', args: ['check', '--offline'], secure: false },
];

describe('#588 a directory the scan cannot list is an unread input on every channel', { timeout: 300_000 }, () => {
  describe.each(ARMS)('$name', { timeout: 300_000 }, ({ name, args, secure }) => {
    beforeEach(() => { armTag = name.replace(/\s+/g, '-'); });

    it('control: the same tree listable exits on its findings and records nothing unread', () => {
      const dir = makeTree('control');
      const res = json([...args, dir]);
      expect(res.body).not.toBeNull();
      expect(res.body.coverage.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
      expect(res.status).not.toBe(EXIT_INCOMPLETE);
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it('mode-000 cfg/: exit 2, one directory record, the directory named with a trailing separator, u+rx remedy', (ctx) => {
      const dir = makeTree('d000');
      if (!makeUnlistable(path.join(dir, 'cfg'))) osDeclined(ctx);
      // The obstruction hides the credential, so against a control that READS
      // it the score must go up — that is #438's phenomenon, and the record is
      // the disclosure of it. The bound the ruling pins is against the same
      // tree with nothing hidden: an obstruction never scores ABOVE the benign
      // tree it obstructs.
      const control = json([...args, makeTree('d000-control', { credential: false })]);
      const res = json([...args, dir]);
      expect(res.body).not.toBeNull();
      expect(res.status).toBe(EXIT_INCOMPLETE);
      expect(res.body.coverage.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 1 });
      const unread = unreadFindings(res.body);
      expect(unread).toHaveLength(1);
      expect(unread[0].file).toBe('cfg/');
      expect(unread[0].kind).toBe('directory');
      expect(unread[0].fixable).toBe(false);
      expect(unread[0].severity).toBe('medium');
      expect(unread[0].message).toBe('cfg/ could not be listed (EACCES) — its contents were not discovered, so nothing inside it reached any check.');
      expect(unread[0].fix.startsWith('chmod u+rx cfg && ')).toBe(true);
      expect(unread[0].fix).toContain(secure ? 'hackmyagent secure ' : 'hackmyagent check ');
      expect(unread[0].fix).not.toContain('chmod u+r ');
      if (secure) {
        // An obstruction may not raise the score above the unobstructed benign
        // tree: the score is an upper bound, not a measurement.
        expect(res.body.score).toBeLessThanOrEqual(control.body.score);
        // Cause split: the unlistable directory does not escalate GIT-002.
        const git002 = res.body.findings.find((f: any) => f.checkId === 'GIT-002');
        if (git002) {
          expect(git002.severity).toBe('low');
          expect(git002.description).toContain('SCAN-UNREAD-001');
        }
        const cred002 = res.body.findings.find((f: any) => f.checkId === 'CRED-002');
        expect(cred002?.severity).not.toBe('high');
      }
    });

    it('mode-000 cfg/ nested two deep is named by its full relative path', (ctx) => {
      const dir = makeTree('nested000', { nestedUnder: 'lib' });
      if (!makeUnlistable(path.join(dir, 'lib', 'cfg'))) osDeclined(ctx);
      const res = json([...args, dir]);
      expect(res.status).toBe(EXIT_INCOMPLETE);
      expect(res.body.coverage.unreadableInputs.directories).toBe(1);
      const unread = unreadFindings(res.body);
      expect(unread.map((f) => f.file)).toEqual([path.join('lib', 'cfg') + '/']);
      expect(unread[0].fix.startsWith(`chmod u+rx ${path.join('lib', 'cfg')} && `)).toBe(true);
    });

    it('mode-600 a/ with the file at a/b/c/: the lost input is the directory a/b/, the remedy is on a/', (ctx) => {
      const dir = path.join(root, `${armTag}-nested600`);
      fs.mkdirSync(path.join(dir, 'a', 'b', 'c'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'util.js'), 'module.exports={};\n');
      fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"fx588n","version":"1.0.0"}\n');
      fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n.env\nsecrets.json\n*.pem\n*.key\n');
      fs.writeFileSync(path.join(dir, 'a', 'b', 'c', 'secrets.js'), `const K = "${SK_KEY}";\n`);
      if (!makeNonTraversable(path.join(dir, 'a'), 'b')) osDeclined(ctx);
      const res = json([...args, dir]);
      expect(res.status).toBe(EXIT_INCOMPLETE);
      expect(res.body.coverage.unreadableInputs.count).toBeGreaterThanOrEqual(1);
      expect(res.body.coverage.unreadableInputs.directories).toBeGreaterThanOrEqual(1);
      const unread = unreadFindings(res.body);
      const lost = unread.find((f) => f.file === path.join('a', 'b') + '/');
      expect(lost).toBeDefined();
      expect(lost.kind).toBe('directory');
      // `a/` lists fine, so it is not an obstruction the ledger observed and
      // is not what the record names; it IS the directory this user cannot
      // enter, so the remedy names it (#515 shape).
      expect(lost.fix.startsWith('chmod u+x a && ')).toBe(true);
      expect(lost.guidance).toContain('the remedy is on `a`');
      expect(lost.guidance).not.toMatch(/\bfiles?\b/i);
    });

    it('the scan root itself at mode 000 is ONE record named `./`, not one per probe', (ctx) => {
      const dir = makeTree('root000');
      if (!makeUnlistable(dir)) osDeclined(ctx);
      const res = json([...args, dir]);
      expect(res.status).toBe(EXIT_INCOMPLETE);
      expect(res.body.coverage.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 1 });
      const unread = unreadFindings(res.body);
      expect(unread).toHaveLength(1);
      expect(unread[0].file).toBe('./');
      // The operand is the absolute target: the printed clause must do the same
      // thing from any cwd, and `.` would not.
      expect(unread[0].fix.startsWith(`chmod u+rx ${dir} && `)).toBe(true);
    });

    it('files hidden inside the lost directory never change the count — one obstruction is one unit', (ctx) => {
      const dir = makeTree('d000-many');
      for (let i = 0; i < 12; i++) fs.writeFileSync(path.join(dir, 'cfg', `k${i}.pem`), 'x');
      if (!makeUnlistable(path.join(dir, 'cfg'))) osDeclined(ctx);
      const res = json([...args, dir]);
      expect(res.status).toBe(EXIT_INCOMPLETE);
      expect(res.body.coverage.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 1 });
    });

    it('the printed remedy runs as printed and clears in ONE step, with no second finding carrying a different remedy', (ctx) => {
      const dir = makeTree('remedy');
      if (!makeUnlistable(path.join(dir, 'cfg'))) osDeclined(ctx);
      const first = json([...args, dir]);
      expect(first.status).toBe(EXIT_INCOMPLETE);
      const clause = unreadFindings(first.body)[0].fix.split(' && ')[0];
      expect(clause).toBe('chmod u+rx cfg');
      const ran = spawnSync('sh', ['-c', clause], { cwd: dir, encoding: 'utf-8' });
      expect(ran.status).toBe(0);
      const again = json([...args, dir]);
      expect(again.body.coverage.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
      expect(unreadFindings(again.body)).toHaveLength(0);
      // The credential the directory hid is now measured.
      if (secure) {
        expect(again.status).toBe(1);
        expect(again.body.findings.some((f: any) => /^AST-CRED-/.test(f.checkId))).toBe(true);
      }
    });
  });

  describe('cause split, both directions (secure)', { timeout: 300_000 }, () => {
    it('no .gitignore over a mode-000 directory: exit 2 with GIT-001 at LOW (was exit 1 with GIT-001 HIGH)', (ctx) => {
      const dir = makeTree('nogi', { gitignore: false });
      if (!makeUnlistable(path.join(dir, 'cfg'))) osDeclined(ctx);
      const res = json(['secure', '--scan-depth', 'standard', dir]);
      expect(res.status).toBe(EXIT_INCOMPLETE);
      const git001 = res.body.findings.find((f: any) => f.checkId === 'GIT-001');
      expect(git001).toBeDefined();
      expect(git001.severity).toBe('low');
      expect(git001.description).toContain('SCAN-UNREAD-001');
      expect(unreadFindings(res.body).map((f) => f.file)).toEqual(['cfg/']);
    });

    it('a complete .gitignore over a mode-000 directory: exit 2 with GIT-002 at LOW cross-referencing the record (was exit 0, nothing named)', (ctx) => {
      const dir = makeTree('fullgi');
      fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n.env\n*.pem\n');
      if (!makeUnlistable(path.join(dir, 'cfg'))) osDeclined(ctx);
      const res = json(['secure', '--scan-depth', 'standard', dir]);
      expect(res.status).toBe(EXIT_INCOMPLETE);
      const git002 = res.body.findings.find((f: any) => f.checkId === 'GIT-002');
      expect(git002).toBeDefined();
      expect(git002.severity).toBe('low');
      expect(git002.description).toContain('SCAN-UNREAD-001');
      expect(git002.description).not.toContain('could not be fully scanned');
    });
  });

  describe.each(['quick', 'standard'])('`secure --fix` does not reach exit 0 over an unread input (%s depth)', { timeout: 300_000 }, (depth) => {
    it('--fix: exit 2, the directory untouched, the record still there after the fix pass', (ctx) => {
      const dir = makeTree(`fix-${depth}`, { gitignore: false });
      if (!makeUnlistable(path.join(dir, 'cfg'))) osDeclined(ctx);
      const res = json(['secure', '--fix', '--scan-depth', depth, dir]);
      expect(res.status).toBe(EXIT_INCOMPLETE);
      expect(res.body.coverage.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 1 });
      const unread = unreadFindings(res.body);
      expect(unread).toHaveLength(1);
      expect(unread[0].fixable).toBe(false);
      expect(unread[0].fixed).not.toBe(true);
      // The fix pass wrote a .gitignore into the target; a new readable file
      // cannot clear an unread input (#438's self-satisfying gate).
      expect(fs.existsSync(path.join(dir, '.gitignore'))).toBe(true);
      expect((fs.statSync(path.join(dir, 'cfg')).mode & 0o777)).toBe(0);
      const again = json(['secure', '--scan-depth', depth, dir]);
      expect(again.status).toBe(EXIT_INCOMPLETE);
    });
  });

  describe('direction: secure and check agree on the same fixture', { timeout: 300_000 }, () => {
    it('same exit, same {count, codes, directories}, same directory, same chmod clause modulo the verb', (ctx) => {
      const dir = makeTree('direction');
      if (!makeUnlistable(path.join(dir, 'cfg'))) osDeclined(ctx);
      const s = json(['secure', '--scan-depth', 'quick', dir]);
      const c = json(['check', '--offline', dir]);
      expect(s.status).toBe(EXIT_INCOMPLETE);
      expect(c.status).toBe(EXIT_INCOMPLETE);
      expect(c.body.coverage.unreadableInputs).toEqual(s.body.coverage.unreadableInputs);
      const su = unreadFindings(s.body)[0];
      const cu = unreadFindings(c.body)[0];
      expect(cu.file).toBe(su.file);
      expect(cu.kind).toBe(su.kind);
      expect(cu.message).toBe(su.message);
      expect(cu.fix.replace(' check ', ' secure ')).toBe(su.fix);
    });
  });

  describe('direction on a name only one arm enters', { timeout: 300_000 }, () => {
    it('a mode-000 dist/ is named by secure (which reads dist/) and not by check (which never enters it, readable or not)', (ctx) => {
      // The direction rule binds on obstructions both arms would have READ. `check`
      // runs the semantic walker only, whose skip list holds `dist`; the guard is
      // that the obstruction never moves an arm's verdict cleaner than its readable
      // tree: check(readable dist/.env) == check(000 dist/) == 0, secure 1 -> 2.
      const dir = makeTree('dist-dir', { credential: false });
      fs.mkdirSync(path.join(dir, 'dist'));
      // A sensitive NAME: secure's sensitive-artifact walk reports `dist/.env`
      // on a readable tree (CRED-001); a `.js` under dist/ is never compiled by
      // either arm, so it would prove nothing about the readable verdict.
      fs.writeFileSync(path.join(dir, 'dist', '.env'), `AWS_ACCESS_KEY_ID=AKIA${'A'.repeat(16)}\nAWS_SECRET_ACCESS_KEY=${'b'.repeat(40)}\n`);
      const sOpen = json(['secure', '--scan-depth', 'quick', dir]);
      const cOpen = json(['check', '--offline', dir]);
      expect(sOpen.status).toBe(1);
      expect(cOpen.status).toBe(0);
      expect(cOpen.body.coverage.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
      if (!makeUnlistable(path.join(dir, 'dist'))) osDeclined(ctx);
      const sLocked = json(['secure', '--scan-depth', 'quick', dir]);
      const cLocked = json(['check', '--offline', dir]);
      expect(sLocked.status).toBe(EXIT_INCOMPLETE);
      expect(unreadFindings(sLocked.body).map((f) => f.file)).toEqual(['dist/']);
      expect(sLocked.body.score).toBeLessThanOrEqual(100);
      expect(cLocked.status).toBe(0);
      expect(cLocked.body.coverage.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
    });
  });

  describe('a rejection two levels down names the directory that failed, not its listable parent', { timeout: 300_000 }, () => {
    it('src/hidden at mode 000: secure at standard names src/hidden/, whose printed remedy runs and clears', (ctx) => {
      // The assembly scanner lists src/ with { recursive: true }; Node rejects
      // that call with the NESTED directory's errno. Attributing it to src/
      // named a directory that lists fine, with a chmod remedy that is a no-op
      // and an exit 2 nothing could clear.
      const dir = makeTree('srcrec', { credential: false });
      fs.mkdirSync(path.join(dir, 'src', 'hidden'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'src', 'a.ts'), 'export const x = 1;\n');
      fs.writeFileSync(path.join(dir, 'src', 'hidden', 'b.ts'), 'export const y = 2;\n');
      if (!makeUnlistable(path.join(dir, 'src', 'hidden'))) osDeclined(ctx);
      const res = json(['secure', '--scan-depth', 'standard', dir]);
      expect(res.status).toBe(EXIT_INCOMPLETE);
      const unread = unreadFindings(res.body);
      expect(unread.map((f) => f.file)).toEqual([path.join('src', 'hidden') + '/']);
      const clause = unread[0].fix.split(' && ')[0];
      expect(clause).toBe(`chmod u+rx ${path.join('src', 'hidden')}`);
      const ran = spawnSync('sh', ['-c', clause], { cwd: dir, encoding: 'utf-8' });
      expect(ran.status).toBe(0);
      const again = json(['secure', '--scan-depth', 'standard', dir]);
      expect(again.body.coverage.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
    });

    it('a mode-000 directory under src/node_modules is recorded by the walker that attempted it, by its own name', (ctx) => {
      const dir = makeTree('srcnm', { credential: false });
      fs.mkdirSync(path.join(dir, 'src', 'node_modules', 'hidden'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'src', 'a.ts'), 'export const x = 1;\n');
      if (!makeUnlistable(path.join(dir, 'src', 'node_modules', 'hidden'))) osDeclined(ctx);
      const res = json(['secure', '--scan-depth', 'standard', dir]);
      expect(res.status).toBe(EXIT_INCOMPLETE);
      const unread = unreadFindings(res.body);
      expect(unread.map((f) => f.file)).toEqual([path.join('src', 'node_modules', 'hidden') + '/']);
    });
  });

  describe('policy-skipped names are breadth, not loss (attempt-set predicate)', { timeout: 300_000 }, () => {
    it('a mode-000 .aws/ is named by secure (its sensitive-artifact walk enters it) and not by check', (ctx) => {
      const dir = makeTree('aws-dir', { credential: false });
      fs.mkdirSync(path.join(dir, '.aws'));
      fs.writeFileSync(path.join(dir, '.aws', 'credentials'), `[default]\naws_access_key_id = AKIA${'A'.repeat(16)}\n`);
      if (!makeUnlistable(path.join(dir, '.aws'))) osDeclined(ctx);
      for (const depth of ['quick', 'standard']) {
        const s = json(['secure', '--scan-depth', depth, dir]);
        expect(s.status).toBe(EXIT_INCOMPLETE);
        expect(unreadFindings(s.body).map((f) => f.file)).toEqual(['.aws/']);
      }
      const c = json(['check', '--offline', dir]);
      expect(c.status).toBe(0);
      expect(c.body.coverage.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
    });

    describe.each(['.git', 'node_modules'])('%s/', { timeout: 300_000 }, (name) => {
    it('at mode 000 is out of class on both arms at every depth: no walker attempts it, and no root probe reads it as a file', (ctx) => {
      // Before this change secure at standard depth recorded `.git` as a FILE
      // (kind file, `chmod u+r .git`): a root probe read every root entry,
      // directories included, and a 000 directory fails open() with EACCES
      // before EISDIR can say "not a file". A policy-skipped directory is
      // breadth, never loss.
      const dir = makeTree(`skip-${name}`, { credential: false });
      fs.mkdirSync(path.join(dir, name));
      fs.writeFileSync(path.join(dir, name, 'placeholder.txt'), 'x');
      if (!makeUnlistable(path.join(dir, name))) osDeclined(ctx);
      for (const depth of ['quick', 'standard']) {
        const s = json(['secure', '--scan-depth', depth, dir]);
        expect(s.body.coverage.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
        expect(unreadFindings(s.body)).toHaveLength(0);
      }
      const c = json(['check', '--offline', dir]);
      expect(c.body.coverage.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
    });
    });

    it('a mode-000 regular FILE named .git at the root stays in class on secure at standard depth (the root probe reads it)', (ctx) => {
      const dir = makeTree('gitfile', { credential: false });
      fs.writeFileSync(path.join(dir, '.git'), 'gitdir: ../elsewhere\n');
      fs.chmodSync(path.join(dir, '.git'), 0o000);
      restore.push({ p: path.join(dir, '.git'), mode: 0o644 });
      try { fs.readFileSync(path.join(dir, '.git')); osDeclined(ctx); } catch { /* denied: proceed */ }
      const s = json(['secure', '--scan-depth', 'standard', dir]);
      expect(s.status).toBe(EXIT_INCOMPLETE);
      const unread = unreadFindings(s.body);
      expect(unread.map((f) => f.file)).toEqual(['.git']);
      expect(unread[0].kind).toBe('file');
    });
  });

  describe('channels (secure)', { timeout: 300_000 }, () => {
    it('SARIF at quick and standard: one result, level warning, artifactLocation.uri is the directory', (ctx) => {
      const dir = makeTree('sarif');
      if (!makeUnlistable(path.join(dir, 'cfg'))) osDeclined(ctx);
      for (const depth of ['quick', 'standard']) {
        const res = run(['secure', '--scan-depth', depth, '--format', 'sarif', dir]);
        expect(res.status).toBe(EXIT_INCOMPLETE);
        const sarif = JSON.parse(res.out.slice(res.out.indexOf('{')));
        const results = sarif.runs[0].results.filter((r: any) => r.ruleId === 'SCAN-UNREAD-001');
        expect(results).toHaveLength(1);
        expect(results[0].level).toBe('warning');
        expect(results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('cfg/');
      }
    });

    it('text at quick and standard names the directory and prints the remedy, and exits 2', (ctx) => {
      const dir = makeTree('text');
      if (!makeUnlistable(path.join(dir, 'cfg'))) osDeclined(ctx);
      for (const depth of ['quick', 'standard']) {
        const res = run(['secure', '--scan-depth', depth, dir]);
        expect(res.status).toBe(EXIT_INCOMPLETE);
        expect(res.out).toContain('cfg/ could not be listed (EACCES)');
        expect(res.out).toContain('chmod u+rx cfg && ');
      }
    });

    it('--ci at quick: exit 2 and the directory named', (ctx) => {
      const dir = makeTree('ci');
      if (!makeUnlistable(path.join(dir, 'cfg'))) osDeclined(ctx);
      const res = run(['secure', '--scan-depth', 'quick', '--ci', dir]);
      expect(res.status).toBe(EXIT_INCOMPLETE);
      expect(res.out).toContain('cfg/ could not be listed (EACCES)');
    });

    it('check text names the directory in the ruled words and exits 2', (ctx) => {
      const dir = makeTree('check-text');
      if (!makeUnlistable(path.join(dir, 'cfg'))) osDeclined(ctx);
      const res = run(['check', '--offline', dir]);
      expect(res.status).toBe(EXIT_INCOMPLETE);
      expect(res.out).toContain('cfg/ could not be listed (EACCES)');
      expect(res.out).toContain('chmod u+rx cfg && ');
    });

    it.todo('text header reads `N files analyzed · 1 directory not listed (contents unknown)`, never `N of M files analyzed` — rendered in src/cli.ts; lands with the paired change to that file');
    it.todo('text prints a `Not listed  cfg/  (EACCES)` line at every depth — rendered in src/cli.ts; lands with the paired change to that file');
    it.todo('check: SARIF and --ci are not offered on this arm (`check --help` lists --json and --offline only) — recorded, not skipped');
  });
});
