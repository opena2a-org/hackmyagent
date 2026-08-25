/**
 * `buildUnreadInputFinding` — the per-path SCAN-UNREAD-001 finding builder,
 * extracted to module scope so `check` (#508) can emit the identical finding
 * as `secure` without a second copy of the errno->remedy logic (#494 class).
 *
 * These pin the two things the extraction must hold: the `secure` default is
 * byte-for-byte the shape the loop produced before, and the `command`
 * parameter is the ONLY thing that changes when `check` reuses it.
 */
import { describe, it, expect, afterAll } from 'vitest';
import * as fsn from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { buildUnreadInputFinding, unsearchableAncestorSync } from '../../src/hardening/scanner';

describe('buildUnreadInputFinding', () => {
  // A fresh target per probe-sensitive cell. The builder probes
  // `<targetDir>/<obstructedBy>` for its read bit (#515), so a cell that pins
  // `obstructedBy` against a shared literal such as `/tmp/proj` reads whatever
  // the machine holds there — world-writable, plantable by any local user.
  // The precondition the pinned strings rely on (no such directory) is
  // asserted, not assumed.
  const freshTargets: string[] = [];
  const freshTarget = (): string => {
    const dir = fsn.mkdtempSync(path.join(os.tmpdir(), 'hma-buif-target-'));
    expect(fsn.existsSync(path.join(dir, 'cfg'))).toBe(false);
    freshTargets.push(dir);
    return dir;
  };
  afterAll(() => { for (const d of freshTargets) fsn.rmSync(d, { recursive: true, force: true }); });

  it('defaults command to `secure`, so the existing caller is unchanged', () => {
    const f = buildUnreadInputFinding(
      { rel: 'locked.txt', code: 'EACCES' },
      { cliName: 'hackmyagent', targetDir: '/tmp/proj' },
    );
    expect(f.checkId).toBe('SCAN-UNREAD-001');
    expect(f.name).toBe('Input Discovered But Not Read');
    expect(f.severity).toBe('medium');
    expect(f.passed).toBe(false);
    expect(f.file).toBe('locked.txt');
    expect(f.message).toBe('locked.txt could not be read (EACCES)');
    // EACCES is a permission denial: chmod, then re-run the SAME verb.
    expect(f.fix).toBe('chmod u+r locked.txt && hackmyagent secure /tmp/proj');
  });

  it('emits the identical finding for `check`, changing only the re-run verb', () => {
    const secure = buildUnreadInputFinding({ rel: 'locked.txt', code: 'EACCES' }, { cliName: 'hackmyagent', targetDir: '/tmp/proj' });
    const check = buildUnreadInputFinding({ rel: 'locked.txt', code: 'EACCES' }, { cliName: 'hackmyagent', targetDir: '/tmp/proj', command: 'check' });
    expect(check.fix).toBe('chmod u+r locked.txt && hackmyagent check /tmp/proj');
    // Everything except the fix's verb is identical.
    expect({ ...check, fix: undefined }).toEqual({ ...secure, fix: undefined });
  });

  it('names the directory the user cannot enter when that, not the file, is the obstruction (#515)', () => {
    // `chmod 600 <dir>` lists its files and rejects every open inside it;
    // `chmod u+r <file>` fails with the same EACCES the scan did.
    const dir = freshTarget();
    const f = buildUnreadInputFinding(
      { rel: 'cfg/secrets.js', code: 'EACCES', obstructedBy: 'cfg' },
      { cliName: 'hackmyagent', targetDir: dir },
    );
    expect(f.fix).toBe(`chmod u+x cfg && hackmyagent secure ${dir}`);
    expect(f.file).toBe('cfg/secrets.js'); // the input is still the file
    expect(f.message).toBe('cfg/secrets.js could not be read (EACCES)');
    expect(f.guidance).toContain('`cfg` can be listed but not entered');
    const check = buildUnreadInputFinding(
      { rel: 'cfg/secrets.js', code: 'EACCES', obstructedBy: 'cfg' },
      { cliName: 'hackmyagent', targetDir: dir, command: 'check' },
    );
    expect(check.fix).toBe(`chmod u+x cfg && hackmyagent check ${dir}`);
  });

  it('a non-permission errno ignores obstructedBy: no chmod can answer EIO', () => {
    const f = buildUnreadInputFinding(
      { rel: 'cfg/secrets.js', code: 'EIO', obstructedBy: 'cfg' },
      { cliName: 'hackmyagent', targetDir: '/tmp/proj' },
    );
    expect(f.fix).not.toContain('chmod');
  });

  it('derives the remedy from the errno: a non-permission code gets no chmod and no re-run verb', () => {
    const f = buildUnreadInputFinding({ rel: 'broken', code: 'ELOOP' }, { cliName: 'hackmyagent', targetDir: '/tmp/proj', command: 'check' });
    expect(f.fix).not.toContain('chmod');
    expect(f.fix).not.toContain('hackmyagent check');
    expect(f.fix).toContain('Resolve the ELOOP');
  });

  it('names the errno in guidance, not only in message', () => {
    const f = buildUnreadInputFinding({ rel: 'x', code: 'EIO' }, { cliName: 'hackmyagent', targetDir: '.' });
    expect(f.guidance).toContain('EIO');
  });

  // ---- The caller that passes the raw ledger record (the `check` arm shape) ----
  // Real obstructions, so the builder's own classification is what is under
  // test — the earlier pins hand it a pre-classified record, which is a shape
  // no shipped `check` caller produces. Under root (or a filesystem without
  // permission support) the obstruction cannot exist; the test SKIPS loudly
  // rather than passing over nothing.

  function realTree(): { dir: string; locked: string } {
    const dir = fsn.mkdtempSync(path.join(os.tmpdir(), 'hma-buif-'));
    fsn.mkdirSync(path.join(dir, 'cfg'));
    fsn.writeFileSync(path.join(dir, 'cfg', 'secrets.js'), 'x\n');
    return { dir, locked: path.join(dir, 'cfg', 'secrets.js') };
  }
  function cleanup(dir: string) {
    try { fsn.chmodSync(path.join(dir, 'cfg'), 0o700); } catch { /* already removable */ }
    fsn.rmSync(dir, { recursive: true, force: true });
  }
  function denied(target: string, mode: number): boolean {
    try { fsn.accessSync(target, mode); return false; } catch { return true; }
  }

  it('classifies the obstruction itself when the caller passes the raw ledger record (the check arm)', (ctx) => {
    const { dir, locked } = realTree();
    try {
      fsn.chmodSync(path.join(dir, 'cfg'), 0o600);
      if (!denied(path.join(dir, 'cfg'), fsn.constants.X_OK)) {
        console.warn('[build-unread-input-finding] cannot deny search to this process (root?): SKIPPING, not passing');
        ctx.skip();
      }
      const f = buildUnreadInputFinding(
        { path: locked, rel: 'cfg/secrets.js', code: 'EACCES' },
        { cliName: 'hackmyagent', targetDir: dir, command: 'check' },
      );
      expect(f.fix.startsWith('chmod u+x cfg && ')).toBe(true);
      expect(f.fix).toContain('hackmyagent check');
      expect(f.fix).not.toContain('chmod u+r ');
      expect(f.guidance).toContain('can be listed but not entered');
    } finally { cleanup(dir); }
  });

  it('a directory that denies read as well gets `u+rx` and wording that does not claim it lists', (ctx) => {
    const { dir } = realTree();
    try {
      fsn.chmodSync(path.join(dir, 'cfg'), 0o000);
      if (!denied(path.join(dir, 'cfg'), fsn.constants.R_OK)) {
        console.warn('[build-unread-input-finding] cannot deny read to this process (root?): SKIPPING, not passing');
        ctx.skip();
      }
      const f = buildUnreadInputFinding(
        { rel: 'cfg/secrets.js', code: 'EACCES', obstructedBy: 'cfg' },
        { cliName: 'hackmyagent', targetDir: dir },
      );
      expect(f.fix.startsWith('chmod u+rx cfg && ')).toBe(true);
      expect(f.guidance).toContain('cannot be listed or entered');
      expect(f.guidance).not.toContain('can be listed but not entered');
      // The `check` arm reaches this wording only through the builder's own
      // classification (raw record, no `obstructedBy`); pin the shipped
      // string with all three together: fallback + read denied + `check`.
      const check = buildUnreadInputFinding(
        { path: path.join(dir, 'cfg', 'secrets.js'), rel: 'cfg/secrets.js', code: 'EACCES' },
        { cliName: 'hackmyagent', targetDir: dir, command: 'check' },
      );
      expect(check.fix.startsWith('chmod u+rx cfg && ')).toBe(true);
      expect(check.fix).toContain('hackmyagent check');
      expect(check.guidance).toContain('cannot be listed or entered');
    } finally { cleanup(dir); }
  });

  describe('directory kind (#588): a directory the scan could not list', () => {
    const NO_FILE = /\bfiles?\b/i;

    it('names the directory with a trailing separator, in the ruled words, with a listing remedy', () => {
      const dir = freshTarget();
      const f = buildUnreadInputFinding(
        { rel: 'cfg', code: 'EACCES', kind: 'directory' },
        { cliName: 'hackmyagent', targetDir: dir },
      );
      expect(f.checkId).toBe('SCAN-UNREAD-001');
      expect(f.kind).toBe('directory');
      expect(f.file).toBe('cfg/');
      expect(f.message).toBe('cfg/ could not be listed (EACCES) — its contents were not discovered, so nothing inside it reached any check.');
      expect(f.fix).toBe(`chmod u+rx cfg && hackmyagent secure ${dir}`);
      expect(f.fixable).toBe(false);
      expect(f.severity).toBe('medium');
      expect(f.description).not.toMatch(NO_FILE);
      expect(f.guidance).not.toMatch(NO_FILE);
      expect(f.guidance).toContain('upper bound');
      const check = buildUnreadInputFinding(
        { rel: 'cfg', code: 'EPERM', kind: 'directory' },
        { cliName: 'hackmyagent', targetDir: dir, command: 'check' },
      );
      expect(check.fix).toBe(`chmod u+rx cfg && hackmyagent check ${dir}`);
      expect(check.message).toContain('(EPERM)');
    });

    it('the scan root itself renders as `./`, whichever name the caller derived for it', () => {
      const dir = freshTarget();
      const f = buildUnreadInputFinding(
        { rel: path.basename(dir), path: dir, code: 'EACCES', kind: 'directory' },
        { cliName: 'hackmyagent', targetDir: dir },
      );
      expect(f.file).toBe('./');
      expect(f.message.startsWith('./ could not be listed (EACCES)')).toBe(true);
      // The operand is the absolute target, not `.`: the reader's cwd is not the
      // target, and `chmod u+rx .` would chmod it and report success.
      expect(f.fix).toBe(`chmod u+rx ${dir} && hackmyagent secure ${dir}`);
    });

    it('a directory lost under an unsearchable ancestor takes the ancestor remedy (#515 shape) and says so', () => {
      const dir = freshTarget();
      const f = buildUnreadInputFinding(
        { rel: 'a/b', code: 'EACCES', kind: 'directory', obstructedBy: 'a' },
        { cliName: 'hackmyagent', targetDir: dir },
      );
      expect(f.file).toBe('a/b/');
      expect(f.fix).toBe(`chmod u+x a && hackmyagent secure ${dir}`);
      expect(f.guidance).toContain('a/b/ could not be listed');
      expect(f.guidance).toContain('the remedy is on `a`');
      expect(f.guidance).not.toMatch(NO_FILE);
    });

    it('a raw directory record with no caller obstruction is its own remedy target (shape-level: the output does not depend on the mode bits)', () => {
      // The ancestor probe inspects ANCESTORS of the record's path, never the
      // path itself, so this output is identical whatever cfg's mode is — the
      // real-obstruction end-to-end coverage lives in the repo matrix suite.
      const { dir } = realTree();
      try {
        const f = buildUnreadInputFinding(
          { path: path.join(dir, 'cfg'), rel: 'cfg', code: 'EACCES', kind: 'directory' },
          { cliName: 'hackmyagent', targetDir: dir, command: 'check' },
        );
        expect(f.fix).toBe(`chmod u+rx cfg && hackmyagent check ${dir}`);
        expect(f.file).toBe('cfg/');
      } finally { cleanup(dir); }
    });
  });

  describe('errno-first remedy: a non-permission code names a cause it can have', () => {
    it('ENAMETOOLONG names the measured path length and a shallower checkout, never a chmod or a symlink alias', () => {
      const dir = freshTarget();
      const long = path.join(dir, 'x'.repeat(300), 'y'.repeat(300), 'z'.repeat(300), 'secrets.js');
      const f = buildUnreadInputFinding(
        { rel: path.relative(dir, long), path: long, code: 'ENAMETOOLONG' },
        { cliName: 'hackmyagent', targetDir: dir },
      );
      expect(f.fix).toContain('shallower checkout');
      expect(f.fix).not.toContain('chmod');
      expect(f.fix).not.toContain('symlink');
      expect(f.guidance).toContain(`${long.length} characters`);
      expect(f.guidance).not.toContain('symlink');
    });

    it('ELOOP and EIO name their own causes; nothing names "a broken symlink" (a dangling link is ENOENT and never reaches here)', () => {
      const dir = freshTarget();
      const loop = buildUnreadInputFinding({ rel: 'loop', code: 'ELOOP' }, { cliName: 'hackmyagent', targetDir: dir });
      expect(loop.fix).toContain('Resolve the ELOOP');
      expect(loop.fix).toContain('symbolic-link loop');
      const eio = buildUnreadInputFinding({ rel: 'disk.js', code: 'EIO' }, { cliName: 'hackmyagent', targetDir: dir });
      expect(eio.fix).toContain('Resolve the EIO');
      expect(eio.fix).toContain('I/O error');
      for (const f of [loop, eio]) {
        expect(f.fix).not.toContain('broken symlink');
        expect(f.guidance).not.toContain('broken symlink');
      }
      const unknown = buildUnreadInputFinding({ rel: 'odd', code: 'EWHATEVER' }, { cliName: 'hackmyagent', targetDir: dir });
      expect(unknown.fix).toContain('Resolve the EWHATEVER');
      expect(unknown.fix).not.toContain('broken symlink');
    });

    it('the directory kind with a non-permission errno gets the same cause phrase and no chmod', () => {
      const dir = freshTarget();
      const f = buildUnreadInputFinding({ rel: 'cfg', code: 'EIO', kind: 'directory' }, { cliName: 'hackmyagent', targetDir: dir });
      expect(f.file).toBe('cfg/');
      expect(f.fix).toContain('Resolve the EIO');
      expect(f.fix).not.toContain('chmod');
      expect(f.guidance).not.toMatch(/\bfiles?\b/i);
    });
  });

  describe('unsearchableAncestorSync names the scan root (#588)', () => {
    it('a readable tree has no unsearchable ancestor', () => {
      const { dir, locked } = realTree();
      try {
        expect(unsearchableAncestorSync(locked, dir)).toBeUndefined();
      } finally { cleanup(dir); }
    });

    it('a root this process cannot enter is the obstruction, named `.` — not silence, not the child', (ctx) => {
      // Measured before this change: a mode-600 root lost every probe path
      // and the finding named each child with a `chmod u+r <file>` that fails.
      const { dir, locked } = realTree();
      try {
        fsn.chmodSync(dir, 0o600);
        if (!denied(dir, fsn.constants.X_OK)) {
          console.warn('[build-unread-input-finding] cannot deny search on the root to this process (root?): SKIPPING, not passing');
          ctx.skip();
        }
        expect(unsearchableAncestorSync(locked, dir)).toBe('.');
        // The root record itself (a mode-000 root rejects readdir) classifies the same way.
        expect(unsearchableAncestorSync(dir, dir)).toBe('.');
      } finally { fsn.chmodSync(dir, 0o700); cleanup(dir); }
    });

    it('the shallowest unsearchable directory wins over a deeper one, and the root over both', (ctx) => {
      const { dir, locked } = realTree();
      try {
        fsn.chmodSync(path.join(dir, 'cfg'), 0o600);
        if (!denied(path.join(dir, 'cfg'), fsn.constants.X_OK)) {
          console.warn('[build-unread-input-finding] cannot deny search to this process (root?): SKIPPING, not passing');
          ctx.skip();
        }
        expect(unsearchableAncestorSync(locked, dir)).toBe('cfg');
        fsn.chmodSync(dir, 0o600);
        expect(unsearchableAncestorSync(locked, dir)).toBe('.');
      } finally { fsn.chmodSync(dir, 0o700); cleanup(dir); }
    });
  });

  it('an absent obstruction directory degrades to the enterable-not-listable strings (probe ENOENT)', () => {
    // The fresh target has no `cfg` (asserted in `freshTarget`), so the
    // read-bit probe cannot tell — and the pinned strings above stand. This is
    // the compatibility contract the pre-classified pins in this file rely on.
    const dir = freshTarget();
    const f = buildUnreadInputFinding(
      { rel: 'cfg/secrets.js', code: 'EACCES', obstructedBy: 'cfg' },
      { cliName: 'hackmyagent', targetDir: dir },
    );
    expect(f.fix).toBe(`chmod u+x cfg && hackmyagent secure ${dir}`);
    expect(f.guidance).toContain('can be listed but not entered');
  });
});
