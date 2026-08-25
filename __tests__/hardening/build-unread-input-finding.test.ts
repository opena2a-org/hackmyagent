/**
 * `buildUnreadInputFinding` — the per-path SCAN-UNREAD-001 finding builder,
 * extracted to module scope so `check` (#508) can emit the identical finding
 * as `secure` without a second copy of the errno->remedy logic (#494 class).
 *
 * These pin the two things the extraction must hold: the `secure` default is
 * byte-for-byte the shape the loop produced before, and the `command`
 * parameter is the ONLY thing that changes when `check` reuses it.
 */
import { describe, it, expect } from 'vitest';
import * as fsn from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { buildUnreadInputFinding } from '../../src/hardening/scanner';

describe('buildUnreadInputFinding', () => {
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
    const f = buildUnreadInputFinding(
      { rel: 'cfg/secrets.js', code: 'EACCES', obstructedBy: 'cfg' },
      { cliName: 'hackmyagent', targetDir: '/tmp/proj' },
    );
    expect(f.fix).toBe('chmod u+x cfg && hackmyagent secure /tmp/proj');
    expect(f.file).toBe('cfg/secrets.js'); // the input is still the file
    expect(f.message).toBe('cfg/secrets.js could not be read (EACCES)');
    expect(f.guidance).toContain('`cfg` can be listed but not entered');
    const check = buildUnreadInputFinding(
      { rel: 'cfg/secrets.js', code: 'EACCES', obstructedBy: 'cfg' },
      { cliName: 'hackmyagent', targetDir: '/tmp/proj', command: 'check' },
    );
    expect(check.fix).toBe('chmod u+x cfg && hackmyagent check /tmp/proj');
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
    } finally { cleanup(dir); }
  });

  it('an absent obstruction directory degrades to the enterable-not-listable strings (probe ENOENT)', () => {
    // `/tmp/proj` does not exist, so the read-bit probe cannot tell — and the
    // pinned strings above stand. This is the compatibility contract the
    // pre-classified pins in this file rely on.
    const f = buildUnreadInputFinding(
      { rel: 'cfg/secrets.js', code: 'EACCES', obstructedBy: 'cfg' },
      { cliName: 'hackmyagent', targetDir: '/tmp/proj' },
    );
    expect(f.fix).toBe('chmod u+x cfg && hackmyagent secure /tmp/proj');
    expect(f.guidance).toContain('can be listed but not entered');
  });
});
