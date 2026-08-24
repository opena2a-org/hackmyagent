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
});
