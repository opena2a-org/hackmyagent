/**
 * #508 — the `SCAN-UNREAD-001` remedy on a downloaded target.
 *
 * The scanner writes its remedy for a tree on the user's machine:
 * `chmod u+r <file> && hackmyagent secure <dir>`. On npm / PyPI / GitHub / URL
 * targets the cited directory is a temp extraction the run deletes before the
 * user reads the line — and it leaked into `--json` — and `chmod` on a copy
 * says nothing about the artifact. Pure and tested here because no instrument
 * produces a real unreadable member of a published package on demand.
 */
import { describe, it, expect } from 'vitest';
import { emitFinding } from '../../src/hardening/finding-emit';
import {
  remoteUnreadRemedy,
  rewriteRemoteUnreadRemedy,
  UNREAD_INPUT_CHECK_ID,
} from '../../src/check/remote-unread-remedy';

const TEMP = '/var/folders/xx/T/hma-check-url-AbCdEf/extracted/agent';

function unread(file: string) {
  return emitFinding({
    checkId: UNREAD_INPUT_CHECK_ID,
    name: 'Input Discovered But Not Read',
    severity: 'medium',
    passed: false,
    message: `${file} could not be read (EACCES)`,
    file,
    fix: `chmod u+r ${file} && hackmyagent secure ${TEMP}`,
  } as any);
}

function other(file: string) {
  return emitFinding({
    checkId: 'GIT-002',
    name: 'Incomplete .gitignore',
    severity: 'low',
    passed: false,
    message: 'x',
    file,
    fix: 'hackmyagent secure . --fix',
  } as any);
}

describe('remoteUnreadRemedy', () => {
  it('never says chmod and never cites a directory on this machine', () => {
    for (const kind of ['package', 'archive', 'repository'] as const) {
      const text = remoteUnreadRemedy(kind, 'src/secrets.js', 'npm pack x');
      expect(text).not.toContain('chmod');
      expect(text).not.toContain('/var/folders');
      expect(text).not.toContain('/tmp/');
      expect(text).toContain('src/secrets.js');
    }
  });

  it('says the mode bits belong to a published archive, and the checkout for a clone', () => {
    expect(remoteUnreadRemedy('package', 'a.js', undefined)).toContain('whoever published it');
    expect(remoteUnreadRemedy('archive', 'a.js', undefined)).toContain('Treat the file as unreviewed');
    expect(remoteUnreadRemedy('repository', 'a.js', undefined)).toContain('checkout on this machine');
    expect(remoteUnreadRemedy('repository', 'a.js', undefined)).not.toContain('whoever published');
  });

  it('carries the inspect command when one is given, and nothing when it is not', () => {
    expect(remoteUnreadRemedy('package', 'a.js', 'npm pack left-pad')).toContain('npm pack left-pad');
    expect(remoteUnreadRemedy('package', 'a.js', undefined)).not.toContain('Inspect the member list');
  });

  it('escapes a hostile member path for display', () => {
    // Member names come out of the archive; a name carrying a terminal escape
    // and a newline must not reach the line as bytes.
    const text = remoteUnreadRemedy('archive', 'evil\u001b[2J\nx.js', undefined);
    expect(text).not.toContain('\u001b');
    expect(text).not.toContain('\n');
  });
});

describe('rewriteRemoteUnreadRemedy', () => {
  it('rewrites only the unread finding and leaves every other finding the same object', () => {
    const gitignore = other('.gitignore');
    const out = rewriteRemoteUnreadRemedy([unread('src/secrets.js'), gitignore], 'package', 'npm pack x');
    expect(out).toHaveLength(2);
    expect(out[1]).toBe(gitignore);
    expect(out[0].checkId).toBe(UNREAD_INPUT_CHECK_ID);
    expect(out[0].fix).not.toContain(TEMP);
    expect(out[0].fix).not.toContain('chmod');
    expect(out[0].fix).toContain('npm pack x');
  });

  it('keeps severity, file and message — only the remedy moves', () => {
    const before = unread('src/secrets.js');
    const [after] = rewriteRemoteUnreadRemedy([before], 'archive', undefined);
    expect(after.severity).toBe(before.severity);
    expect(after.file).toBe(before.file);
    expect(after.message).toBe(before.message);
  });

  it('is the identity on a list with no unread finding', () => {
    const list = [other('a'), other('b')];
    expect(rewriteRemoteUnreadRemedy(list, 'repository', undefined)).toEqual(list);
  });
});
