/**
 * #510 — the SCAN-UNREAD-001 finding for an input one reader read and
 * another could not.
 *
 * A path stays lost while any reader that failed on it has no success of its
 * own there, however many other checks read it: a check that never got the
 * bytes is blind to them. The finding built from that record said "its
 * contents never reached a check" and handed the user `chmod u+r` for a file
 * another check had just read and that this user can read now. These pin the
 * ledger counts behind the record and the words and remedy built from them.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { CoverageLedger, noteReadFailure } from '../../src/hardening/coverage-ledger';
import { buildUnreadInputFinding, HardeningScanner } from '../../src/hardening/scanner';
import { tempDir } from '../helpers/temp-dir';

const TARGET = path.join(path.sep, 'tmp', 'hma-read-elsewhere-target');
const inside = (p: string) => path.join(TARGET, p);

function denied(target: string, mode: number): boolean {
  try { fs.accessSync(target, mode); return false; } catch { return true; }
}

describe('CoverageLedger.lostInputReaders', () => {
  it('check A reads the file, check B fails on it: one check read it, one check did not', async () => {
    const ledger = new CoverageLedger(TARGET);
    const file = inside('secrets.js');
    await ledger.run('checkClaudeMd', async () => { ledger.noteRead(file); });
    await ledger.run('checkCredentialExposure', async () => { ledger.noteReadFailure(file, 'EACCES'); });
    expect(ledger.unreadablePaths()).toEqual([{ path: file, code: 'EACCES', kind: 'file' }]);
    expect(ledger.lostInputReaders(file, 'file')).toEqual({ succeeded: 1, failedChecks: 1, failedOutsideChecks: false });
  });

  it('a failure outside any check beside a framed read is reported as the outside reader', async () => {
    const ledger = new CoverageLedger(TARGET);
    const file = inside('semantic-only.js');
    ledger.noteReadFailure(file, 'EACCES');
    await ledger.run('checkCredentialExposure', async () => { ledger.noteRead(file); });
    expect(ledger.lostInputReaders(file, 'file')).toEqual({ succeeded: 1, failedChecks: 0, failedOutsideChecks: true });
  });

  it('a failing check that re-read the path counts as a reader that got it, not as a failing one', async () => {
    const ledger = new CoverageLedger(TARGET);
    const file = inside('secrets.js');
    await ledger.run('checkCredentialExposure', async () => { ledger.noteReadFailure(file, 'EACCES'); });
    await ledger.run('checkClaudeMd', async () => { ledger.noteReadFailure(file, 'EACCES'); });
    await ledger.run('checkCredentialExposure', async () => { ledger.noteRead(file); });
    expect(ledger.lostInputReaders(file, 'file')).toEqual({ succeeded: 1, failedChecks: 1, failedOutsideChecks: false });
  });

  it('a failure whose errno does not count is not a failing reader', async () => {
    const ledger = new CoverageLedger(TARGET);
    const file = inside('secrets.js');
    await ledger.run('checkGitSecurity', async () => { ledger.noteReadFailure(file, 'ENOENT'); });
    await ledger.run('checkCredentialExposure', async () => { ledger.noteReadFailure(file, 'EACCES'); });
    expect(ledger.lostInputReaders(file, 'file')).toEqual({ succeeded: 0, failedChecks: 1, failedOutsideChecks: false });
  });

  it('a directory is answered from the listing channel', async () => {
    const ledger = new CoverageLedger(TARGET);
    const dir = inside('cfg');
    await ledger.run('checkFilePermissions', async () => { ledger.noteListed(dir); });
    await ledger.run('checkMcpConfig', async () => { ledger.noteListFailure(dir, 'EACCES'); });
    // A content read of the same path is not a listing.
    await ledger.run('checkClaudeMd', async () => { ledger.noteRead(dir); });
    expect(ledger.unreadablePaths()).toEqual([{ path: dir, code: 'EACCES', kind: 'directory' }]);
    expect(ledger.lostInputReaders(dir, 'directory')).toEqual({ succeeded: 1, failedChecks: 1, failedOutsideChecks: false });
  });
});

describe('buildUnreadInputFinding for an input another check read (#510)', () => {
  function readableFile(): { dir: string; file: string } {
    const dir = tempDir('hma-510-');
    const file = path.join(dir, 'secrets.js');
    fs.writeFileSync(file, 'module.exports = 1;\n');
    return { dir, file };
  }

  it('readable now: the remedy is the re-run, not a chmod, and the text says a check read it', () => {
    const { dir, file } = readableFile();
    const f = buildUnreadInputFinding(
      { path: file, rel: 'secrets.js', code: 'EACCES', readers: { succeeded: 2, failedChecks: 1, failedOutsideChecks: false } },
      { cliName: 'hackmyagent', targetDir: dir },
    );
    expect(f.checkId).toBe('SCAN-UNREAD-001');
    expect(f.passed).toBe(false);
    expect(f.severity).toBe('medium');
    expect(f.fix).toBe(`hackmyagent secure ${dir}`);
    expect(f.message).toBe('secrets.js could not be read (EACCES)');
    expect(f.guidance).toContain('This file was read by 2 checks in this scan, but the read by 1 other check failed with EACCES');
    expect(f.guidance).toContain('It is readable now, so `chmod` would change nothing');
    expect(f.guidance).not.toContain('never reached a check');
    expect(f.description).not.toContain('no check examined it');
  });

  it('the re-run names the verb of the command that reported it', () => {
    const { dir, file } = readableFile();
    const f = buildUnreadInputFinding(
      { path: file, rel: 'secrets.js', code: 'EACCES', readers: { succeeded: 1, failedChecks: 1, failedOutsideChecks: false } },
      { cliName: 'hackmyagent', targetDir: dir, command: 'check' },
    );
    expect(f.fix).toBe(`hackmyagent check ${dir}`);
  });

  it('a failure outside any check is named as such', () => {
    const { dir, file } = readableFile();
    const f = buildUnreadInputFinding(
      { path: file, rel: 'secrets.js', code: 'EACCES', readers: { succeeded: 1, failedChecks: 0, failedOutsideChecks: true } },
      { cliName: 'hackmyagent', targetDir: dir },
    );
    expect(f.guidance).toContain('This file was read by 1 check in this scan, but the read by a reader outside any single check failed with EACCES');
    expect(f.guidance).toContain('the findings of that reader do not cover its contents');
    expect(f.fix).not.toContain('chmod');
  });

  it('two failing readers are counted in the text', () => {
    const { dir, file } = readableFile();
    const f = buildUnreadInputFinding(
      { path: file, rel: 'secrets.js', code: 'EACCES', readers: { succeeded: 1, failedChecks: 1, failedOutsideChecks: true } },
      { cliName: 'hackmyagent', targetDir: dir },
    );
    expect(f.guidance).toContain('the read by 1 other check and a reader outside any single check failed with EACCES');
    expect(f.guidance).toContain('the findings of those readers do not cover its contents');
  });

  it('not readable now: the chmod remedy stands and the text says it is not readable now', (ctx) => {
    const { dir, file } = readableFile();
    try {
      fs.chmodSync(file, 0o000);
      if (!denied(file, fs.constants.R_OK)) {
        console.warn('[unread-input-read-elsewhere] cannot deny read to this process (root?): SKIPPING, not passing');
        ctx.skip();
      }
      const f = buildUnreadInputFinding(
        { path: file, rel: 'secrets.js', code: 'EACCES', readers: { succeeded: 1, failedChecks: 1, failedOutsideChecks: false } },
        { cliName: 'hackmyagent', targetDir: dir },
      );
      expect(f.fix).toBe(`chmod u+r secrets.js && hackmyagent secure ${dir}`);
      expect(f.guidance).toContain('It is not readable now.');
      expect(f.guidance).not.toContain('never reached a check');
    } finally { fs.chmodSync(file, 0o600); }
  });

  it('a directory another check listed, listable now: re-run, and the message keeps its errno form', () => {
    const dir = tempDir('hma-510-dir-');
    const cfg = path.join(dir, 'cfg');
    fs.mkdirSync(cfg);
    const f = buildUnreadInputFinding(
      { path: cfg, rel: 'cfg', kind: 'directory', code: 'EACCES', readers: { succeeded: 1, failedChecks: 1, failedOutsideChecks: false } },
      { cliName: 'hackmyagent', targetDir: dir },
    );
    expect(f.file).toBe('cfg/');
    expect(f.fix).toBe(`hackmyagent secure ${dir}`);
    expect(f.message).toBe('cfg/ could not be listed (EACCES) by 1 check, though 1 other check listed it in this scan: '
      + 'the findings of that reader do not cover anything inside it.');
    expect(f.guidance).toContain('It can be listed now, so `chmod` would change nothing');
    expect(f.guidance).not.toContain('nothing inside it reached any check');
  });

  it('no check read it: the words and remedy are the ones without reader counts', () => {
    const { dir, file } = readableFile();
    const withCounts = buildUnreadInputFinding(
      { path: file, rel: 'secrets.js', code: 'EACCES', readers: { succeeded: 0, failedChecks: 0, failedOutsideChecks: true } },
      { cliName: 'hackmyagent', targetDir: dir },
    );
    const without = buildUnreadInputFinding(
      { path: file, rel: 'secrets.js', code: 'EACCES' },
      { cliName: 'hackmyagent', targetDir: dir },
    );
    expect(withCounts).toEqual(without);
    expect(withCounts.fix).toBe(`chmod u+r secrets.js && hackmyagent secure ${dir}`);
    expect(withCounts.guidance).toContain('so its contents never reached a check');
  });
});

describe('secure carries the reader counts from the ledger to the finding (#510)', () => {
  it('a file a check read and a reader outside every check failed on: re-run remedy, read-by text', async () => {
    const dir = tempDir('hma-510-scan-');
    fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"fixture510","version":"1.0.0"}\n');
    const scanner = new HardeningScanner();
    const result = await scanner.scan({
      targetDir: dir,
      autoFix: false,
      // The semantic pass runs inside the ledger's window and outside every
      // check frame, so a failure it reports is the unattributed kind. The
      // static checks have already read `package.json` by then.
      semanticPass: async () => {
        noteReadFailure(path.join(dir, 'package.json'), 'EACCES');
      },
    });
    expect(result.coverage?.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 0 });
    const unread = result.findings.filter((f) => f.checkId === 'SCAN-UNREAD-001');
    expect(unread).toHaveLength(1);
    expect(unread[0].file).toBe('package.json');
    expect(unread[0].guidance).toMatch(/^This file was read by \d+ checks? in this scan, but the read by a reader outside any single check failed with EACCES/);
    expect(unread[0].fix).not.toContain('chmod');
    expect(unread[0].fix).toContain('secure');
  });
});
