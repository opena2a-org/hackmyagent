/**
 * #613 — `NemoClawScanner` must not pass a check over an input it reached and
 * could not list, read or stat.
 *
 * Its helpers caught every failure and returned "nothing here": a config file
 * at mode 000 left NMC-001 with nothing to match and it PASSED; a `stat` that
 * failed on a world-readable blueprint classified it as not world-readable and
 * NMC-005 PASSED with "All blueprint cache files have appropriate permissions"
 * (the verdict inverted); a directory at mode 000 vanished from every walk.
 *
 * The contract, the same one `secure` holds for the scan target: a not-there
 * errno is absence and changes nothing; any other errno is a lost input, so the
 * check that lost it withholds its pass, its measured failures stand, and the
 * path is disclosed once as SCAN-UNREAD-001.
 *
 * The scanner reads the user's home directory, fixed at import, so each case
 * points HOME at a fresh temporary tree and imports the module afresh. Every
 * shell probe is stubbed to fail, which the scanner reads as "not installed".
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

vi.mock('child_process', async (importOriginal) => ({
  ...(await importOriginal<typeof import('child_process')>()),
  execSync: () => {
    throw new Error('shell probes are disabled in this test');
  },
}));

// Permission bits do not bind root, and Windows has no mode-000 file.
const canDenyAccess = process.platform !== 'win32' && process.getuid?.() !== 0;

const realHome = process.env.HOME;
let roots: string[] = [];

function writeFile(p: string, content: string, mode = 0o600): void {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
  fs.chmodSync(p, mode);
}

/** A fresh HOME holding `~/.nemoclaw/`, and an empty scan target beside it. */
function fixture(): { home: string; target: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nmc-'));
  roots.push(root);
  const home = path.join(root, 'home');
  const target = path.join(root, 'target');
  fs.mkdirSync(path.join(home, '.nemoclaw'), { recursive: true });
  fs.mkdirSync(target, { recursive: true });
  return { home, target };
}

async function scan(home: string, target: string) {
  process.env.HOME = home;
  vi.resetModules();
  const { NemoClawScanner } = await import('../../src/hardening/nemoclaw-scanner');
  return new NemoClawScanner().scan(target);
}

function byCheck(findings: Array<{ checkId: string; passed?: boolean }>, checkId: string) {
  return findings.filter((f) => f.checkId === checkId);
}

function unread(findings: Array<{ checkId: string; file?: string; details?: Record<string, unknown> }>) {
  return findings
    .filter((f) => f.checkId === 'SCAN-UNREAD-001')
    .map((f) => ({ file: f.file, code: f.details?.code, operation: f.details?.operation }));
}

afterEach(() => {
  process.env.HOME = realHome;
  // Restore traversal before removal: rm cannot descend into a mode-000 directory.
  for (const root of roots) {
    const restore = (p: string): void => {
      try { fs.chmodSync(p, 0o700); } catch { /* already gone */ }
      let entries: fs.Dirent[] = [];
      try { entries = fs.readdirSync(p, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        const full = path.join(p, e.name);
        if (e.isDirectory()) restore(full);
        else try { fs.chmodSync(full, 0o600); } catch { /* already gone */ }
      }
    };
    restore(root);
    fs.rmSync(root, { recursive: true, force: true });
  }
  roots = [];
});

describe('#613 a readable tree is unchanged', () => {
  it('passes the file checks and discloses nothing when every input reads', async () => {
    const { home, target } = fixture();
    writeFile(path.join(home, '.nemoclaw', 'config'), 'region=us\n');
    writeFile(path.join(target, '.env'), 'PLACEHOLDER=1\n');

    const findings = await scan(home, target);

    expect(byCheck(findings, 'HMA-NMC-001')).toEqual([
      expect.objectContaining({ passed: true }),
    ]);
    expect(byCheck(findings, 'HMA-NMC-014')).toEqual([
      expect.objectContaining({ passed: true }),
    ]);
    expect(unread(findings)).toEqual([]);
  });
});

describe.skipIf(!canDenyAccess)('#613 a lost input withholds the pass and is disclosed', () => {
  it('a mode-000 file the target listing found does not let NMC-001 pass', async () => {
    const { home, target } = fixture();
    const env = path.join(target, '.env');
    writeFile(env, 'PLACEHOLDER=1\n', 0o000);

    const findings = await scan(home, target);

    expect(byCheck(findings, 'HMA-NMC-001').filter((f) => f.passed === true)).toEqual([]);
    expect(unread(findings)).toEqual([{ file: env, code: 'EACCES', operation: 'read' }]);
  });

  it('a stat that fails on a listed blueprint does not report it as restricted', async () => {
    const { home, target } = fixture();
    const bpDir = path.join(home, '.nemoclaw', 'blueprints', 'web');
    const bp = path.join(bpDir, 'blueprint.yaml');
    // World-readable file inside a directory that can be listed but not entered.
    writeFile(bp, 'digest: sha256:0\n', 0o644);
    fs.chmodSync(bpDir, 0o600);

    const findings = await scan(home, target);

    expect(byCheck(findings, 'HMA-NMC-005').filter((f) => f.passed === true)).toEqual([]);
    expect(unread(findings)).toContainEqual({ file: bp, code: 'EACCES', operation: 'stat' });
  });

  it('a mode-000 directory under a walked root is disclosed, not skipped', async () => {
    const { home, target } = fixture();
    const policies = path.join(home, '.nemoclaw', 'policies');
    fs.mkdirSync(policies, { recursive: true });
    fs.chmodSync(policies, 0o000);

    const findings = await scan(home, target);

    expect(byCheck(findings, 'HMA-NMC-013').filter((f) => f.passed === true)).toEqual([]);
    expect(unread(findings)).toContainEqual({ file: policies, code: 'EACCES', operation: 'list' });
  });

  it('a mode-000 skills directory in the target withholds only the checks that list it', async () => {
    const { home, target } = fixture();
    const skills = path.join(target, '.agents', 'skills');
    fs.mkdirSync(path.join(skills, 'demo'), { recursive: true });
    fs.chmodSync(skills, 0o000);

    const findings = await scan(home, target);

    for (const id of ['HMA-NMC-020', 'HMA-NMC-024']) {
      expect(byCheck(findings, id).filter((f) => f.passed === true)).toEqual([]);
    }
    // NMC-022 stats the directory itself, which succeeds: measured, so it stands.
    expect(byCheck(findings, 'HMA-NMC-022')).toEqual([
      expect.objectContaining({ passed: true }),
    ]);
    expect(unread(findings)).toEqual([{ file: skills, code: 'EACCES', operation: 'list' }]);
  });

  it('keeps a measured failure and discloses each lost path once', async () => {
    const { home, target } = fixture();
    const readable = path.join(home, '.nemoclaw', 'a.conf');
    const sealed = path.join(home, '.nemoclaw', 'b.conf');
    writeFile(readable, 'heartbeat_url=http://example.invalid/hb\n');
    writeFile(sealed, 'region=us\n', 0o000);

    const findings = await scan(home, target);

    // NMC-023 measured an HTTP heartbeat in the readable file: that stands.
    expect(byCheck(findings, 'HMA-NMC-023')).toEqual([
      expect.objectContaining({ passed: false }),
    ]);
    // NMC-001 and NMC-023 both walked ~/.nemoclaw and both lost b.conf.
    expect(byCheck(findings, 'HMA-NMC-001').filter((f) => f.passed === true)).toEqual([]);
    expect(unread(findings)).toEqual([{ file: sealed, code: 'EACCES', operation: 'read' }]);
  });
});
