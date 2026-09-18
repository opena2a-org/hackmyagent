/**
 * DEP-001 reads a package manifest as its subject, not a lock file.
 *
 * Since #636 an absent-subject check emits a not-applicable record. DEP-001
 * ("No lock file found") was carved out as an absent-mitigation advisory whose
 * `file` names the path the fix creates, and that carried it past the CLI's
 * file-less filter: an EMPTY directory, a Python agent, a skill directory,
 * anything with no package.json, scored a MEDIUM advising a lock file for
 * dependencies it never declared (measured in the 0.33.0 release test: an
 * empty tree scored 93 where 0.32.0 scored 98).
 *
 * The ruled contract, mirroring DEP-002/DEP-003/LOG-004 on the same subject:
 *
 *   package.json absent            -> not-applicable record naming package.json,
 *                                     no severity, `passed` omitted, never on
 *                                     the render channel, no score deduction;
 *   package.json read, no lock     -> the MEDIUM advisory, byte-identical to
 *                                     before, `file: 'package-lock.json'`;
 *   package.json read, lock read   -> measured pass.
 *
 * The lock file stays the MEASURED substance; only the subject moved.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'fs/promises';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import * as path from 'path';
import * as os from 'os';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { SecurityFinding, ScanResult } from '../../src/hardening/security-check';
import { initThrowawayRepo } from '../helpers/throwaway-repo';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

const SCAN_TIMEOUT = 120_000;

const tempDirs: string[] = [];

const MANIFEST = JSON.stringify({ name: 'manifest-fixture', version: '1.0.0' }, null, 2);
const LOCK = JSON.stringify(
  { name: 'manifest-fixture', version: '1.0.0', lockfileVersion: 3, packages: {} },
  null,
  2,
);

async function makeTree(files: Record<string, string>): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-dep001-'));
  tempDirs.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    await fs.writeFile(path.join(dir, rel), content);
  }
  initThrowawayRepo(dir);
  return dir;
}

async function scanTree(dir: string): Promise<ScanResult> {
  return new HardeningScanner().scan({ targetDir: dir });
}

function dep001(findings: SecurityFinding[] | undefined): SecurityFinding[] {
  return (findings ?? []).filter((f) => f.checkId === 'DEP-001');
}

afterAll(async () => {
  for (const dir of tempDirs) {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

describe('DEP-001 with no package manifest in the tree', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await scanTree(await makeTree({}));
  }, SCAN_TIMEOUT);

  it('emits exactly one not-applicable record naming package.json, with no severity and passed omitted', () => {
    const records = dep001(result.allFindings);
    expect(records).toHaveLength(1);
    const f = records[0];
    expect(f.notApplicable?.subject).toBe('package.json');
    expect(f.notApplicable?.reason).toBeTruthy();
    expect(f.severity).toBeUndefined();
    expect(f.file).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(f, 'passed')).toBe(false);
  });

  it('never reaches the render channel', () => {
    expect(dep001(result.findings)).toHaveLength(0);
  });
});

describe('DEP-001 with a package manifest and no lock file', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await scanTree(await makeTree({ 'package.json': MANIFEST }));
  }, SCAN_TIMEOUT);

  it('keeps the MEDIUM advisory with file naming the path the fix creates', () => {
    const records = dep001(result.allFindings);
    expect(records).toHaveLength(1);
    const f = records[0];
    expect(f.passed).toBe(false);
    expect(f.severity).toBe('medium');
    expect(f.file).toBe('package-lock.json');
    expect(f.notApplicable).toBeUndefined();
    expect(f.message).toBe('No lock file found - dependency versions may vary between installs');
  });

  it('renders the advisory', () => {
    expect(dep001(result.findings).some((f) => f.passed === false)).toBe(true);
  });
});

describe('DEP-001 with a package manifest and a lock file', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await scanTree(await makeTree({ 'package.json': MANIFEST, 'package-lock.json': LOCK }));
  }, SCAN_TIMEOUT);

  it('passes as a measured verdict', () => {
    const records = dep001(result.allFindings);
    expect(records).toHaveLength(1);
    const f = records[0];
    expect(f.passed).toBe(true);
    expect(f.severity).toBe('medium');
    expect(f.notApplicable).toBeUndefined();
    expect(dep001(result.findings)).toHaveLength(0);
  });
});

// The CLI half: the score an empty directory prints. The check-level tests
// above pin the record shape; this one pins that the CLI's file-less filter
// no longer lets the advisory through and that no deduction is taken for it.
describe('secure on an empty directory (CLI)', () => {
  beforeAll(assertDistFreshIfPresent);

  const REPO_ROOT = path.join(__dirname, '..', '..');
  const CLI = path.join(REPO_ROOT, 'dist', 'cli.js');
  const canRun = () => existsSync(CLI);

  const spawned: string[] = [];
  afterAll(() => {
    for (const d of spawned) {
      try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  function secureJson(dir: string): { score: number; findings: SecurityFinding[]; allFindings: SecurityFinding[] } {
    // A sandboxed HOME so a machine-level AI runtime cannot enter the picture.
    const home = mkdtempSync(path.join(os.tmpdir(), 'hackmyagent-dep001-home-'));
    spawned.push(home);
    const r = spawnSync(process.execPath, [CLI, 'secure', dir, '--ci', '--json'], {
      encoding: 'utf8',
      env: { ...process.env, HOME: home, OPENA2A_CORPUS_DETERMINISTIC: '' },
    });
    return JSON.parse((r.stdout || '').trim());
  }

  it.runIf(canRun())('carries no DEP-001 finding, a not-applicable record in --json, and the same score as a tree whose manifest is locked', () => {
    const empty = mkdtempSync(path.join(os.tmpdir(), 'hackmyagent-dep001-empty-'));
    spawned.push(empty);
    const locked = mkdtempSync(path.join(os.tmpdir(), 'hackmyagent-dep001-locked-'));
    spawned.push(locked);
    writeFileSync(path.join(locked, 'package.json'), MANIFEST);
    writeFileSync(path.join(locked, 'package-lock.json'), LOCK);

    const emptyRun = secureJson(empty);
    expect(dep001(emptyRun.findings)).toHaveLength(0);
    const records = dep001(emptyRun.allFindings);
    expect(records).toHaveLength(1);
    expect(records[0].notApplicable?.subject).toBe('package.json');
    expect(records[0].severity).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(records[0], 'passed')).toBe(false);

    // No deduction: a not-applicable DEP-001 and a passing DEP-001 both weigh
    // nothing, so the two trees score alike. Before the fix the empty tree
    // was 5 points lower (93 against 98).
    const lockedRun = secureJson(locked);
    expect(dep001(lockedRun.allFindings)[0]?.passed).toBe(true);
    expect(emptyRun.score).toBe(lockedRun.score);
  }, SCAN_TIMEOUT);
});
