// Cross-analyzer direction-agreement gate for `check <localdir>` vs
// `secure <localdir>` (closes #200).
//
// The defect: `check <dir>` runs only the NanoMind semantic artifact
// matrix — it never runs the static rule suite — yet its Observations
// block claimed the full static suite had run ("310 static"), marked
// every category including `credentials` as "(all clear)", and closed
// with the absolute verdict "No security issues detected. This local
// project looks safe to use." On a directory containing an un-ignored
// `.env` with a password-bearing connection string, `secure` reports
// 1 CRITICAL + 2 HIGH on the same bytes. A `check`-only user was told
// the exposure was safe.
//
// This is the same class as the HMA 0.22.0 release-blocker (cross-
// analyzer direction disagreement) and a CISO Rule 11 violation: an
// absolute label asserting a global verdict the analyzer never
// evaluated.
//
// Two layers, mirroring check-not-found-json.test.ts:
//  1. Deterministic unit layer over the pure copy helper. This is the
//     contract gate and runs in every CI run.
//  2. Spawned parity smoke test, local-only (needs a built dist). It
//     runs BOTH analyzers over one fixture and asserts they agree on
//     direction. No network — the fixture is a temp dir — so the
//     parallel-load flake mode described in #203 does not apply.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { quickScanScopeDisclosure } from '../../src/ui/quick-scan-labels';

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');

function canRunSpawn(): boolean {
  if (process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true') return false;
  return existsSync(CLI);
}

// A password-bearing localhost connection string. Deliberately chosen over
// a vendor-prefixed API key so the fixture cannot trip GitHub push
// protection while still firing SEM-CRED-001 + GIT-003.
const FIXTURE_ENV = 'DATABASE_URL=postgres://user:FAKEpassword@localhost:5432/db\n';

describe('quick-scan scope disclosure (deterministic — #200 contract gate)', () => {
  const disclosure = quickScanScopeDisclosure({
    staticCount: 310,
    semanticCount: 1,
    fullAuditTarget: '/tmp/example',
  });

  it('never emits an absolute safety claim for an un-run matrix', () => {
    // The exact strings the pre-fix build shipped. Either one reaching a
    // user is the CISO Rule 11 violation this issue is about.
    expect(disclosure.cleanVerdict).not.toMatch(/looks safe to use/i);
    expect(disclosure.cleanVerdict).not.toMatch(/no security issues detected/i);
  });

  it('names credentials among what was NOT evaluated', () => {
    // Credentials are the highest-consequence category the quick scan
    // skips, and the one that made #200 dangerous rather than merely
    // imprecise. It must be named explicitly, not implied.
    expect(disclosure.cleanVerdict).toMatch(/credential/i);
  });

  it('routes the user to the analyzer that does evaluate them', () => {
    // No dead ends: the disclosure has to carry the runnable escape hatch.
    expect(disclosure.cleanVerdict).toContain('secure /tmp/example');
  });

  it('does not claim the static suite ran', () => {
    expect(disclosure.checks).toMatch(/not run/i);
    // The advertised suite size may still be cited for context, but only
    // alongside the not-run qualifier asserted above.
    expect(disclosure.checks).toContain('310');
  });

  it('still reports what the semantic matrix actually did', () => {
    expect(disclosure.checks).toMatch(/1 semantic/);
  });

  it('never marks unevaluated categories as clear', () => {
    expect(disclosure.categories).not.toMatch(/all clear/i);
  });
});

describe('check vs secure direction agreement on a local dir (spawn, local-only)', () => {
  let fixture: string;

  beforeAll(() => {
    fixture = mkdtempSync(join(tmpdir(), 'hma-200-parity-'));
    writeFileSync(join(fixture, '.env'), FIXTURE_ENV, 'utf8');
  });

  afterAll(() => {
    if (fixture) rmSync(fixture, { recursive: true, force: true });
  });

  it.runIf(canRunSpawn())('secure establishes the ground truth (>=1 critical or high)', () => {
    const res = spawnSync('node', [CLI, 'secure', fixture, '--ci', '--json'], {
      encoding: 'utf8',
      timeout: 120_000,
    });

    const parsed = JSON.parse((res.stdout || '').trim());
    const failed = (parsed.findings ?? []).filter((f: any) => !f.passed);
    const severe = failed.filter(
      (f: any) => f.severity === 'critical' || f.severity === 'high',
    );

    // If this ever drops to zero the fixture stopped being adversarial and
    // the parity assertions below would pass vacuously.
    expect(severe.length).toBeGreaterThan(0);
  });

  it.runIf(canRunSpawn())('check does not contradict secure with an absolute safe verdict', () => {
    const res = spawnSync('node', [CLI, 'check', fixture, '--ci'], {
      encoding: 'utf8',
      timeout: 120_000,
    });

    const stdout = res.stdout || '';
    expect(stdout.length).toBeGreaterThan(0);

    // The pre-fix misstatements, asserted individually so a regression
    // names which one came back. "No security issues found" is the
    // headline verdict and was a separate surface from the Observations
    // "No security issues detected" — both had to go.
    expect(stdout).not.toMatch(/looks safe to use/i);
    expect(stdout).not.toMatch(/no security issues detected/i);
    expect(stdout).not.toMatch(/no security issues found/i);
    expect(stdout).not.toMatch(/all clear/i);
  });

  it.runIf(canRunSpawn())('check discloses the scope it did not cover', () => {
    const res = spawnSync('node', [CLI, 'check', fixture, '--ci'], {
      encoding: 'utf8',
      timeout: 120_000,
    });

    const stdout = res.stdout || '';
    // Names the skipped category and hands over the command that covers it.
    expect(stdout).toMatch(/credential/i);
    expect(stdout).toContain(`secure ${fixture}`);
  });
});
