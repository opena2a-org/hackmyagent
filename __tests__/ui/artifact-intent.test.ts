// Regression gate for the raw NanoMind intent label on the Observations
// `Artifacts` line (closes #252).
//
// The defect: the Artifacts line printed the classifier's raw intent class
// verbatim, so a benign hardened SOUL rendered
//
//   Artifacts   SOUL.md  soul · malicious · no inferred capabilities
//
// three lines under a 94-100/100 score and a clean Verdict — the same output
// contradicting itself. The classifier (0.5.0) over-flags benign and OOD
// input at max confidence; every other surface in HMA keeps its raw verdict
// advisory, and this one did not.
//
// Two layers, mirroring check-secure-cross-analyzer-parity.test.ts:
//  1. Deterministic unit layer over the pure reconciler. Runs everywhere.
//  2. Spawned end-to-end layer over the real corpus fixtures, local-only.
//     Asserts BOTH directions: the uncorroborated label is withheld on the
//     benign SOUL, and the corroborated label still prints on the malicious
//     one, so the fix cannot degenerate into blanket suppression.

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  reconcileArtifactIntents,
  rawIntentDisclosureLines,
  type ArtifactIntent,
} from '../../src/ui/artifact-intent';

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');
const CORPUS = join(homedir(), '.opena2a', 'corpus', 'soul');
const BENIGN_FIXTURE = join(CORPUS, 'benign', 'hardened-soul');
const MALICIOUS_FIXTURE = join(CORPUS, 'malicious', 'permissive-overrides-soul');

function canRun(fixture: string): boolean {
  if (process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true') return false;
  return existsSync(CLI) && existsSync(fixture);
}

function artifact(path: string, intent: ArtifactIntent) {
  return { path, intent, type: 'soul', capabilityLabels: [], constraintCount: 0, weakConstraintCount: 0 };
}

describe('artifact intent reconciliation (deterministic — #252 contract gate)', () => {
  it('withholds an uncorroborated malicious label', () => {
    const { artifacts, suppressed } = reconcileArtifactIntents(
      [artifact('SOUL.md', 'malicious')],
      [{ file: '.gitignore', severity: 'low' }],
    );

    expect(artifacts[0].intent).toBe('unknown');
    expect(suppressed).toEqual([{ path: 'SOUL.md', rawIntent: 'malicious' }]);
  });

  it('withholds an uncorroborated suspicious label', () => {
    const { artifacts } = reconcileArtifactIntents([artifact('SKILL.md', 'suspicious')], []);
    expect(artifacts[0].intent).toBe('unknown');
  });

  it('keeps a malicious label this scan corroborates with a high finding', () => {
    const { artifacts, suppressed } = reconcileArtifactIntents(
      [artifact('SOUL.md', 'malicious')],
      [{ file: 'SOUL.md', severity: 'high' }],
    );

    expect(artifacts[0].intent).toBe('malicious');
    expect(suppressed).toEqual([]);
  });

  it('keeps a malicious label corroborated by a critical finding', () => {
    const { artifacts } = reconcileArtifactIntents(
      [artifact('SOUL.md', 'malicious')],
      [{ file: 'SOUL.md', severity: 'critical' }],
    );
    expect(artifacts[0].intent).toBe('malicious');
  });

  it('does not treat a medium or low finding as corroboration', () => {
    // 94-98/100 scans in #252 still carried medium/low findings. If those
    // corroborated, the reported cases would still print "malicious".
    for (const severity of ['medium', 'low', 'info']) {
      const { artifacts } = reconcileArtifactIntents(
        [artifact('SOUL.md', 'malicious')],
        [{ file: 'SOUL.md', severity }],
      );
      expect(artifacts[0].intent, `severity ${severity} must not corroborate`).toBe('unknown');
    }
  });

  it('does not let a high finding on one artifact corroborate another', () => {
    const { artifacts } = reconcileArtifactIntents(
      [artifact('SOUL.md', 'malicious'), artifact('SKILL.md', 'malicious')],
      [{ file: 'SKILL.md', severity: 'high' }],
    );

    expect(artifacts[0].intent).toBe('unknown');
    expect(artifacts[1].intent).toBe('malicious');
  });

  it('matches an absolute finding path against the relative artifact path', () => {
    const { artifacts } = reconcileArtifactIntents(
      [artifact('SOUL.md', 'malicious')],
      [{ file: '/tmp/hma-scan-abc/SOUL.md', severity: 'high' }],
    );
    expect(artifacts[0].intent).toBe('malicious');
  });

  it('does not match a same-named file in a nested directory', () => {
    // `nested/SOUL.md` is its own artifact with its own summary line; a
    // finding on it must not clear the root SOUL.md.
    const { artifacts } = reconcileArtifactIntents(
      [artifact('SOUL.md', 'malicious')],
      [{ file: 'nested/SOUL.md', severity: 'high' }],
    );
    expect(artifacts[0].intent).toBe('unknown');
  });

  it('passes benign and unknown through untouched and reports nothing withheld', () => {
    // The model's failure mode is over-flagging, so a negative prediction
    // needs no corroboration.
    const { artifacts, suppressed } = reconcileArtifactIntents(
      [artifact('a.md', 'benign'), artifact('b.md', 'unknown')],
      [],
    );

    expect(artifacts.map(a => a.intent)).toEqual(['benign', 'unknown']);
    expect(suppressed).toEqual([]);
  });

  it('never mutates its input', () => {
    const input = [artifact('SOUL.md', 'malicious')];
    reconcileArtifactIntents(input, []);
    expect(input[0].intent).toBe('malicious');
  });

  it('qualifies every disclosed raw label as advisory and over-flagging', () => {
    const lines = rawIntentDisclosureLines([{ path: 'SOUL.md', rawIntent: 'malicious' }]);
    const text = lines.join('\n');

    expect(text).toMatch(/over-flags benign/i);
    expect(text).toMatch(/not a verdict/i);
    expect(text).toContain('SOUL.md');
    expect(text).toContain('malicious');
  });

  it('emits no disclosure when nothing was withheld', () => {
    expect(rawIntentDisclosureLines([])).toEqual([]);
  });
});

describe('Artifacts line does not contradict the score (spawn, local-only)', { timeout: 180_000 }, () => {
  it.runIf(canRun(BENIGN_FIXTURE))('withholds the raw label on a benign hardened SOUL', () => {
    const res = spawnSync('node', [CLI, 'check', BENIGN_FIXTURE, '--ci', '--verbose'], {
      encoding: 'utf8',
      timeout: 120_000,
    });

    const stdout = res.stdout || '';
    const artifactLine = stdout.split('\n').find(l => l.includes('Artifacts'));

    // Non-vacuity part 1: the line under test must actually render. A
    // fixture that produced no Artifacts block would satisfy every
    // "must not say malicious" assertion for the wrong reason.
    expect(artifactLine, 'no Artifacts line rendered — assertions would be vacuous').toBeTruthy();
    expect(artifactLine).toContain('SOUL.md');

    // Non-vacuity part 2: the classifier must actually have produced a
    // concerning label here, otherwise there was nothing to withhold.
    // The verbose disclosure only renders when something was withheld.
    expect(stdout, 'classifier did not flag this fixture — nothing was withheld').toMatch(
      /raw NanoMind classifier affinity/i,
    );

    // The defect itself: the withheld class must not reach the line.
    expect(artifactLine).not.toMatch(/·\s*malicious\s*·/);
    expect(artifactLine).not.toMatch(/·\s*suspicious\s*·/);
  });

  it.runIf(canRun(BENIGN_FIXTURE))('keeps the raw label out of default (non-verbose) output entirely', () => {
    const res = spawnSync('node', [CLI, 'check', BENIGN_FIXTURE, '--ci'], {
      encoding: 'utf8',
      timeout: 120_000,
    });

    const stdout = res.stdout || '';
    expect(stdout).toContain('Artifacts');
    expect(stdout).not.toMatch(/raw NanoMind classifier affinity/i);
    expect(stdout).not.toMatch(/·\s*malicious\s*·/);
  });

  it.runIf(canRun(MALICIOUS_FIXTURE))('still prints a corroborated malicious label', () => {
    const res = spawnSync('node', [CLI, 'check', MALICIOUS_FIXTURE, '--ci'], {
      encoding: 'utf8',
      timeout: 120_000,
    });

    const stdout = res.stdout || '';
    const artifactLine = stdout.split('\n').find(l => l.includes('Artifacts'));

    expect(artifactLine, 'no Artifacts line rendered').toBeTruthy();
    // The reconciliation must not degenerate into blanket suppression: the
    // malicious SOUL fires 4 HIGH governance/prompt findings on SOUL.md,
    // which is exactly the corroboration the rule asks for.
    expect(artifactLine).toMatch(/·\s*malicious\s*·/);
  });
});
