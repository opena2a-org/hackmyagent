/**
 * The coverage-sweep escalation channel's redaction.
 *
 * This is the STRONGER half of the analyst advisory channel and the one that
 * was left prose-guarded when the per-finding half was closed (adversarial
 * review 2026-08-21, F3): `runAnalystOnFindings` builds its prompt from
 * already-redacted finding text, but the sweep hands the model the RAW
 * artifact file, so the model's own narrative can quote a credential it read.
 * Those rows ride `secure --json` and every `check --json` path, and they
 * carry no `passed` field, so the publish-boundary reader exempts them by
 * shape — nothing else would catch them.
 *
 * Proven by injection through the real `runCoverageSweep` with a stubbed
 * classifier, not by grep.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCoverageSweep } from '../../src/nanomind-core/orchestrate';
import type { CoverageCandidate } from '../../src/nanomind-core/scanner-bridge';
import type { ArtifactCoverageVerdict } from '../../src/nanomind-core/inference/security-analyst';

/** Synthesised at runtime — never a literal in the source tree. */
const GH = `ghp_${'a'.repeat(36)}`;
const GH_MARK = '[REDACTED_GITHUB_TOKEN]';

/** A verdict that routes to `attack`: known class + high severity. */
function quotingVerdict(text: string): ArtifactCoverageVerdict {
  return {
    attackClass: 'credential_abuse',
    classification: 'malicious',
    severity: 'high',
    confidence: 0.9,
    source: 'nlm',
    analysis: text,
    modelVersion: 'stub-1',
  } as ArtifactCoverageVerdict;
}

async function sweepWith(verdict: ArtifactCoverageVerdict) {
  const dir = await mkdtemp(join(tmpdir(), 'hma-sweep-'));
  try {
    await writeFile(join(dir, 'SKILL.md'), 'irrelevant — the stub classifier decides the verdict\n');
    const candidates: CoverageCandidate[] = [
      { path: 'SKILL.md', artifactType: 'skill' } as CoverageCandidate,
    ];
    return await runCoverageSweep(dir, candidates, [], async () => verdict, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

describe('coverage-sweep escalations are redacted before they can reach a channel', () => {
  // RED-PROOF: remove the `redactOpenBagForPublish` wrap around the
  // `escalations.push({...})` call in orchestrate.ts — this case goes red with
  // the raw canary present in `summary`.
  it('a model narrative quoting a credential ships the marker, not the bytes', async () => {
    expect(GH.length, 'canary must clear the ghp_ 36-char pattern gate').toBe(40);
    const outcome = await sweepWith(quotingVerdict(`the file contains ${GH} in plain text`));
    expect(
      outcome.escalations.length,
      'the stub must actually escalate or this test is vacuous',
    ).toBe(1);
    const text = JSON.stringify(outcome.escalations);
    expect(text).not.toContain(GH);
    expect(text).toContain(GH_MARK);
  });

  it('control: a benign narrative survives unchanged, including its scalar fields', async () => {
    const outcome = await sweepWith(quotingVerdict('the skill declares broad filesystem access'));
    expect(outcome.escalations.length).toBe(1);
    const row = outcome.escalations[0];
    expect(row.summary).toBe('the skill declares broad filesystem access');
    expect(row.attackClass).toBe('credential_abuse');
    expect(row.routed).toBe('attack');
    expect(row.file).toBe('SKILL.md');
    expect(row.policy).toBe('abstention-gated');
  });
});
