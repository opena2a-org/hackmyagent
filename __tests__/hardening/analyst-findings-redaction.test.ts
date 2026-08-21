/**
 * The analyst advisory channel's open-bag redaction — [CHIEF-CISO] 2026-08-21.
 *
 * `analystFindings` rides the secure/check JSON channels raw and is not
 * finding-shaped, so the publish-boundary reader does not see it. Its safety
 * used to rest on a prose invariant ("the analyst's input is already-redacted
 * finding text") that one upstream edit could break silently. The
 * `redactOpenBagForPublish` call at the push site in `runAnalystOnFindings`
 * makes it structural; this file proves the WIRING by injection through the
 * real function with a stubbed inference backend — not by grep, which dead
 * code satisfies.
 */
import { describe, it, expect } from 'vitest';
import { emitFinding } from '../../src/hardening/finding-emit';
import type { SecurityFinding, SecurityFindingDraft } from '../../src/hardening/security-check';
import { runAnalystOnFindingsForTest } from '../../src/nanomind-core/orchestrate';

/** Synthesised at runtime — never a literal in the source tree. */
const GH = `ghp_${'a'.repeat(36)}`;
const GH_MARK = '[REDACTED_GITHUB_TOKEN]';

function emitted(over: Record<string, unknown> = {}): SecurityFinding {
  return emitFinding({
    checkId: 'TEST-ANALYST-001',
    name: 'analyst channel test finding',
    description: 'exercises the analyst advisory channel',
    category: 'credentials',
    severity: 'critical',
    passed: false,
    message: 'analyst channel test message',
    fixable: false,
    file: 'x.ts',
    ...over,
  } as unknown as SecurityFindingDraft);
}

describe('analyst advisory channel: the open-bag redaction is wired, not prose', () => {
  // RED-PROOF: remove the `redactOpenBagForPublish` call at the push site in
  // `runAnalystOnFindings` (orchestrate.ts) — this case goes red with the raw
  // canary present in the response bag.
  it('a credential-bearing analyst response is redacted before it can reach a channel', async () => {
    expect(GH.length, 'canary must clear the ghp_ 36-char pattern gate').toBe(40);
    const stubInference = (async () => ({
      taskType: 'threatAnalysis',
      result: { analysis: `exposed token ${GH}`, nested: [{ note: `again ${GH}` }] },
      confidence: 0.9,
      modelVersion: 'stub',
      durationMs: 1,
      backend: 'stub',
    })) as never;
    const out = await runAnalystOnFindingsForTest([emitted()], stubInference);
    expect(out.length, 'stub inference must produce a response or this test is vacuous').toBe(1);
    const text = JSON.stringify(out);
    expect(text).not.toContain(GH);
    expect(text).toContain(GH_MARK);
  });

  it('control: a benign analyst response passes through with its scalar fields intact', async () => {
    const stubInference = (async () => ({
      taskType: 'checkExplanation',
      result: { analysis: 'benign prose only' },
      confidence: 0.5,
      modelVersion: 'stub',
      durationMs: 1,
      backend: 'stub',
    })) as never;
    const out = await runAnalystOnFindingsForTest([emitted()], stubInference);
    expect(out.length).toBe(1);
    expect(out[0].confidence).toBe(0.5);
    expect(out[0].taskType).toBe('checkExplanation');
    expect((out[0].result as { analysis: string }).analysis).toBe('benign prose only');
  });
});
