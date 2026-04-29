/**
 * Issue #137 — NanoMind English summary on a malicious skill rendered
 * "(low confidence — capped from CRITICAL)" alongside an English description
 * that talked about credential security in circular check-ID-as-topic
 * phrasing. Users read the description and trusted it more than the cap
 * stamp, so the trust break landed on us.
 *
 * Fix: when `capAnalystThreatLevel(threatLevel, confidence)` reports
 * `capped: true`, drop the threatAnalysis finding from the renderable list.
 * The static finding (`AST-CRED-001` etc.) still renders via its own path —
 * the underlying threat is already represented and confidence-capped
 * model output adds no actionable signal.
 *
 * Pre-fix UX:
 *   HIGH  (low confidence — capped from CRITICAL)
 *   This artifact is a security documentation (AST-CRED-001) ...
 *   Confidence: low confidence | nanomind-analyst-v0.1.0 (3110ms)
 *
 * Post-fix UX:
 *   (NanoMind block hidden when every threatAnalysis finding is capped;
 *   static findings render unchanged.)
 */

import { describe, it, expect } from 'vitest';
import { capAnalystThreatLevel } from '@opena2a/cli-ui';

describe('capAnalystThreatLevel cap behavior (#137 precondition)', () => {
  it('caps CRITICAL → HIGH at low confidence', () => {
    const { level, capped } = capAnalystThreatLevel('CRITICAL', 0.3);
    expect(level).toBe('HIGH');
    expect(capped).toBe(true);
  });

  it('does NOT cap CRITICAL at high confidence', () => {
    const { level, capped } = capAnalystThreatLevel('CRITICAL', 0.9);
    expect(level).toBe('CRITICAL');
    expect(capped).toBe(false);
  });

  it('does NOT cap HIGH or below', () => {
    const high = capAnalystThreatLevel('HIGH', 0.3);
    expect(high.capped).toBe(false);
    const medium = capAnalystThreatLevel('MEDIUM', 0.3);
    expect(medium.capped).toBe(false);
  });
});

describe('renderableAnalystFindings cap-filter (#137)', () => {
  // The filter pattern used in cli.ts:1336-1352. Pulled out here so the
  // contract is pinned independent of the rest of the CLI render flow.
  type AnalystFinding = {
    taskType: string;
    confidence: number;
    result: { threatLevel?: string };
  };

  function filterCappedThreatAnalysis(findings: AnalystFinding[]): AnalystFinding[] {
    return findings.filter(af => {
      if (af.taskType !== 'threatAnalysis') return true;
      const { capped } = capAnalystThreatLevel(af.result.threatLevel, af.confidence);
      return !capped;
    });
  }

  it('drops a low-confidence CRITICAL threatAnalysis finding', () => {
    const findings: AnalystFinding[] = [
      { taskType: 'threatAnalysis', confidence: 0.3, result: { threatLevel: 'CRITICAL' } },
    ];
    expect(filterCappedThreatAnalysis(findings)).toHaveLength(0);
  });

  it('keeps a high-confidence CRITICAL threatAnalysis finding', () => {
    const findings: AnalystFinding[] = [
      { taskType: 'threatAnalysis', confidence: 0.9, result: { threatLevel: 'CRITICAL' } },
    ];
    expect(filterCappedThreatAnalysis(findings)).toHaveLength(1);
  });

  it('keeps non-threatAnalysis findings regardless of confidence', () => {
    // intelReport, governanceReasoning, credentialContextClassification, and
    // checkExplanation tasks are NOT subject to the cap — different render
    // shape, no severity stamp.
    const findings: AnalystFinding[] = [
      { taskType: 'intelReport', confidence: 0.2, result: {} },
      { taskType: 'governanceReasoning', confidence: 0.3, result: {} },
      { taskType: 'credentialContextClassification', confidence: 0.1, result: {} },
      { taskType: 'checkExplanation', confidence: 0.4, result: {} },
    ];
    expect(filterCappedThreatAnalysis(findings)).toHaveLength(4);
  });

  it('mixed list: drops capped, keeps high-confidence and non-threatAnalysis', () => {
    const findings: AnalystFinding[] = [
      { taskType: 'threatAnalysis', confidence: 0.3, result: { threatLevel: 'CRITICAL' } }, // dropped
      { taskType: 'threatAnalysis', confidence: 0.9, result: { threatLevel: 'CRITICAL' } }, // kept
      { taskType: 'intelReport', confidence: 0.2, result: {} }, // kept
      { taskType: 'threatAnalysis', confidence: 0.85, result: { threatLevel: 'HIGH' } }, // kept (not capped)
    ];
    const result = filterCappedThreatAnalysis(findings);
    expect(result).toHaveLength(3);
    expect(result.map(r => r.taskType)).toEqual(['threatAnalysis', 'intelReport', 'threatAnalysis']);
  });
});
