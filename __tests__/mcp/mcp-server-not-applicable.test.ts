/**
 * #458 — the benchmark assessor must not read a not-applicable record as the
 * legacy "no false => pass".
 *
 * Measured at the extraction commit (088d451, behaviour-identical to main):
 * an NA record carries `passed: undefined`, so `checkIdResults.get(id) !==
 * false` credited its control as [PASS] and an L1 assessment fed NOTHING BUT
 * an NA record read 100% compliance with every control passing. The three
 * NA-bucket cells below go red there; the compatibility cells (measured
 * pass/fail beside an NA sibling, absent-record legacy credit) stay green at
 * both commits — they pin what #458 must NOT change.
 */
import { describe, it, expect } from 'vitest';
import { assessBenchmarkFindings } from '../../src/mcp-server';
import { getControlsForLevel } from '../../src/benchmarks/oasb-1';

// Real L1 controls selected by SHAPE, not by hardcoded id: one with a single
// checkId, one with at least two. The checkId->control mapping is
// MANY-TO-MANY (measured: PROMPT-001 serves three L1 controls, so one NA
// record moved three controls at once) — fixtures are restricted to controls
// whose checkIds no other control cites, so every delta below is exactly 1.
// If the control census changes, the premise cell fails loudly instead of the
// suite testing nothing.
const L1 = getControlsForLevel('L1');
const citations = (id: string) => L1.filter((c) => c.checkIds.includes(id)).length;
const single = L1.find((c) => c.checkIds.length === 1 && citations(c.checkIds[0]) === 1)!;
const multi = L1.find((c) => c.checkIds.length >= 2 && c.checkIds.every((id) => citations(id) === 1))!;

const na = (checkId: string) => ({
  checkId,
  notApplicable: { subject: 'system prompt', reason: 'no prompt file exists in the scanned tree' },
});
const pass = (checkId: string) => ({ checkId, passed: true });
const fail = (checkId: string) => ({ checkId, passed: false });

const baseline = assessBenchmarkFindings([], 'L1');

describe('#458 benchmark assessor: not-applicable bucket', () => {
  it('pins the premise: fixture controls exist and the empty baseline is all legacy credit', () => {
    expect(single).toBeDefined();
    expect(multi).toBeDefined();
    expect(baseline.failed).toBe(0);
    // Every absent record is credited as a pass (legacy, kept — see below).
    expect(baseline.compliance).toBe(100);
  });

  it('an NA record moves its control out of passed into notApplicable', () => {
    const a = assessBenchmarkFindings([na(single.checkIds[0])], 'L1');
    expect(a.notApplicable).toBe(baseline.notApplicable + 1);
    expect(a.passed).toBe(baseline.passed - 1);
    expect(a.failed).toBe(baseline.failed);
    expect(a.lines).toContain(
      `[NOT-APPLICABLE] ${single.id} ${single.name} (${single.checkIds[0]}: no system prompt)`,
    );
    expect(a.lines).not.toContain(`[PASS] ${single.id} ${single.name}`);
  });

  it('NA is excluded from the compliance denominator and named in the summary line', () => {
    const a = assessBenchmarkFindings([na(single.checkIds[0])], 'L1');
    // If NA were bucketed as a failure, the denominator would keep the
    // control and compliance would drop below 100.
    expect(a.compliance).toBe(100);
    expect(a.text).toContain('Not applicable: 1');
  });

  it('NA + an absent sibling checkId still reads NOT-APPLICABLE, not the legacy absent-record pass', () => {
    const a = assessBenchmarkFindings([na(multi.checkIds[0])], 'L1');
    expect(a.lines).toContain(
      `[NOT-APPLICABLE] ${multi.id} ${multi.name} (${multi.checkIds[0]}: no system prompt)`,
    );
    expect(a.notApplicable).toBe(baseline.notApplicable + 1);
  });

  it('compat: one NA + one measured pass on the same control reads PASS', () => {
    const a = assessBenchmarkFindings([na(multi.checkIds[0]), pass(multi.checkIds[1])], 'L1');
    expect(a.lines).toContain(`[PASS] ${multi.id} ${multi.name}`);
    expect(a.notApplicable).toBe(baseline.notApplicable);
  });

  it('compat: one NA + one measured failure reads FAIL, naming only the measured check', () => {
    const a = assessBenchmarkFindings([na(multi.checkIds[0]), fail(multi.checkIds[1])], 'L1');
    expect(a.lines).toContain(`[FAIL] ${multi.id} ${multi.name} (${multi.checkIds[1]})`);
    expect(a.failed).toBe(baseline.failed + 1);
    expect(a.notApplicable).toBe(baseline.notApplicable);
  });

  it('compat: pins the legacy credit #458 deliberately keeps — a control with NO records still passes', () => {
    // Kept, not endorsed: the #458 ruling narrows the credit only where a
    // positive NA record exists. This cell exists so a future fix of the
    // absent-record credit is loud, not silent.
    expect(baseline.passed).toBeGreaterThan(0);
    expect(baseline.lines).toContain(`[PASS] ${single.id} ${single.name}`);
  });
});
