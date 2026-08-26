/**
 * #458 step 5 — the benchmark assessor is the ONE shared
 * `generateBenchmarkReport`, under the ruled semantics.
 *
 * The interim assessor these pins replaced (deleted with step 5, as its own
 * doc comment scheduled) kept the legacy credit: a control none of whose
 * checkIds produced ANY record counted as [PASS] — `.get(id) !== false`, the
 * executed defect #458 named. Measured on the pre-step-5 build (ff345e7):
 * `assessBenchmarkFindings([], 'L1')` read 100% compliance — 23 of 26
 * controls passing for free, the rest manual/forward unverified. Under the shared function that baseline is all-[UNVERIFIED],
 * compliance `null`, rating `Not Assessed` (step 0's contract). The
 * absence-is-never-credited cells below are red on that build; the
 * measured-beside-NA compatibility cells keep their meaning.
 */
import { describe, it, expect } from 'vitest';
import { assessBenchmarkFindings } from '../../src/mcp-server';
import { getControlsForLevel } from '../../src/benchmarks/oasb-1';
import type { SecurityFinding } from '../../src/hardening/security-check';

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

// Complete records, not partials: the adapter takes real SecurityFinding[]
// (tsc excludes tests, so a partial would pass vitest while lying about the
// API — the step-5 review caught exactly that).
const base = (checkId: string) => ({
  checkId,
  name: checkId,
  description: `fixture record for ${checkId}`,
  severity: 'medium' as const,
  category: 'fixture',
  message: 'fixture',
});
const na = (checkId: string): SecurityFinding => ({
  ...base(checkId),
  severity: undefined,
  notApplicable: { subject: 'system prompt', reason: 'no prompt file exists in the scanned tree' },
} as SecurityFinding);
const pass = (checkId: string): SecurityFinding => ({ ...base(checkId), passed: true } as SecurityFinding);
const fail = (checkId: string): SecurityFinding => ({ ...base(checkId), passed: false } as SecurityFinding);

const baseline = assessBenchmarkFindings([], 'L1');

describe('#458 step 5: the shared assessor never credits absence', () => {
  it('premise + ruled baseline: no records at all is all-unverified, not measured, Not Assessed', () => {
    expect(single).toBeDefined();
    expect(multi).toBeDefined();
    expect(baseline.passed).toBe(0);
    expect(baseline.failed).toBe(0);
    expect(baseline.notApplicable).toBe(0);
    expect(baseline.compliance).toBeNull();
    expect(baseline.rating).toBe('Not Assessed');
    expect(baseline.text).toContain('not measured');
    expect(baseline.lines).toContain(`[UNVERIFIED] ${single.id} ${single.name}`);
    expect(baseline.lines.some((l) => l.startsWith('[PASS]'))).toBe(false);
  });

  it('an NA record moves its control into notApplicable, named with its absent subject', () => {
    const a = assessBenchmarkFindings([na(single.checkIds[0])], 'L1');
    expect(a.notApplicable).toBe(1);
    expect(a.passed).toBe(0);
    expect(a.failed).toBe(0);
    expect(a.lines).toContain(`[NOT-APPLICABLE] ${single.id} ${single.name} (no system prompt)`);
    expect(a.lines).not.toContain(`[UNVERIFIED] ${single.id} ${single.name}`);
  });

  it('NA is excluded from the denominator: one NA and one measured pass yields 100% over the one measurement', () => {
    const a = assessBenchmarkFindings([na(single.checkIds[0]), pass(multi.checkIds[0]), pass(multi.checkIds[1])], 'L1');
    expect(a.notApplicable).toBe(1);
    expect(a.passed).toBe(1);
    expect(a.compliance).toBe(100);
    expect(a.text).toContain('Not applicable: 1');
  });

  it('NA + an absent sibling checkId still reads NOT-APPLICABLE, never unverified-by-the-sibling', () => {
    const a = assessBenchmarkFindings([na(multi.checkIds[0])], 'L1');
    expect(a.lines).toContain(`[NOT-APPLICABLE] ${multi.id} ${multi.name} (no system prompt)`);
    expect(a.notApplicable).toBe(1);
  });

  it('compat: one NA + one measured pass on the same control reads PASS (measured wins)', () => {
    const a = assessBenchmarkFindings([na(multi.checkIds[0]), pass(multi.checkIds[1])], 'L1');
    expect(a.lines).toContain(`[PASS] ${multi.id} ${multi.name}`);
    expect(a.notApplicable).toBe(0);
  });

  it('compat: one NA + one measured failure reads FAIL, naming only the measured check', () => {
    const a = assessBenchmarkFindings([na(multi.checkIds[0]), fail(multi.checkIds[1])], 'L1');
    expect(a.lines).toContain(`[FAIL] ${multi.id} ${multi.name} (${multi.checkIds[1]})`);
    expect(a.failed).toBe(1);
    expect(a.notApplicable).toBe(0);
  });

  it('the legacy absent-record credit is DEAD: a control with no records is [UNVERIFIED], and nothing passes for free', () => {
    // The interim pin held this door open on purpose ("kept, not endorsed");
    // step 5 closes it. RED on the pre-step-5 build, where this control
    // read [PASS] and the baseline read 100%.
    expect(baseline.lines).toContain(`[UNVERIFIED] ${single.id} ${single.name}`);
    expect(baseline.unverified).toBeGreaterThan(0);
    expect(baseline.compliance).toBeNull();
  });
});
