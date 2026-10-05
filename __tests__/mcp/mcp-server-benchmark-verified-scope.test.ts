/**
 * #531 — `hackmyagent_benchmark` stated its compliance figure without its
 * denominator.
 *
 * The figure is passed / (passed + failed) over the scored controls that
 * produced a result; an unverified control is outside it (the ruled #458
 * step 3 contract, unchanged here). Stated bare on the headline, a run that
 * verified 4 controls read `100% compliance (Certified)` while a run over the
 * same level that verified 23 read `91% compliance (Passing)`: the host agent
 * received a number that rose as the assessment narrowed, with the denominator
 * left to inference from a count line. The headline now names the controls
 * the figure is over, and a coverage line names the unverified ones as outside
 * it. The figure and the rating themselves are unchanged.
 */
import { describe, it, expect } from 'vitest';
import { assessBenchmarkFindings } from '../../src/mcp-server';
import { getControlsForLevel } from '../../src/benchmarks/oasb-1';
import type { SecurityFinding } from '../../src/hardening/security-check';

// Automated, scored L1 controls whose checkIds no other L1 control cites, so
// one record settles exactly one control. Selected by shape, not by id.
const L1 = getControlsForLevel('L1');
const citations = (id: string) => L1.filter((c) => c.checkIds.includes(id)).length;
const settleable = L1.filter(
  (c) => c.scored && c.verification === 'automated' && c.checkIds.length > 0 && c.checkIds.every((id) => citations(id) === 1),
);

const record = (checkId: string, passed: boolean): SecurityFinding =>
  ({
    checkId,
    name: checkId,
    description: `fixture record for ${checkId}`,
    severity: 'medium',
    category: 'fixture',
    message: 'fixture',
    passed,
  }) as SecurityFinding;
const passing = (n: number) => settleable.slice(0, n).flatMap((c) => c.checkIds.map((id) => record(id, true)));

const headline = (text: string) => text.split('\n')[0];

describe('#531 the MCP benchmark figure names the controls it is over', () => {
  it('premise: enough settleable controls exist for every cell below', () => {
    expect(settleable.length).toBeGreaterThanOrEqual(4);
  });

  it('a narrow run names its denominator on the headline and the unverified controls as outside it', () => {
    const a = assessBenchmarkFindings(passing(2), 'L1');
    expect(a.passed).toBe(2);
    expect(a.failed).toBe(0);
    // The figure itself is the ruled one, unchanged.
    expect(a.compliance).toBe(100);
    const total = a.passed + a.failed + a.notApplicable + a.unverified;
    expect(headline(a.text)).toBe(`OASB-1 L1 Assessment: 100% compliance over 2 verified controls (${a.rating})`);
    expect(a.text).toContain(
      `Coverage: 2 of ${total} controls verified. The ${a.unverified} unverified controls are not in the compliance figure; each is listed as [UNVERIFIED] below.`,
    );
  });

  it('when a narrower run reads higher, each headline shows the smaller denominator beside the higher figure', () => {
    const narrow = assessBenchmarkFindings(passing(2), 'L1');
    const failingFirst = settleable[0].checkIds.map((id) => record(id, false));
    const wide = assessBenchmarkFindings([...failingFirst, ...passing(4).slice(failingFirst.length)], 'L1');
    expect(wide.failed).toBe(1);
    // The issue's premise: fewer verified controls, higher figure.
    expect(narrow.compliance!).toBeGreaterThan(wide.compliance!);
    expect(headline(narrow.text)).toContain(`over ${narrow.passed + narrow.failed} verified controls`);
    expect(headline(wide.text)).toContain(`over ${wide.passed + wide.failed} verified controls`);
    expect(narrow.passed + narrow.failed).toBeLessThan(wide.passed + wide.failed);
  });

  it('one verified control reads in the singular', () => {
    const a = assessBenchmarkFindings(passing(1), 'L1');
    expect(headline(a.text)).toContain('100% compliance over 1 verified control (');
    expect(a.text).toContain('Coverage: 1 of ');
  });

  it('a level with no measured control keeps its not-measured headline and adds no coverage line', () => {
    const a = assessBenchmarkFindings([], 'L1');
    expect(a.compliance).toBeNull();
    expect(headline(a.text)).toBe('OASB-1 L1 Assessment: not measured (Not Assessed)');
    expect(a.text).not.toContain('Coverage:');
  });
});
