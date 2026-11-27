/**
 * The benchmark assessor is told what the person running the scan set aside
 * (`--ignore`, `.hmaignore` check and path rules), and a control a withheld
 * check maps to is never credited: unless another of its checks failed it,
 * it is `unverified`, outside every denominator, and marked `suppressed`.
 *
 * Before this, the suppressed records were removed from the findings and the
 * assessor never heard of them: a control whose failing check was ignored read
 * as unverified (leaving the denominator unnamed), and one with a passing
 * sibling check read as passed.
 */
import { describe, it, expect } from 'vitest';
import { generateBenchmarkReport } from '../../src/benchmarks/benchmark-report';
import { getControlsForLevel } from '../../src/benchmarks/oasb-1';
import type { SecurityFinding } from '../../src/hardening/scanner';

// Every L1 control TOOL-001 maps to (2.3 and one other at the time of writing).
const TOOL_001_L1 = getControlsForLevel('L1').filter((c) => c.checkIds.includes('TOOL-001')).map((c) => c.id);

function record(over: Partial<SecurityFinding> & { checkId: string }): SecurityFinding {
  return {
    name: 'x',
    description: 'x',
    category: 'x',
    severity: 'high',
    passed: true,
    message: 'x',
    fixable: false,
    ...over,
  } as SecurityFinding;
}

type Row = { checkId: string; name: string; category: string; severity: string; count: number; suppressedBy: string };
const row = (checkId: string, suppressedBy: string, count = 1): Row =>
  ({ checkId, name: 'x', category: 'x', severity: 'high', count, suppressedBy });

function ctrl(report: ReturnType<typeof generateBenchmarkReport>, id: string) {
  const found = report.categories.flatMap((c) => c.controls).find((c) => c.controlId === id);
  if (!found) throw new Error(`control ${id} not in report`);
  return found;
}

// Control 2.3 (Capability Boundaries, L1, automated) maps TOOL-001/TOOL-002.
// Controls 6.1-6.4 (Supply Chain Integrity, L1) all map DEP-001.
describe('benchmark assessor and the run\'s own suppression', () => {
  it('a suppressed failing check does not let a passing sibling check credit the control', () => {
    const findings = [record({ checkId: 'TOOL-002', passed: true })];
    const plain = generateBenchmarkReport(findings, 'L1');
    expect(ctrl(plain, '2.3').status).toBe('passed');

    const report = generateBenchmarkReport(findings, 'L1', undefined, { rows: [row('TOOL-001', 'ignore-flag')], ignored: ['TOOL-001'] });
    const c = ctrl(report, '2.3');
    expect(c.status).toBe('unverified');
    expect(c.suppressed).toEqual({ checkIds: ['TOOL-001'], suppressedBy: ['ignore-flag'], findings: 1 });
    expect(TOOL_001_L1).toContain('2.3');
    expect(report.suppressedControls).toBe(TOOL_001_L1.length);
    for (const id of TOOL_001_L1) expect(ctrl(report, id).suppressed?.checkIds).toEqual(['TOOL-001']);
    const cat = report.categories.find((x) => x.category === 'Capability & Authorization')!;
    expect(cat.suppressed).toBe(1);
    const plainCat = plain.categories.find((x) => x.category === 'Capability & Authorization')!;
    expect(cat.passed).toBe(plainCat.passed - 1);
    expect(cat.failed).toBe(plainCat.failed);
  });

  it('an --ignore list alone marks the control, even with no withheld row (a clean or unlisted record)', () => {
    const report = generateBenchmarkReport([record({ checkId: 'TOOL-002', passed: true })], 'L1', undefined, { ignored: ['tool-001'] });
    const c = ctrl(report, '2.3');
    expect(c.status).toBe('unverified');
    expect(c.suppressed).toEqual({ checkIds: ['TOOL-001'], suppressedBy: ['ignore-flag'], findings: 0 });
  });

  it('.hmaignore check and path rows mark the control with their own channel', () => {
    const report = generateBenchmarkReport([], 'L1', undefined, {
      rows: [row('DEP-001', 'hmaignore-check', 2), row('DEP-001', 'hmaignore-path')],
    });
    for (const id of ['6.1', '6.2', '6.3', '6.4']) {
      expect(ctrl(report, id).status).toBe('unverified');
      expect(ctrl(report, id).suppressed).toEqual({ checkIds: ['DEP-001'], suppressedBy: ['hmaignore-check', 'hmaignore-path'], findings: 3 });
    }
    expect(report.suppressedControls).toBe(4);
    expect(report.categories.find((x) => x.category === 'Supply Chain Integrity')!.suppressed).toBe(4);
  });

  it('an unsuppressed failure still fails the control, and the suppression is named on it', () => {
    const report = generateBenchmarkReport(
      [record({ checkId: 'TOOL-002', passed: false })],
      'L1', undefined, { rows: [row('TOOL-001', 'ignore-flag')], ignored: ['TOOL-001'] },
    );
    const c = ctrl(report, '2.3');
    expect(c.status).toBe('failed');
    expect(c.suppressed?.checkIds).toEqual(['TOOL-001']);
    // A failed control is scored, so it is not counted as left unscored.
    expect(report.suppressedControls).toBe(TOOL_001_L1.length - 1);
  });

  it('a suppressed check never turns a control not-applicable', () => {
    const na = record({
      checkId: 'TOOL-002',
      passed: undefined as unknown as boolean,
      notApplicable: { subject: 'mcp.json', reason: 'No mcp.json in the scanned tree.' },
    });
    const report = generateBenchmarkReport([na], 'L1', undefined, { ignored: ['TOOL-001'] });
    expect(ctrl(report, '2.3').status).toBe('unverified');
    expect(report.notApplicableControls).toBe(generateBenchmarkReport([na], 'L1').notApplicableControls - 1);
  });

  it('CONTROL: with nothing withheld the document carries no suppression key', () => {
    const findings = [record({ checkId: 'TOOL-001', passed: true }), record({ checkId: 'DEP-001', passed: false })];
    const plain = generateBenchmarkReport(findings, 'L1');
    const empty = generateBenchmarkReport(findings, 'L1', undefined, { rows: [], ignored: ['FOO-999'] });
    expect(plain).not.toHaveProperty('suppressedControls');
    expect(JSON.stringify({ ...empty, timestamp: 0 })).toBe(JSON.stringify({ ...plain, timestamp: 0 }));
    for (const cat of plain.categories) {
      expect(cat).not.toHaveProperty('suppressed');
      for (const c of cat.controls) expect(c).not.toHaveProperty('suppressed');
    }
  });
});
