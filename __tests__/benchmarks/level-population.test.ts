/**
 * #652 — a `Not assessed at <level>:` line reads "N of M automated <level>
 * controls produced a result". Before: N counted every record at the level
 * that was not `unverified`, while M counted only the scored automated
 * controls with mapped checks. A refute-only control (#639) or an unscored
 * one produces a result without entering that set, so N could exceed M, and
 * with no automated control the "none has an automated check" sentence sat
 * beside the control's `[-]` row without naming it.
 *
 * Unreachable on the shipped catalogue while 2.1 is the only refute-only
 * control (scored at L1, so its failure gives L1 a figure), which is why the
 * line cells use a catalogue built here. RED-ON-BASE cells fail on bf324d6c;
 * PIN cells pass on both.
 */
import { describe, it, expect } from 'vitest';
import { generateBenchmarkReport } from '../../src/benchmarks/benchmark-report';
import { OASB_1_CATEGORIES, automatedControlsAt, levelPopulation } from '../../src/benchmarks/oasb-1';
import type {
  BenchmarkCategory,
  BenchmarkControl,
  BenchmarkControlResult,
  BenchmarkLevel,
} from '../../src/benchmarks/oasb-1';
import type { SecurityFinding } from '../../src/hardening/security-check';

function control(
  id: string,
  level: BenchmarkLevel,
  scored: boolean,
  verification: BenchmarkControl['verification'],
  checkIds: string[],
): BenchmarkControl {
  return { id, name: `control ${id}`, category: 'Fixture', level, scored, description: `fixture ${id}`, checkIds, verification };
}

function catalogueOf(controls: BenchmarkControl[]): BenchmarkCategory[] {
  return [{ id: 99, name: 'Fixture', description: 'fixture category', controls }];
}

function resultOf(records: Array<[BenchmarkControl, BenchmarkControlResult['status']]>) {
  return {
    categories: [{
      category: 'Fixture',
      compliance: null,
      passed: 0,
      failed: 0,
      unverified: 0,
      notApplicable: 0,
      controls: records.map(([c, status]) => ({ controlId: c.id, name: c.name, level: c.level, status, findings: [] })),
    }],
  };
}

const ids = (records: BenchmarkControlResult[]) => records.map((r) => r.controlId);

describe('#652 the measured count is taken over the denominator the line names', () => {
  it('RED-ON-BASE: refute-only and unscored records that failed are not counted as automated controls that produced a result', () => {
    const automated = control('F.1', 'L2', true, 'automated', ['FX-001']);
    const refuteOnly = control('F.2', 'L2', false, 'forward', ['FX-002']);
    const unscoredManual = control('F.3', 'L2', false, 'manual', ['FX-003']);
    const catalogue = catalogueOf([automated, refuteOnly, unscoredManual]);
    const pop = levelPopulation(
      resultOf([[automated, 'unverified'], [refuteOnly, 'failed'], [unscoredManual, 'failed']]),
      'L2',
      catalogue,
    );
    expect(ids(pop.automated)).toEqual(['F.1']);
    // Base read 2 of 1: "2 of 1 automated L2 control produced a result".
    expect(pop.measured).toBe(0);
    expect(pop.measured).toBeLessThanOrEqual(pop.automated.length);
    expect(ids(pop.outside)).toEqual(['F.2', 'F.3']);
    expect(pop.manualForward).toBe(2);
  });

  it('RED-ON-BASE: with no automated control at the level, a failed refute-only record is named, not left beside "none has an automated check"', () => {
    const refuteOnly = control('F.4', 'L3', false, 'manual', ['FX-004']);
    const noChecks = control('F.5', 'L3', true, 'forward', []);
    const pop = levelPopulation(
      resultOf([[refuteOnly, 'failed'], [noChecks, 'unverified']]),
      'L3',
      catalogueOf([refuteOnly, noChecks]),
    );
    expect(pop.automated).toHaveLength(0);
    expect(pop.measured).toBe(0);
    expect(ids(pop.outside)).toEqual(['F.4']);
  });

  it('RED-ON-BASE (shipped catalogue): every mapped check failing at L1 counts the automated controls once and puts the refute-only control outside them', () => {
    const l1 = OASB_1_CATEGORIES.flatMap((c) => c.controls).filter((c) => c.level === 'L1');
    const findings = [...new Set(l1.flatMap((c) => c.checkIds))].map((checkId) => ({
      checkId,
      name: checkId,
      description: `fixture record for ${checkId}`,
      severity: 'high',
      category: 'fixture',
      message: `fixture message for ${checkId}`,
      passed: false,
    } as SecurityFinding));
    const report = generateBenchmarkReport(findings, 'L1');
    const pop = levelPopulation(report, 'L1');
    const refuteOnly = l1.filter((c) => c.verification !== 'automated' && c.checkIds.length > 0).map((c) => c.id);
    expect(refuteOnly.length, 'the shipped catalogue has a refute-only L1 control; this cell needs one').toBeGreaterThan(0);
    expect(pop.measured).toBe(pop.automated.length);
    expect(ids(pop.outside)).toEqual(refuteOnly);
  });

  it('PIN: a not-applicable automated record still counts as a result, inside the denominator', () => {
    const measuredClean = control('F.6', 'L1', true, 'automated', ['FX-006']);
    const absentSubject = control('F.7', 'L1', true, 'automated', ['FX-007']);
    const silent = control('F.8', 'L1', true, 'automated', ['FX-008']);
    const pop = levelPopulation(
      resultOf([[measuredClean, 'passed'], [absentSubject, 'not-applicable'], [silent, 'unverified']]),
      'L1',
      catalogueOf([measuredClean, absentSubject, silent]),
    );
    expect(ids(pop.automated)).toEqual(['F.6', 'F.7', 'F.8']);
    expect(pop.measured).toBe(2);
    expect(pop.outside).toHaveLength(0);
  });

  it('PIN: the denominator is automatedControlsAt, record for record, at every level of the shipped catalogue', () => {
    for (const level of ['L1', 'L2', 'L3'] as const) {
      const report = generateBenchmarkReport([], level);
      const pop = levelPopulation(report, level);
      expect(ids(pop.automated).sort()).toEqual(automatedControlsAt(level).map((c) => c.id).sort());
      expect(pop.inScope.every((r) => r.level === level)).toBe(true);
    }
  });
});
