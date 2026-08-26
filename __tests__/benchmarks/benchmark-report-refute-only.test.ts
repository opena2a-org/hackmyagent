/**
 * #639 — checkIds on a non-automated OASB-1 control are refutation-only.
 *
 * Before: `generateBenchmarkReport` classified every manual/forward control
 * `unverified` BEFORE reading its records, so control 2.1 (forward, mapping
 * SEM-MCP-001 and SEM-MCP-004) never moved on a measured failure — a
 * wildcard MCP grant, the exact violation its audit step names, changed no
 * benchmark figure. Now: records are read for every control that maps
 * checks; a non-automated control's checks can REFUTE it (any measured
 * failure -> `failed`) and never confirm it (clean, absent-subject or no
 * record -> `unverified`, never `passed`, never `not-applicable`).
 *
 * The subject control is selected by SHAPE, not by id, so the file fails
 * loudly if the catalogue census changes. RED-ON-BASE cells fail on the
 * 2a39b72 build; PIN cells pass on both.
 */
import { describe, it, expect } from 'vitest';
import { generateBenchmarkReport } from '../../src/benchmarks/benchmark-report';
import { OASB_1_CATEGORIES, getControlsForLevel } from '../../src/benchmarks/oasb-1';
import type { BenchmarkControl } from '../../src/benchmarks/oasb-1';
import { assessBenchmarkFindings } from '../../src/mcp-server';
import type { SecurityFinding } from '../../src/hardening/security-check';

const ALL: BenchmarkControl[] = OASB_1_CATEGORIES.flatMap((c) => c.controls);
const automatedCited = new Set(ALL.filter((c) => c.verification === 'automated').flatMap((c) => c.checkIds));

// The class under test: non-automated controls that map checks.
const subjects = ALL.filter((c) => c.verification !== 'automated' && c.checkIds.length > 0);
const subject = subjects[0];
// A checkId of the subject that no automated control cites — its failure can
// only reach the benchmark through the subject.
const refutationId = subject?.checkIds.find((id) => !automatedCited.has(id));
// A checkId the subject shares with an automated control.
const sharedId = subject?.checkIds.find((id) => automatedCited.has(id));
const sharedAutomated = sharedId ? ALL.find((c) => c.verification === 'automated' && c.checkIds.includes(sharedId)) : undefined;
// Non-automated controls WITHOUT checkIds, one of each label.
const forwardNoIds = ALL.find((c) => c.verification === 'forward' && c.checkIds.length === 0);
const manualNoIds = ALL.find((c) => c.verification === 'manual' && c.checkIds.length === 0);

const base = (checkId: string) => ({
  checkId,
  name: checkId,
  description: `fixture record for ${checkId}`,
  severity: 'high' as const,
  category: 'mcp',
  message: `fixture message for ${checkId}`,
});
const failed = (checkId: string): SecurityFinding => ({ ...base(checkId), passed: false, fix: `fixture fix for ${checkId}` } as SecurityFinding);
const passed = (checkId: string): SecurityFinding => ({ ...base(checkId), passed: true } as SecurityFinding);
const na = (checkId: string): SecurityFinding => ({
  ...base(checkId),
  severity: undefined,
  notApplicable: { subject: 'mcp.json', reason: 'no MCP configuration exists in the scanned tree' },
} as unknown as SecurityFinding);

function statusOf(findings: SecurityFinding[], id: string) {
  const r = generateBenchmarkReport(findings, 'L1');
  const c = r.categories.flatMap((cat) => cat.controls).find((x) => x.controlId === id);
  if (!c) throw new Error(`control ${id} absent from the L1 report`);
  return { report: r, control: c };
}

describe('#639 premise: the class exists and is exactly what the rule was written for', () => {
  it('exactly one non-automated control maps checkIds, and it is scored at L1', () => {
    expect(subjects.map((c) => `${c.id}:${c.verification}`), 'census of non-automated controls with checkIds changed — re-read the #639 ruling before editing this file').toHaveLength(1);
    expect(subject.scored).toBe(true);
    expect(subject.level).toBe('L1');
    expect(getControlsForLevel('L1').some((c) => c.id === subject.id)).toBe(true);
  });

  it('the subject maps one checkId no automated control cites, and one it shares with an automated control', () => {
    expect(refutationId, `${subject.id} has no refutation-only checkId`).toBeDefined();
    expect(sharedId, `${subject.id} shares no checkId with an automated control`).toBeDefined();
    expect(sharedAutomated).toBeDefined();
    expect(forwardNoIds).toBeDefined();
    expect(manualNoIds).toBeDefined();
  });
});

describe('#639 a non-automated control is failed by its checks and never passed by them', () => {
  it('RED-ON-BASE: the refutation-only checkId failed alone -> failed, l1 0, Not Passing', () => {
    const { report, control } = statusOf([failed(refutationId!)], subject.id);
    expect(control.status).toBe('failed');
    expect(control.findings[0]).toMatch(new RegExp(`^${refutationId}: `));
    expect(control.remediation).toBe(`fixture fix for ${refutationId}`);
    expect(report.failedControls).toBe(1);
    expect(report.l1Compliance).toBe(0);
    expect(report.rating).toBe('Not Passing');
  });

  it('RED-ON-BASE: the shared checkId failed -> the subject AND the automated control both fail', () => {
    const { report, control } = statusOf([failed(sharedId!)], subject.id);
    expect(control.status).toBe('failed');
    const other = report.categories.flatMap((c) => c.controls).find((x) => x.controlId === sharedAutomated!.id)!;
    expect(other.status).toBe('failed');
    expect(report.failedControls).toBe(2);
  });

  it('RED-ON-BASE: shared passed + refutation-only failed -> failed (a clean sibling does not outvote a violation)', () => {
    const { report, control } = statusOf([passed(sharedId!), failed(refutationId!)], subject.id);
    expect(control.status).toBe('failed');
    const other = report.categories.flatMap((c) => c.controls).find((x) => x.controlId === sharedAutomated!.id)!;
    expect(other.status).toBe('passed');
  });

  it('RED-ON-BASE: absent-subject on one check + failed on the other -> failed', () => {
    const { control } = statusOf([na(sharedId!), failed(refutationId!)], subject.id);
    expect(control.status).toBe('failed');
  });

  it('PIN (kills the symmetric variant): every mapped check passed -> unverified, never passed, out of the denominator', () => {
    const { report, control } = statusOf(subject.checkIds.map(passed), subject.id);
    expect(control.status).toBe('unverified');
    expect(control.findings).toEqual([]);
    expect(control.remediation).toBe(subject.remediation);
    // The shared id also credits the automated control, and that is the ONLY
    // passed control: the subject did not enter the count or the denominator.
    expect(report.passedControls).toBe(1);
    expect(report.l1Compliance).toBe(100);
  });

  it('PIN (kills forward-NA): every mapped check absent-subject -> unverified, no notApplicableSubjects', () => {
    const { report, control } = statusOf(subject.checkIds.map(na), subject.id);
    expect(control.status).toBe('unverified');
    expect((control as any).notApplicableSubjects).toBeUndefined();
    // The automated sibling that shares an id IS not-applicable on the same records.
    const other = report.categories.flatMap((c) => c.controls).find((x) => x.controlId === sharedAutomated!.id)!;
    expect(other.status).toBe('not-applicable');
    expect(report.notApplicableControls).toBe(1);
  });

  it('PIN: no record at all -> unverified, compliance null, Not Assessed', () => {
    const { report, control } = statusOf([], subject.id);
    expect(control.status).toBe('unverified');
    expect(report.compliance).toBeNull();
    expect(report.rating).toBe('Not Assessed');
  });
});

describe('#639 the rule does not reach controls outside the class', () => {
  it('PIN: non-automated controls WITHOUT checkIds stay unverified on empty and on unrelated records', () => {
    for (const c of [forwardNoIds!, manualNoIds!]) {
      const r0 = generateBenchmarkReport([], c.level as any);
      const r1 = generateBenchmarkReport([failed(refutationId!), failed(sharedId!)], c.level as any);
      for (const r of [r0, r1]) {
        const x = r.categories.flatMap((cat) => cat.controls).find((y) => y.controlId === c.id);
        expect(x?.status, `${c.id} (${c.verification}, no checkIds)`).toBe('unverified');
      }
    }
  });

  it('PIN: an automated control still takes all three measured states', () => {
    const id = sharedAutomated!.id;
    expect(statusOf([failed(sharedId!)], id).control.status).toBe('failed');
    expect(statusOf(sharedAutomated!.checkIds.map(passed), id).control.status).toBe('passed');
    expect(statusOf(sharedAutomated!.checkIds.map(na), id).control.status).toBe('not-applicable');
  });

  it('class guard: walks the catalogue — refutation-only on every non-automated control with checks, confirmation on every automated one', () => {
    let automatedChecked = 0;
    for (const c of ALL) {
      if (c.checkIds.length === 0) continue;
      const level = c.level;
      const find = (fs: SecurityFinding[]) =>
        generateBenchmarkReport(fs, level).categories.flatMap((cat) => cat.controls).find((x) => x.controlId === c.id)!;
      if (c.verification === 'automated') {
        automatedChecked++;
        expect(find(c.checkIds.map(passed)).status, `${c.id} automated, all passed`).toBe('passed');
      } else {
        for (const id of c.checkIds) {
          expect(find([failed(id)]).status, `${c.id} ${c.verification}, ${id} failed alone`).toBe('failed');
        }
        expect(find(c.checkIds.map(passed)).status, `${c.id} ${c.verification}, all passed`).toBe('unverified');
      }
    }
    expect(automatedChecked).toBeGreaterThan(0);
  });

  it('the rule is keyed on "not automated", not on "forward": a manual control given a checkId in memory follows it', () => {
    // No manual control carries checkIds in the catalogue today, so a predicate
    // written as `=== 'forward'` would pass every other cell in this file.
    // The catalogue objects are shared references; lend one a checkId and
    // restore it.
    const c = manualNoIds!;
    const saved = c.checkIds;
    try {
      c.checkIds = ['ZZ-MANUAL-1'];
      const find = (fs: SecurityFinding[]) =>
        generateBenchmarkReport(fs, c.level).categories.flatMap((cat) => cat.controls).find((x) => x.controlId === c.id)!;
      expect(find([failed('ZZ-MANUAL-1')]).status).toBe('failed');
      expect(find([passed('ZZ-MANUAL-1')]).status).toBe('unverified');
      expect(find([na('ZZ-MANUAL-1')]).status).toBe('unverified');
    } finally {
      c.checkIds = saved;
    }
  });
});

describe('#639 the MCP server benchmark tool renders the same verdict', () => {
  it('RED-ON-BASE: the refutation-only checkId failed -> [FAIL] <subject> (<checkId>)', () => {
    const r = assessBenchmarkFindings([failed(refutationId!)], 'L1');
    const lines: string[] = (r as any).lines ?? [];
    const row = lines.find((l) => l.includes(` ${subject.id} `));
    expect(row, `no row for ${subject.id} in: ${lines.slice(0, 5).join(' | ')}`).toBeDefined();
    expect(row).toMatch(/^\[FAIL\]/);
    expect(row).toContain(refutationId!);
  });

  it('PIN: no records -> the subject stays [UNVERIFIED]', () => {
    const r = assessBenchmarkFindings([], 'L1');
    const lines: string[] = (r as any).lines ?? [];
    const row = lines.find((l) => l.includes(` ${subject.id} `));
    expect(row).toMatch(/^\[UNVERIFIED\]/);
  });
});
