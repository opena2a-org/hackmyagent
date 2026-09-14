/**
 * #637 — the evaluator folds MULTIPLE records per checkId (CA ruling
 * 2026-08-27, ledger).
 *
 * One checkId can carry several records: one per root MCP config spelling,
 * one per file for the per-file emitters. `generateBenchmarkReport` built its
 * index with `Map.set` — the LAST record won — so the verdict on a
 * multi-record checkId was an artifact of scanner emission order: a failing
 * `mcp.json` record followed by a clean `.mcp.json` record read as passed
 * (the shadow-file evasion #637 closes, re-created one layer down), and a
 * failure beside an NA sibling could launder into `not-applicable`.
 *
 * The ruled fold is the SAME join the evaluator already applies across a
 * control's checkIds: any failure fails; a measured record outranks an NA
 * sibling; NA only when NA is all there is; order-independent; one evidence
 * line per failing record; NA subjects are the de-duped union.
 */
import { describe, it, expect } from 'vitest';
import { generateBenchmarkReport } from '../../src/benchmarks/benchmark-report';
import type { SecurityFinding } from '../../src/hardening/scanner';

// Control 2.3 (Capability Boundaries, L1, automated) maps TOOL-001/TOOL-002.
const CONTROL = '2.3';

function record(over: Partial<SecurityFinding> & { checkId: string }): SecurityFinding {
  return {
    name: 'Tool Whitelisting',
    description: 'MCP servers should have explicit tool whitelists',
    category: 'tool-boundaries',
    severity: 'high',
    passed: true,
    message: 'x',
    fixable: false,
    ...over,
  } as SecurityFinding;
}

const P = (file: string) => record({ checkId: 'TOOL-001', passed: true, file });
const F = (file: string) => record({ checkId: 'TOOL-001', passed: false, file });
const NA = (subject: string) =>
  record({
    checkId: 'TOOL-001',
    passed: undefined as unknown as boolean,
    notApplicable: { subject, reason: `No ${subject} in the scanned tree.` },
  });

function control(findings: SecurityFinding[]) {
  const report = generateBenchmarkReport(findings, 'L1');
  for (const category of report.categories) {
    for (const ctrl of category.controls) {
      if (ctrl.controlId === CONTROL) return ctrl;
    }
  }
  throw new Error(`control ${CONTROL} not in report`);
}

describe('multi-record fold per checkId (#637)', () => {
  it('a failure is never erased by a later clean record for the same checkId', () => {
    // The laundering direction: last-wins read [F, P] as passed.
    expect(control([F('mcp.json'), P('.mcp.json')]).status).toBe('failed');
    expect(control([P('mcp.json'), F('.mcp.json')]).status).toBe('failed');
  });

  it('a failure is never laundered into not-applicable by a later NA record', () => {
    expect(control([F('mcp.json'), NA('.mcp.json')]).status).toBe('failed');
    expect(control([NA('mcp.json'), F('.mcp.json')]).status).toBe('failed');
  });

  it('a measured-clean record outranks an NA sibling record, in both orders', () => {
    expect(control([P('mcp.json'), NA('.mcp.json')]).status).toBe('passed');
    expect(control([NA('mcp.json'), P('.mcp.json')]).status).toBe('passed');
  });

  it('all-NA records keep not-applicable, with the subjects a de-duped union', () => {
    const ctrl = control([NA('mcp.json'), NA('.mcp.json'), NA('mcp.json')]);
    expect(ctrl.status).toBe('not-applicable');
    expect(ctrl.notApplicableSubjects).toEqual(['mcp.json', '.mcp.json']);
  });

  it('every failing record is cited: one evidence line per record, not per checkId', () => {
    const ctrl = control([F('mcp.json'), F('.mcp.json')]);
    expect(ctrl.status).toBe('failed');
    expect(ctrl.findings.length).toBe(2);
  });

  it('the verdict is order-independent: status, counts, findings-as-set, subjects-as-set survive reversal', () => {
    const findings = [F('mcp.json'), P('.mcp.json'), NA('other.json'), F('.mcp.json')];
    const forward = generateBenchmarkReport([...findings], 'L1');
    const reversed = generateBenchmarkReport([...findings].reverse(), 'L1');
    expect(reversed.compliance).toBe(forward.compliance);
    expect(reversed.passedControls).toBe(forward.passedControls);
    expect(reversed.failedControls).toBe(forward.failedControls);
    expect(reversed.unverifiedControls).toBe(forward.unverifiedControls);
    expect(reversed.notApplicableControls).toBe(forward.notApplicableControls);
    const ctl = (r: typeof forward) =>
      r.categories.flatMap((c) => c.controls).find((c) => c.controlId === CONTROL)!;
    expect(ctl(reversed).status).toBe(ctl(forward).status);
    expect([...ctl(reversed).findings].sort()).toEqual([...ctl(forward).findings].sort());
  });
});
