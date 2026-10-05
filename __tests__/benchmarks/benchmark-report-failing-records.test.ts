/**
 * #673 — a control result carries machine-readable failing-record refs.
 *
 * After #668 a control cites one evidence line per failing record, but the
 * line is a display string: a JSON consumer of `-b --format json` had to
 * parse `${checkId}: ${description} (file:line)` to attribute a per-file
 * failure. `failingRecords` carries `{checkId, file, line}` for each failing
 * record, parallel to `findings` (same order, same cardinality), so the
 * display strings are presentational. `findings: string[]` is unchanged.
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

function control(findings: SecurityFinding[]) {
  const report = generateBenchmarkReport(findings, 'L1');
  for (const category of report.categories) {
    for (const ctrl of category.controls) {
      if (ctrl.controlId === CONTROL) return ctrl;
    }
  }
  throw new Error(`control ${CONTROL} not in report`);
}

describe('failing-record refs on a control result (#673)', () => {
  it('two per-file failures of one checkId are two distinct refs naming their files', () => {
    const ctrl = control([
      record({ checkId: 'TOOL-001', passed: false, file: 'a/mcp.json', line: 3 }),
      record({ checkId: 'TOOL-001', passed: false, file: 'b/mcp.json', line: 7 }),
    ]);
    expect(ctrl.status).toBe('failed');
    expect(ctrl.failingRecords).toEqual([
      { checkId: 'TOOL-001', file: 'a/mcp.json', line: 3 },
      { checkId: 'TOOL-001', file: 'b/mcp.json', line: 7 },
    ]);
  });

  it('is parallel to findings: same order and cardinality, across checkIds', () => {
    const ctrl = control([
      record({ checkId: 'TOOL-002', passed: false, file: 'tools.json' }),
      record({ checkId: 'TOOL-001', passed: false, file: 'mcp.json', line: 1 }),
      record({ checkId: 'TOOL-001', passed: false, file: '.mcp.json', line: 2 }),
    ]);
    expect(ctrl.failingRecords.length).toBe(ctrl.findings.length);
    ctrl.failingRecords.forEach((ref, i) => {
      expect(ctrl.findings[i].startsWith(`${ref.checkId}: `)).toBe(true);
      expect(ctrl.findings[i]).toContain(ref.file as string);
    });
  });

  it('omits file and line when the record carries neither', () => {
    const ctrl = control([record({ checkId: 'TOOL-001', passed: false })]);
    expect(ctrl.failingRecords).toEqual([{ checkId: 'TOOL-001' }]);
    expect(Object.keys(ctrl.failingRecords[0])).toEqual(['checkId']);
  });

  it('carries file without line when the record has no line', () => {
    const ctrl = control([record({ checkId: 'TOOL-001', passed: false, file: 'mcp.json' })]);
    expect(ctrl.failingRecords).toEqual([{ checkId: 'TOOL-001', file: 'mcp.json' }]);
  });

  it('cites only failing records: passing and not-applicable records leave no ref', () => {
    const ctrl = control([
      record({ checkId: 'TOOL-001', passed: true, file: 'clean.json' }),
      record({
        checkId: 'TOOL-001',
        passed: undefined as unknown as boolean,
        notApplicable: { subject: 'absent.json', reason: 'No absent.json in the scanned tree.' },
      }),
      record({ checkId: 'TOOL-001', passed: false, file: 'bad.json', line: 9 }),
    ]);
    expect(ctrl.failingRecords).toEqual([{ checkId: 'TOOL-001', file: 'bad.json', line: 9 }]);
  });

  it('is an empty array on a control with no failing record', () => {
    expect(control([record({ checkId: 'TOOL-001', passed: true, file: 'mcp.json' })]).failingRecords).toEqual([]);
    expect(control([]).failingRecords).toEqual([]);
  });

  it('rides the JSON document beside the unchanged findings strings', () => {
    const report = generateBenchmarkReport(
      [
        record({ checkId: 'TOOL-001', passed: false, file: 'a/mcp.json', line: 3 }),
        record({ checkId: 'TOOL-001', passed: false, file: 'b/mcp.json', line: 7 }),
      ],
      'L1',
    );
    const parsed = JSON.parse(JSON.stringify(report));
    const ctrl = parsed.categories
      .flatMap((c: { controls: unknown[] }) => c.controls)
      .find((c: { controlId: string }) => c.controlId === CONTROL);
    expect(ctrl.findings).toEqual([
      'TOOL-001: MCP servers should have explicit tool whitelists (a/mcp.json:3)',
      'TOOL-001: MCP servers should have explicit tool whitelists (b/mcp.json:7)',
    ]);
    expect(ctrl.failingRecords).toEqual([
      { checkId: 'TOOL-001', file: 'a/mcp.json', line: 3 },
      { checkId: 'TOOL-001', file: 'b/mcp.json', line: 7 },
    ]);
  });
});
