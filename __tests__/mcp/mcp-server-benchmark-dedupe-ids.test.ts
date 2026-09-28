/**
 * #671 — the `hackmyagent_benchmark` text names each failing checkId once.
 *
 * Since #668 the shared evaluator cites one evidence line per failing record,
 * so a checkId that fails in both `mcp.json` and `.mcp.json` contributes two
 * lines to `ctrl.findings`. The MCP assessor rendered the ids by mapping every
 * line, which printed "(TOOL-001, TOOL-001)". The per-record evidence stays in
 * the report; only the id list shown beside [FAIL] is de-duplicated, in
 * first-seen order.
 */
import { describe, it, expect } from 'vitest';
import { assessBenchmarkFindings } from '../../src/mcp-server';
import { getControlsForLevel } from '../../src/benchmarks/oasb-1';
import type { SecurityFinding } from '../../src/hardening/security-check';

const L1 = getControlsForLevel('L1');
const citations = (id: string) => L1.filter((c) => c.checkIds.includes(id)).length;
// Controls selected by shape, not by hardcoded id, so a catalog change fails
// the premise cell instead of silently testing nothing.
const single = L1.find((c) => c.checkIds.length === 1 && citations(c.checkIds[0]) === 1)!;
const multi = L1.find((c) => c.checkIds.length >= 2 && c.checkIds.every((id) => citations(id) === 1))!;

const fail = (checkId: string, file: string): SecurityFinding => ({
  checkId,
  name: checkId,
  description: `fixture record for ${checkId}`,
  severity: 'medium',
  category: 'fixture',
  message: 'fixture',
  passed: false,
  file,
} as SecurityFinding);

const failLine = (text: string, controlId: string) =>
  text.split('\n').find((l) => l.startsWith(`[FAIL] ${controlId} `));

describe('#671: benchmark display names a failing checkId once', () => {
  it('premise: fixture controls exist', () => {
    expect(single).toBeDefined();
    expect(multi).toBeDefined();
  });

  it('one checkId failing in two files is listed once', () => {
    const id = single.checkIds[0];
    const r = assessBenchmarkFindings([fail(id, 'mcp.json'), fail(id, '.mcp.json')], 'L1');
    const line = failLine(r.text, single.id);
    expect(line).toBeDefined();
    expect(line).toMatch(new RegExp(`\\(${id}\\)$`));
    expect(line!.split(id).length - 1).toBe(1);
  });

  it('distinct checkIds are each listed once', () => {
    const [a, b] = multi.checkIds;
    const r = assessBenchmarkFindings(
      [fail(b, 'mcp.json'), fail(a, 'mcp.json'), fail(b, '.mcp.json'), fail(a, '.mcp.json')],
      'L1',
    );
    const line = failLine(r.text, multi.id)!;
    const listed = line.slice(line.lastIndexOf('(') + 1, -1).split(', ');
    expect(new Set(listed).size).toBe(listed.length);
    expect(listed.sort()).toEqual([a, b].sort());
  });

  it('the count and status are unchanged by the display fix', () => {
    const id = single.checkIds[0];
    const once = assessBenchmarkFindings([fail(id, 'mcp.json')], 'L1');
    const twice = assessBenchmarkFindings([fail(id, 'mcp.json'), fail(id, '.mcp.json')], 'L1');
    expect(twice.failed).toBe(once.failed);
    expect(twice.passed).toBe(once.passed);
    expect(twice.compliance).toBe(once.compliance);
  });
});
