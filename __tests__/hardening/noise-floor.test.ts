import { describe, it, expect } from 'vitest';
import {
  dropPathlessNoiseFloor,
  findingAppliesTo,
} from '../../src/hardening/scanner';
import type { SecurityFinding, SecurityFindingDraft } from '../../src/hardening/security-check';

/**
 * Issue #131 / #130 — Pathless HIGH/CRITICAL findings (NET-, INJ-, SESSION-,
 * ENCRYPT-, AUDIT-, etc.) were leaking into `result.allFindings` when the
 * check did not apply to the detected project type. They polluted corpus
 * release-smoke goldens, benchmark math, and OASB-2 composite scoring even
 * though `result.findings` (user-facing) already gated them out via `f.file`.
 *
 * Regression contract: dropPathlessNoiseFloor must drop only failed pathless
 * findings whose check prefix is not in scope for the current project type —
 * and (#458) not-applicable records under the same type rule: type scope wins
 * over the not-applicable channel, so a scoped-off check leaves no record.
 * Pathless findings that DO apply (project-level real detections that lack
 * file attribution due to a separate emission bug) and all passed/fixed
 * findings remain.
 */

function fail(checkId: string, file?: string): SecurityFinding {
  return {
    checkId,
    name: `${checkId} test finding`,
    description: 'synthetic',
    category: 'test',
    severity: 'high',
    passed: false,
    message: 'synthetic',
    fixable: false,
    ...(file ? { file } : {}),
  };
}

function passed(checkId: string, file?: string): SecurityFinding {
  return {
    checkId,
    name: `${checkId} test finding`,
    description: 'synthetic',
    category: 'test',
    severity: 'high',
    passed: true,
    message: 'synthetic',
    fixable: false,
    ...(file ? { file } : {}),
  };
}

describe('dropPathlessNoiseFloor (issue #131 / #130)', () => {
  it('drops pathless failed findings whose check does not apply to the project type', () => {
    const findings: SecurityFinding[] = [
      fail('NET-003'),       // webapp/api only — pathless on mcp = noise floor
      fail('INJ-003'),       // webapp/api only — pathless on mcp = noise floor
      fail('SESSION-003'),   // webapp/api only — pathless on mcp = noise floor
      fail('AUDIT-004'),     // webapp/api only — pathless on mcp = noise floor
    ];
    expect(dropPathlessNoiseFloor(findings, 'mcp')).toEqual([]);
  });

  it('keeps pathless failed findings whose check applies to the project type', () => {
    // CRED-/PERM-/CLAUDE-/CURSOR-/DEP- are mapped to ['all']; a pathless
    // failure here is a check-emission bug, not noise — preserve it so the
    // corpus harness still asserts the finding fires.
    const findings: SecurityFinding[] = [
      fail('CRED-002'),      // ['all'] — kept
      fail('PERM-001'),      // ['all'] — kept
      fail('CLAUDE-004'),    // ['all'] — kept
      fail('CURSOR-001'),    // ['all'] — kept
      fail('DEP-003'),       // ['all'] — kept
    ];
    const out = dropPathlessNoiseFloor(findings, 'openclaw');
    expect(out.map((f) => f.checkId)).toEqual([
      'CRED-002',
      'PERM-001',
      'CLAUDE-004',
      'CURSOR-001',
      'DEP-003',
    ]);
  });

  it('keeps failed findings with a file path even when check does not apply', () => {
    const findings: SecurityFinding[] = [
      fail('NET-003', 'src/server.ts'),    // has file → kept regardless
      fail('INJ-003', 'src/db.ts'),        // has file → kept regardless
    ];
    expect(dropPathlessNoiseFloor(findings, 'mcp')).toHaveLength(2);
  });

  it('always retains passed findings regardless of file or applicability', () => {
    const findings: SecurityFinding[] = [
      passed('NET-003'),                    // passed pathless non-applicable
      passed('INJ-003', 'src/db.ts'),       // passed with file non-applicable
      passed('CRED-001'),                   // passed pathless applicable
    ];
    expect(dropPathlessNoiseFloor(findings, 'mcp')).toHaveLength(3);
  });

  it('mixes correctly: drops only the pathless+failed+non-applicable subset', () => {
    const findings: SecurityFinding[] = [
      fail('NET-003'),                       // drop  — pathless, non-app
      fail('NET-003', 'src/server.ts'),      // keep — has file
      passed('NET-003'),                     // keep — passed
      fail('CRED-002'),                      // keep — applies
      fail('AST-CRED-001', 'src/secret.ts'), // keep — has file
    ];
    const out = dropPathlessNoiseFloor(findings, 'mcp');
    expect(out).toHaveLength(4);
    expect(out.map((f) => f.checkId).sort()).toEqual([
      'AST-CRED-001',
      'CRED-002',
      'NET-003',
      'NET-003',
    ]);
  });

  it('handles SANDBOX- checks correctly (applies to mcp)', () => {
    // SANDBOX- maps to ['webapp', 'api', 'mcp'] — pathless SANDBOX-002 on
    // mcp is preserved (real check that legitimately scans whole project).
    const findings: SecurityFinding[] = [
      fail('SANDBOX-002'),
    ];
    expect(dropPathlessNoiseFloor(findings, 'mcp')).toHaveLength(1);
    // ...but on a project type SANDBOX- doesn't cover (cli/library/sdk),
    // a pathless SANDBOX-002 is noise.
    expect(dropPathlessNoiseFloor(findings, 'library')).toEqual([]);
  });

  it('does not depend on findingAppliesTo defaulting to true for unknown prefixes', () => {
    // An unknown prefix returns true from findingAppliesTo (catch-all).
    // We rely on that: unknown checks are kept when pathless, since we
    // can't classify them as noise without a mapping.
    const findings: SecurityFinding[] = [
      fail('NEW-CHECK-001'),
    ];
    expect(findingAppliesTo({ ...fail('NEW-CHECK-001') }, 'mcp')).toBe(true);
    expect(dropPathlessNoiseFloor(findings, 'mcp')).toHaveLength(1);
  });
});

describe('not-applicable records vs project-type scope (#458)', () => {
  function notApplicable(checkId: string): SecurityFindingDraft {
    return {
      checkId,
      name: `${checkId} test record`,
      description: 'synthetic',
      category: 'test',
      notApplicable: { subject: 'Dockerfile', reason: 'synthetic' },
      message: 'Not applicable: no Dockerfile to inspect',
      fixable: false,
    };
  }

  it('drops a not-applicable record whose check is scoped off the project type', () => {
    // PROC- is ['webapp', 'api']: a library or mcp tree carries NO record for
    // it — the same outcome as the checks that never ran. This is a decision
    // (type scope wins over the not-applicable channel), not a fall-through:
    // dropPathlessNoiseFloor has an explicit notApplicable branch.
    expect(dropPathlessNoiseFloor([notApplicable('PROC-001')], 'library')).toEqual([]);
    expect(dropPathlessNoiseFloor([notApplicable('PROC-001')], 'mcp')).toEqual([]);
  });

  it('retains a not-applicable record whose check applies to the project type', () => {
    const record = notApplicable('PROC-001');
    expect(dropPathlessNoiseFloor([record], 'webapp')).toEqual([record]);
    expect(dropPathlessNoiseFloor([record], 'api')).toEqual([record]);
  });
});
