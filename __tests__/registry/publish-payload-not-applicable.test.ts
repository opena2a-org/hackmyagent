/**
 * #458 — a not-applicable record never reaches the publish wire, even when it
 * is handed to `buildPublishPayload` directly.
 *
 * A mutation pass over this change showed the wire filter (publish.ts, the
 * `isMeasured` continue in the hardening mapping) was unfalsifiable through
 * the CLI fixture: `isReportableFinding` (scanner.ts) drops NA records
 * upstream, so no end-to-end path ever fed one to the mapping and removing
 * the filter left every suite green (survivor M7). This file feeds synthetic
 * NA records to the builder directly, so the defense-in-depth filter is
 * pinned on its own — an NA record that leaked onto the wire would fabricate
 * a PASS, because `!countsAgainstScore(NA)` is true by the #458 score guard.
 *
 * The same pass surfaced the filter's unswept twin: `subReports.hardening`
 * computed its denominator from the RAW input list, so an NA record inflated
 * `totalChecks` and overstated `passRate`. The third cell pins the sweep.
 *
 * Fixtures go through `emitFinding` (the real emission boundary) so the
 * builder's redaction-provenance read passes — same pattern as
 * unverified-fix-must-count.test.ts.
 */
import { describe, it, expect } from 'vitest';
import { buildPublishPayload } from '../../src/registry/publish';
import { emitFinding } from '../../src/hardening/finding-emit';
import type { SecurityFinding } from '../../src/hardening';
import type { SecurityFindingDraft } from '../../src/hardening/security-check';

const NOT_APPLICABLE: SecurityFinding = emitFinding({
  checkId: 'PROC-001',
  name: 'Container hardening',
  description: 'Inspects the Dockerfile for hardening directives',
  category: 'process',
  notApplicable: {
    subject: 'Dockerfile',
    reason: 'No Dockerfile in the scanned tree.',
  },
  message: 'Not applicable: no Dockerfile to inspect',
  fixable: false,
} as SecurityFindingDraft);

const MEASURED_FAIL: SecurityFinding = emitFinding({
  checkId: 'GIT-001',
  name: 'Sensitive files not ignored',
  description: 'The ignore file does not cover local credential patterns',
  category: 'process',
  severity: 'medium',
  passed: false,
  message: 'ignore rules missing for local credential files',
  fixable: true,
  file: '.gitignore',
} as SecurityFindingDraft);

const MEASURED_PASS: SecurityFinding = emitFinding({
  checkId: 'LOG-003',
  name: 'No credential logging',
  description: 'No credential values are written to logs',
  category: 'logging',
  severity: 'low',
  passed: true,
  message: 'no credential logging found',
  fixable: false,
} as SecurityFindingDraft);

describe('#458 — not-applicable records at the publish boundary', () => {
  const build = (findings: SecurityFinding[]) =>
    buildPublishPayload(
      { packageName: 'demo-agent', directory: '/tmp/demo', hardeningFindings: findings },
      '0.25.2',
    );

  it('excludes the NA record from the wire and keeps both measured records', () => {
    const payload = build([NOT_APPLICABLE, MEASURED_FAIL, MEASURED_PASS]);
    expect(payload.findings.map((f) => f.checkId).sort()).toEqual(['GIT-001', 'LOG-003']);
    for (const f of payload.findings) {
      expect(typeof f.passed, `${f.checkId} must carry a boolean passed`).toBe('boolean');
      expect('notApplicable' in f, `${f.checkId} must not carry notApplicable`).toBe(false);
    }
    const git = payload.findings.find((f) => f.checkId === 'GIT-001');
    const log = payload.findings.find((f) => f.checkId === 'LOG-003');
    expect(git!.passed, 'the measured failure stays a failure on the wire').toBe(false);
    expect(log!.passed, 'the measured pass stays a pass on the wire').toBe(true);
  });

  it('a lone NA record publishes zero findings, not a fabricated pass', () => {
    const payload = build([NOT_APPLICABLE]);
    expect(payload.findings).toEqual([]);
    expect(payload.verdict, 'nothing was measured, so nothing failed').toBe('pass');
  });

  it('the hardening sub-report denominator counts measured records only', () => {
    const payload = build([NOT_APPLICABLE, MEASURED_FAIL, MEASURED_PASS]);
    const hardening = payload.subReports.hardening as {
      totalChecks: number;
      failedChecks: number;
    };
    expect(hardening.totalChecks, 'NA is in no denominator anywhere').toBe(2);
    expect(hardening.failedChecks).toBe(1);
    // #464 deleted `passRate` — the ratio no server reads was a second
    // spelling of the settled score. The judgment this cell carries (an NA
    // record enters no denominator) lives on in the two counts above.
    expect(hardening).not.toHaveProperty('passRate');
  });
});
