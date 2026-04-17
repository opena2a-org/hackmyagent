/**
 * Regression test for bug #1 (briefs/release-findings.md):
 * AST-SCOPE-003 / SEMANTIC-MISMATCH dispatch must preserve the specific
 * `finding.fix` supplied by the scope analyzer instead of falling through
 * to the generic `fixScopeMismatch` prose generator that leads with
 * "Align capabilities with the declared purpose."
 *
 * Surfaced 2026-04-17 during per-finding-review of `check getsentry/sentry-mcp`.
 * Fix lives at src/nanomind-core/fix-generator.ts:104 —
 *   return finding.fix ?? fixScopeMismatch(finding, ast);
 */
import { describe, it, expect } from 'vitest';
import { enrichFindings } from '../../src/nanomind-core/fix-generator';
import type { ASTFinding } from '../../src/nanomind-core/analyzers/capability-analyzer';
import type { SecurityAST } from '../../src/nanomind-core/types';

const minimalAst = (): SecurityAST => ({
  artifactType: 'mcp_config',
  contentHash: 'x'.repeat(64),
  artifactPath: 'mcp.json',
  artifactSize: 100,
  declaredPurpose: 'Fetch Sentry issues for on-call triage',
  declaredCapabilities: [
    { name: 'shell-exec', scope: '*', declared: true, inferred: false, riskLevel: 'critical' },
  ],
  declaredConstraints: [],
  declaredDataAccess: [],
  inferredCapabilities: [],
  inferredRiskSurface: [],
  intentClassification: 'benign',
  intentConfidence: 0.9,
  dependsOn: [],
  governedBy: [],
  evidenceSpans: [],
  signature: '',
  modelVersion: 'test',
  compiledAt: new Date().toISOString(),
});

describe('fix-generator: SEMANTIC-MISMATCH preserves analyzer-supplied fix (bug #1)', () => {
  it('returns the specific finding.fix when the analyzer set one', () => {
    const finding: ASTFinding = {
      checkId: 'AST-SCOPE-003',
      name: 'Scope-Purpose Mismatch',
      description: 'capability shell-exec inconsistent with declared purpose',
      category: 'scope',
      severity: 'high',
      passed: false,
      message: 'scope mismatch',
      fixable: false,
      attackClass: 'SEMANTIC-MISMATCH',
      fix: 'Remove the shell-exec capability from mcp.json or justify it in the declared purpose.',
    };

    const [enriched] = enrichFindings([finding], minimalAst());

    expect(enriched.fix).toBe(
      'Remove the shell-exec capability from mcp.json or justify it in the declared purpose.'
    );
    expect(enriched.fix).not.toMatch(/^In .* align capabilities/);
  });

  it('falls back to prose generator when finding.fix is undefined', () => {
    // Sanity: the ?? dispatch must still allow the generic path when the
    // analyzer didn't supply a specific fix. A regression that set the
    // dispatch to `finding.fix ?? ''` would also pass the preservation
    // test above but break this one.
    const finding: ASTFinding = {
      checkId: 'AST-SCOPE-003',
      name: 'Scope-Purpose Mismatch',
      description: 'capability shell-exec inconsistent with declared purpose',
      category: 'scope',
      severity: 'high',
      passed: false,
      message: 'scope mismatch',
      fixable: false,
      attackClass: 'SEMANTIC-MISMATCH',
      // fix intentionally omitted
    };

    const [enriched] = enrichFindings([finding], minimalAst());

    expect(enriched.fix).toBeTruthy();
    // The generic generator mentions the declared purpose — a reasonable
    // signal that we actually hit fixScopeMismatch instead of returning ''.
    expect(enriched.fix).toMatch(/declared purpose/i);
  });
});
