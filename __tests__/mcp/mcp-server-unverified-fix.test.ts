/**
 * #285 — the MCP server must not tell the host LLM a disproved fix is a pass.
 *
 * `startMcpServer` registers its tool handlers inside a closure that needs a
 * stdio transport, so nothing in the suite ever executed them. Measured on
 * `9180999`: replacing `countsAgainstScore(f)` at `src/mcp-server.ts:151` with
 * `!f.passed` AND REBUILDING left the whole suite green — 219 files / 2876
 * tests, exit 0. The first attempt at that measurement was confounded by the
 * `dist` freshness guard firing on the edited file, which is why the rebuild is
 * part of the claim.
 *
 * The predicate matters because twelve checks report `passed: <check>Fixed` —
 * they flip `passed` to true the moment a fix is applied. When the verification
 * pass then DISPROVES the fix (`fixed: true, fixVerified: false`), `!f.passed`
 * reads it as a pass and drops it. `countsAgainstScore` tests that case first,
 * before `passed`.
 */
import { describe, it, expect } from 'vitest';
import { buildScanToolText, buildDeepScanLayer1 } from '../../src/mcp-server';
import { emitFinding } from '../../src/hardening/finding-emit';
import type { SecurityFindingDraft } from '../../src/hardening/security-check';
import { countsAgainstScore } from '../../src/ui/verdict-band';
import type { SecurityFinding } from '../../src/index';

/** A CRITICAL whose fix was applied and then DISPROVED by the verification pass. */
const disprovedFix = emitFinding({
  checkId: 'CRED-001',
  name: 'Hardcoded Secret',
  category: 'credentials',
  severity: 'critical',
  message: 'A live token is still present in config.json',
  file: 'config.json',
  line: 4,
  fix: 'Move the value to an environment variable',
  fixable: true,
  // The shape the twelve `passed: <check>Fixed` checks produce.
  passed: true,
  fixed: true,
  fixVerified: false,
} as unknown as SecurityFindingDraft) as SecurityFinding;

/** An ordinary genuinely-passing check. */
const cleanPass = emitFinding({
  checkId: 'GIT-001',
  name: 'Gitignore present',
  category: 'git',
  severity: 'low',
  message: '.gitignore covers secrets',
  fixable: false,
  passed: true,
} as unknown as SecurityFindingDraft) as SecurityFinding;

describe('#285 MCP scan tool reports a disproved fix', () => {
  it('pins the premise: the naive predicate and the real one disagree on this finding', () => {
    // Non-tautology guard. If these two ever agreed, every assertion below
    // would pass for the wrong reason and the mutation would be undetectable.
    expect(countsAgainstScore(disprovedFix)).toBe(true);
    expect(!disprovedFix.passed).toBe(false);
  });

  it('counts it in the summary and names it in the body', () => {
    const text = buildScanToolText({
      score: 40,
      maxScore: 100,
      findings: [disprovedFix, cleanPass],
    });

    // The count the host LLM reads. `!f.passed` makes this "0 issues found".
    expect(text).toContain('1 issue found');
    expect(text).toContain('CRED-001');
    expect(text).toContain('config.json:4');
    // And it must not announce the clean check as a problem.
    expect(text).not.toContain('GIT-001');
  });

  it('does not report "No issues found." on a run with an outstanding CRITICAL', () => {
    // The exact sentence the naive predicate produces, and the reason this is
    // worth a test: it is an affirmative all-clear, not a silent omission.
    const text = buildScanToolText({ score: 40, maxScore: 100, findings: [disprovedFix] });
    expect(text).not.toContain('No issues found.');
  });

  it('does not count the disproved attempt as fixed: the counts partition the findings (#274)', () => {
    const text = buildScanToolText({ score: 40, maxScore: 100, findings: [disprovedFix] });
    expect(text).toContain('1 issue found');
    expect(text).not.toContain('fixed');
  });
});

describe('#285 MCP deep_scan hands the disproved fix to the host LLM', () => {
  it('includes it in the Layer-1 payload', () => {
    // This half was a live defect, not just an untested one: deep_scan filtered
    // on `!f.passed`, so the host LLM was told nothing about an outstanding
    // CRITICAL because HMA had tried to fix it and failed.
    const layer1 = buildDeepScanLayer1([disprovedFix, cleanPass]);
    expect(layer1.map((f) => f.checkId)).toEqual(['CRED-001']);
    expect(layer1[0].file).toBe('config.json');
  });

  it('omits a genuinely passing check', () => {
    // Both directions: a filter that returned everything would also pass the
    // assertion above.
    expect(buildDeepScanLayer1([cleanPass])).toEqual([]);
  });
});
