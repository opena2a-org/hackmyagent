/**
 * #274 — the MCP summary's two counts partition the findings.
 *
 * `Score: N/100 | 1 issue found | 1 fixed` was printed for ONE finding: an
 * auto-fix that was attempted and then disproved by the verification pass
 * counted as an outstanding issue AND as a completed fix. The HTML report and
 * the Registry remediation report count a fix only when it is confirmed, and
 * the text fix summary leads with what was confirmed; the MCP summary and the
 * OpenClaw arm were the holdouts.
 * `confirmedFix` is the complement of `countsAgainstScore` over the attempted
 * ones. The partition and disproved-attempt cells are stated against
 * `countsAgainstScore`, and the whole-space count cell checks the two printed
 * counts SUM to the union of "counts against the score" and "was attempted" —
 * an identity that does not mention the helper, so a helper reverted to bare
 * `fixed` breaks the sum (an extra 3 on one side) instead of being copied to
 * both sides of the assertion.
 */
import { describe, it, expect } from 'vitest';
import { emitFinding } from '../../src/hardening/finding-emit';
import type { SecurityFinding, SecurityFindingDraft } from '../../src/hardening/security-check';
import { buildScanToolText } from '../../src/mcp-server';
import { confirmedFix, countsAgainstScore } from '../../src/ui/verdict-band';

/** Every combination of the three fields the predicates read. */
const SPACE = (() => {
  const tri = [true, false, undefined] as const;
  const out: Array<{ passed?: boolean; fixed?: boolean; fixVerified?: boolean }> = [];
  for (const passed of tri) for (const fixed of tri) for (const fixVerified of tri) {
    out.push({ passed, fixed, fixVerified });
  }
  return out;
})();

function finding(shape: { passed?: boolean; fixed?: boolean; fixVerified?: boolean }, i = 0): SecurityFinding {
  return emitFinding({
    checkId: `T-${String(i).padStart(3, '0')}`,
    name: 'Test finding',
    category: 'test',
    severity: 'medium',
    message: 'm',
    fixable: true,
    ...shape,
  } as unknown as SecurityFindingDraft) as SecurityFinding;
}

function counts(text: string): { issues: number; fixed: number | null } {
  const issues = Number(/\| (\d+) issues? found/.exec(text)?.[1]);
  const fixed = /\| (\d+) fixed/.exec(text);
  return { issues, fixed: fixed ? Number(fixed[1]) : null };
}

describe('#274 MCP summary counts partition the findings', () => {
  it('covers the whole input space', () => {
    expect(SPACE).toHaveLength(27);
  });

  it('no finding is both an outstanding issue and a confirmed fix', () => {
    for (const shape of SPACE) {
      const f = finding(shape);
      expect(countsAgainstScore(f) && confirmedFix(f), JSON.stringify(shape)).toBe(false);
    }
  });

  it('every disproved attempt is an issue and never a fix', () => {
    // A disproved attempt is `fixed: true, fixVerified: false` whatever the
    // check did to `passed` (some flip it on fix, some leave it, some never
    // set it) — all three shapes are issues.
    for (const passed of [true, false, undefined]) {
      const f = finding({ passed, fixed: true, fixVerified: false });
      expect(countsAgainstScore(f), `passed=${String(passed)}`).toBe(true);
      expect(confirmedFix(f), `passed=${String(passed)}`).toBe(false);
    }
  });

  it('the summary line counts exactly the two classes, over the whole space at once', () => {
    const all = SPACE.map((s, i) => finding(s, i));
    const text = buildScanToolText({ score: 50, maxScore: 100, findings: all });
    const c = counts(text);
    expect(c.issues).toBe(all.filter(countsAgainstScore).length);
    // The two counts partition the union of "counts against the score" and
    // "was attempted": stated without the helper, so the helper cannot be on
    // both sides. Over this space the union is 21; a bare-`fixed` helper would
    // print 9 fixed and make the sum 24.
    const union = all.filter((f) => countsAgainstScore(f) || f.fixed === true).length;
    expect(c.issues + (c.fixed ?? 0)).toBe(union);
    // Non-vacuity: both classes are populated by the space.
    expect(c.issues).toBeGreaterThan(0);
    expect(c.fixed ?? 0).toBeGreaterThan(0);
  });

  it('prints the ruled strings for the three shapes', () => {
    const disproved = finding({ passed: true, fixed: true, fixVerified: false }, 1);
    const verified = finding({ passed: true, fixed: true, fixVerified: true }, 2);
    expect(buildScanToolText({ score: 40, maxScore: 100, findings: [disproved] })).toMatch(/^Score: 40\/100 \| 1 issue found(?! \| \d+ fixed)/);
    expect(buildScanToolText({ score: 40, maxScore: 100, findings: [disproved, verified] })).toContain('| 1 issue found | 1 fixed');
    expect(buildScanToolText({ score: 90, maxScore: 100, findings: [verified] })).toContain('| 0 issues found | 1 fixed');
  });
});
