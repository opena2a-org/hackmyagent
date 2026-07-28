/**
 * Composite-score / verdict band coherence (closes #259).
 *
 * `secure` renders the composite on a three-colour meter:
 *
 *   >= 70   green   "good"
 *   40-69   yellow  "needs work"
 *   < 40    red     "bad"
 *
 * and, independently, prints a verdict derived from severity counts. On the
 * governance-subverted `soul/malicious/permissive-overrides-soul` fixture the
 * two disagreed:
 *
 *   Security  ━━━━━━━━━━━━━━━━━━━━ 76/100
 *   Verdict   Not safe as-is. SOUL.md Injection Vectors in SOUL.md + 3 more.
 *
 * A SOUL-only subversion barely dents the infra-weighted composite, so the
 * number landed in the green band next to a red verdict. Exit code, verdict
 * direction and findings were all correct — but the number is what a reader
 * anchors on, and 76-in-green reads as "mostly fine".
 *
 * The rule: a fail-direction verdict floors the composite out of the good
 * band. It never raises a score, and it never changes the verdict, the exit
 * code, or which findings are reported — the pre-clamp value travels
 * alongside as `rawScore`, so the clamp adds information instead of
 * destroying it. Same shape as the scan-soul #206 / #251 clamps.
 *
 * Deliberately NOT done: pushing a critical-bearing scan into the red band.
 * The composite's own exponential decay already puts real critical
 * concentrations there (the malicious kitchen-sink scores 0/100), and
 * re-banding criticals is a calibration change beyond the reported
 * incoherence.
 */

/** Lowest score the meter still paints green. Mirrors the renderer in cli.ts. */
export const GOOD_BAND_FLOOR = 70;

/** Ceiling applied when the verdict is fail-direction: the top of "needs work". */
export const VERDICT_FAIL_CLAMP = GOOD_BAND_FLOOR - 1;

/**
 * Whether the verdict derived from these findings is fail-direction.
 *
 * Mirrors `buildVerdict` in `@opena2a/cli-ui`, which returns
 * `status: 'unsafe'` — "Not safe to ship" / "Not safe as-is" — when any
 * critical or high finding is present. Medium/low produce "Usable with
 * caveats", which is not a fail direction and is not clamped.
 *
 * A finding that `--fix` *verifiably* resolved is NOT fail-direction. It
 * carries `passed: false, fixed: true` and is deliberately retained in
 * `filteredFindings` so the run can report what it repaired. Filtering only
 * on `passed` put the two halves of the same decision on different evidence:
 * a `secure --fix` run that repaired everything scored a raw 100 and was then
 * clamped to 69 for findings that no longer existed —
 *
 *   Score: 69/100 | 0 issues found | 2 fixed
 *
 * which is #259 inverted, a capped number beside a clean verdict.
 *
 * But `fixed` alone is not enough either, and excluding on it was its own
 * bug. Checks set `fixed: autoFix && !passed` *before* knowing whether the
 * write landed — `PERM-001` swallows a failed `fs.chmod` (immutable flag,
 * EPERM, read-only mount) and still reports `fixed: true` on a file that is
 * still world-readable. The post-fix verification pass catches this and sets
 * `fixVerified: false` with `[FIX NOT VERIFIED - issue may persist]`, so an
 * unverified fix must count as not fixed: the issue is still there, and the
 * score must still say so.
 *
 * Use `countsAgainstScore` for both the score and the direction so the number
 * and the cap can never be computed off different evidence.
 */

/**
 * Whether a finding counts as an outstanding problem — the single predicate
 * behind both `calculateSecurityScore` and `isFailDirection`.
 */
export function countsAgainstScore(f: {
  passed?: boolean;
  fixed?: boolean;
  fixVerified?: boolean;
}): boolean {
  // Fixed, but the verification pass proved the issue survived.
  //
  // Tested BEFORE `passed`, not after. Twelve checks report
  // `passed: <check>Fixed` — they flip `passed` to true the moment they
  // apply a fix — so an early return on `passed` made this branch
  // unreachable for every one of them, and the verification pass could
  // never rescue an unverified fix on `MCP-001`, `GIT-001..003`,
  // `NET-001`, `MCP-003`, `SKILL-019`, `HB-007` or the gateway checks.
  // Only `PERM-001`'s shape (`passed` stays false while fixing) was ever
  // covered. Order matters more than the predicate here.
  if (f.fixed && f.fixVerified === false) return true;
  if (f.passed) return false;
  return !f.fixed;
}

export function isFailDirection(
  findings: readonly {
    severity?: string;
    passed?: boolean;
    fixed?: boolean;
    fixVerified?: boolean;
  }[],
): boolean {
  return findings.some(f => {
    if (!countsAgainstScore(f)) return false;
    const severity = (f.severity ?? '').toLowerCase();
    return severity === 'critical' || severity === 'high';
  });
}

export interface ClampedScore {
  /** The score to render and publish. */
  score: number;
  /** True when the clamp actually lowered the score. */
  clamped: boolean;
}

/**
 * Floor a composite out of the good band when the verdict is fail-direction.
 * Returns the input unchanged in every other case, including a scan that is
 * already below the band — the clamp is a ceiling, never a floor upward.
 */
export function clampScoreToVerdictBand(
  rawScore: number,
  findings: readonly { severity?: string; passed?: boolean; fixed?: boolean }[],
): ClampedScore {
  if (!isFailDirection(findings) || rawScore <= VERDICT_FAIL_CLAMP) {
    return { score: rawScore, clamped: false };
  }
  return { score: VERDICT_FAIL_CLAMP, clamped: true };
}

/**
 * Suffix for the score line explaining the clamp. Empty when nothing was
 * clamped, so callers can append unconditionally. Names the pre-clamp value
 * so the reader can see what the raw composite was and why it does not stand.
 */
export function clampDisclosure(opts: {
  rawScore?: number;
  score: number;
  clamped?: boolean;
}): string {
  if (!opts.clamped || opts.rawScore === undefined) return '';
  return `  (score capped from ${opts.rawScore} to ${opts.score} — verdict is fail-direction)`;
}
