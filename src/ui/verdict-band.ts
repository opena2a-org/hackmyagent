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
  notApplicable?: { subject: string; reason: string };
}): boolean {
  // #458 — nothing was measured. Tested before everything else: a
  // not-applicable record carries no `passed`, and on `!f.fixed` alone it
  // counted against the score as an outstanding failure (measured on
  // c0ee1f7: `countsAgainstScore({ notApplicable: {…} })` was true).
  if (f.notApplicable) return false;
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

/**
 * #274 — a fix the count surfaces may call "fixed": attempted AND not
 * disproved. The complement of `countsAgainstScore` over the fixed ones, so
 * the two counts on a summary line partition the findings: a finding is an
 * outstanding issue or a confirmed fix, never both. The HTML report and the
 * Registry remediation report already drew this line inline, and the text
 * fix summary leads with what was confirmed (`fixSummaryLine`); the MCP
 * summary and the OpenClaw arm counted every attempt.
 */
export function confirmedFix(f: { passed?: boolean; fixed?: boolean; fixVerified?: boolean }): boolean {
  return f.fixed === true && !countsAgainstScore(f);
}

/**
 * Whether a finding stays in the report list after a re-filter.
 *
 * The list this gates is the one `countsAgainstScore` is then applied to, so
 * the two predicates are a pair and the ONLY property that matters between
 * them is: anything that counts against the score must survive to be counted.
 * Drop it here and the score is computed from a list the finding was already
 * removed from — #259, where a GIT-002 HIGH clamped the score to 69 and then
 * appeared in no finding block, no category summary and no verdict.
 *
 * `f.fixed` is the load-bearing half. Twelve checks report
 * `passed: <check>Fixed`, flipping `passed` true the moment a fix is applied;
 * the verification pass then sets `fixVerified: false` without resetting
 * `passed`. On `!f.passed` alone every one of those disappears.
 *
 * #285 — this rule existed as five identical inline copies in `src/cli.ts`
 * (the `secure` path plus the four NanoMind merge blocks). Measured on
 * `d9e4ee1`: mutating the four NanoMind copies to `!f.passed` and rebuilding
 * left the suite green at 221 files / 2886 tests, because only the `secure`
 * copy was reachable from a test. One rule, one place, one guard.
 */
export function retainForVerdict(f: {
  passed?: boolean;
  fixed?: boolean;
  notApplicable?: { subject: string; reason: string };
}): boolean {
  // #458 — a not-applicable record is neither an outstanding issue nor a fix.
  // It reaches `allFindings` under `notApplicable`; it is not a verdict line.
  // Same first-position rule as `countsAgainstScore`: on `!f.passed` alone the
  // record (no `passed`) was retained as a failure.
  if (f.notApplicable) return false;
  return !f.passed || Boolean(f.fixed);
}

/**
 * Turn a suppression summary back into findings the scorer and the gate can
 * count (#450).
 *
 * A check-ID suppression is a display choice, not a security fact, so the
 * penalty has to survive it. But the finding itself must NOT survive in
 * `ScanResult.findings`: that array also drives the `--fix` governance auto-fix,
 * the Registry publish payload, `allFindings` in `--json`, and the openclaw and
 * nemoclaw report paths. Leaving suppressed entries in it made
 * `secure --fix --ignore X` write a `SOUL.md` for the suppressed check and made
 * `--json` ship the suppressed finding's plaintext `evidence.lines[].content`.
 *
 * So the finding leaves, and this brings back exactly the part the score is
 * entitled to: severity, category and checkId, which is the whole of what
 * `calculateSecurityScore` reads. `count` is expanded rather than summed so the
 * per-checkId cap (`MAX_FINDINGS_PER_CHECK`) applies identically to a suppressed
 * finding and a reported one — collapsing to one stub would quietly discount
 * the second and third instance.
 *
 * The stubs carry no `file`, no `message` and no `evidence`, so nothing that
 * consumes them can leak what the finding was about.
 */
export function expandSuppressed(
  summary: readonly { checkId: string; name: string; category: string; severity: string; count: number }[] | undefined,
): Array<{ checkId: string; name: string; category: string; severity: string; passed: false; suppressed: true }> {
  if (!summary?.length) return [];
  const out: Array<{ checkId: string; name: string; category: string; severity: string; passed: false; suppressed: true }> = [];
  for (const row of summary) {
    for (let i = 0; i < row.count; i++) {
      out.push({
        checkId: row.checkId,
        name: row.name,
        // Carried, not blanked. `calculateSecurityScore` applies the 0.4
        // governance weight on EITHER the category or an `AST-GOV*`-style
        // checkId prefix, so dropping the category would score a suppressed
        // governance finding at full weight — a suppression that made the score
        // WORSE than reporting it, which is the same class of defect in mirror
        // image.
        category: row.category,
        severity: row.severity,
        passed: false,
        suppressed: true,
      });
    }
  }
  return out;
}

/**
 * Whether a finding is shown in the rendered findings list.
 *
 * #450 — the counterpart to `countsAgainstScore`, and deliberately the ONLY
 * predicate that differs from it. A finding the user suppressed (`--ignore`, an
 * `.hmaignore` check-ID pattern, an `.hmaignore` path pattern) is not listed,
 * but it is still scored, still sets the verdict band, and still decides the
 * exit code. Before this split there was one array for both jobs, so suppressing
 * a check removed its penalties: naming one check moved the leaky-env corpus
 * fixture from 69/100 exit 1 to 98/100 exit 0.
 *
 * The pairing rule from `retainForVerdict` inverts here and that is the point:
 * anything that counts against the score must still be COUNTED, and may be
 * un-listed. A display site that forgets this predicate shows a suppressed
 * finding, which is visible and harmless. A scoring site that applies it
 * launders the score, which is neither. If you are reaching for this function
 * outside a renderer, you probably want `countsAgainstScore`.
 */
export function isDisplayed(f: { suppressed?: boolean }): boolean {
  return !f.suppressed;
}

/**
 * The suppression disclosure, folded to one row per checkId.
 *
 * Identity only — `checkId`, `name`, `severity`, `count`, and which channel
 * asked. No `file`, no `message`, no evidence: #370 has `secure --json` emitting
 * plaintext credentials in `evidence.lines[].content`, and a disclosure record
 * for a suppressed credential finding must not become a second copy of it.
 */
export function summarizeSuppressed(
  findings: readonly {
    checkId?: string;
    name?: string;
    category?: string;
    severity?: string;
    suppressed?: boolean;
    suppressedBy?: string;
    passed?: boolean;
    fixed?: boolean;
    fixVerified?: boolean;
  }[],
): Array<{ checkId: string; name: string; category: string; severity: string; count: number; suppressedBy: string }> {
  const rows = new Map<string, { checkId: string; name: string; category: string; severity: string; count: number; suppressedBy: string }>();
  for (const f of findings) {
    // Only findings that would otherwise have been reported. A suppressed
    // check that passed was never going to appear, and announcing it as
    // "suppressed" would overstate what the flag cost the reader.
    if (!f.suppressed || !countsAgainstScore(f)) continue;
    const checkId = f.checkId || '_unknown_';
    const existing = rows.get(checkId);
    if (existing) {
      existing.count += 1;
      continue;
    }
    rows.set(checkId, {
      checkId,
      name: f.name || checkId,
      category: f.category || '',
      severity: f.severity || 'info',
      count: 1,
      suppressedBy: f.suppressedBy || 'ignore-flag',
    });
  }
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return [...rows.values()].sort(
    (a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5) || a.checkId.localeCompare(b.checkId),
  );
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
