/**
 * OASB-1 benchmark evaluation over a scan's findings (#458 step 5).
 *
 * Extracted from `src/cli.ts` so the MCP server can share it: importing
 * `cli.ts` is side-effectful (its top-level `program.parseAsync` runs the
 * CLI), so the one honest way to have ONE assessor — the 0.33.0 hold
 * condition — is for both callers to import this module. Behavior is the
 * step-3 contract: NA-first, measured outranks an NA sibling, an all-NA
 * control is `not-applicable` and leaves every denominator, and a control
 * with no record at all is `unverified` — never credited.
 */
import {
  OASB_1_CATEGORIES,
  OASB_1_VERSION,
  OASB_1_NAME,
  getControlsForLevel,
  getControlsForCategory,
  calculateRating,
  type BenchmarkLevel,
  type BenchmarkControl,
  type BenchmarkCategory,
  type BenchmarkResult,
  type BenchmarkCategoryResult,
} from './index';
import type { SecurityFinding } from '../hardening/security-check';
import { escapeForDisplay } from '../ui/display-safe';

export interface LocalControlResult {
  control: BenchmarkControl;
  status: 'passed' | 'failed' | 'unverified' | 'not-applicable';
  findings: string[];
  remediation?: string;
  /** Absent subject artifacts, when status is `not-applicable` (#458). */
  naSubjects?: string[];
}


export function generateBenchmarkReport(
  findings: ReadonlyArray<SecurityFinding>,
  level: BenchmarkLevel,
  categoryFilter?: string
): BenchmarkResult {
  // Get controls for the specified level
  let controls = getControlsForLevel(level);

  // Filter by category if specified
  if (categoryFilter) {
    const categoryControls = getControlsForCategory(categoryFilter);
    if (categoryControls.length === 0) {
      console.error(`Error: Unknown category '${escapeForDisplay(String(categoryFilter))}'.`);
      console.error(`Available categories: ${OASB_1_CATEGORIES.map((c: BenchmarkCategory) => c.name).join(', ')}`);
      process.exit(1);
    }
    controls = controls.filter((c: BenchmarkControl) => c.category.toLowerCase() === categoryFilter.toLowerCase());
  }

  // Build a map of checkId -> finding for quick lookup
  const findingsByCheckId = new Map<string, SecurityFinding>();
  for (const finding of findings) {
    findingsByCheckId.set(finding.checkId, finding);
  }

  // Evaluate each control
  const controlResults: LocalControlResult[] = [];
  let l1Passed = 0, l1Total = 0;
  let l2Passed = 0, l2Total = 0;
  let l3Passed = 0, l3Total = 0;
  let passedCount = 0, failedCount = 0, unverifiedCount = 0, notApplicableCount = 0;

  for (const control of controls) {
    let status: 'passed' | 'failed' | 'unverified' | 'not-applicable';
    const relatedFindings: string[] = [];
    const naSubjects: string[] = [];
    let remediation: string | undefined;

    if (control.checkIds.length === 0) {
      // No automated check maps to this control (manual, forward, or an
      // empty mapping): a person must verify it; never credited.
      status = 'unverified';
      unverifiedCount++;
      remediation = control.remediation;
    } else {
      // #639 — `verification` says whether the mapped checks are SUFFICIENT
      // to settle the control. `automated`: they are. `manual`/`forward`:
      // they are not, so their checks can only REFUTE it — a measured
      // failure fails the control (the violation is the control's own audit
      // step); a clean, absent-subject or missing record leaves it
      // `unverified`, never passed and never not-applicable, because
      // automation cannot confirm what the label says a person must.
      // Before this the manual/forward test ran BEFORE the record scan, so
      // a failing SEM-MCP-004 (2.1's wildcard-grant check) moved nothing.
      const refuteOnly = control.verification !== 'automated';
      // Check all mapped check IDs
      let hasMeasured = false;
      let hasFailure = false;
      let hasNotApplicable = false;
      for (const checkId of control.checkIds) {
        const finding = findingsByCheckId.get(checkId);
        if (!finding) continue;
        // #458 step 3 — the NA test comes FIRST: an NA record OMITS `passed`
        // (never false), so the `!finding.passed` test below read "subject
        // absent" as a failure and, before steps 1-2, the absent subject was
        // a pathless HIGH. The record contributes no pass/fail value; it
        // names its absent subject.
        if (finding.notApplicable) {
          hasNotApplicable = true;
          if (!naSubjects.includes(finding.notApplicable.subject)) {
            naSubjects.push(finding.notApplicable.subject);
          }
          continue;
        }
        hasMeasured = true;
        if (!finding.passed) {
          hasFailure = true;
          relatedFindings.push(`${checkId}: ${finding.description}`);
          if (finding.fix) {
            remediation = remediation || finding.fix;
          }
        }
      }
      // Resolution: a measured failure fails the control whatever its
      // verification; a refute-only control with no failure is unverified;
      // an automated control is passed only when something MEASURED clean
      // (a measured record outranks an NA sibling — a control with one
      // check that measured and one whose subject is absent WAS measured),
      // `not-applicable` only when NA records are all it has, and nothing
      // at all stays `unverified` — a type-scoped-off check leaves NO
      // record, and crediting that as anything would relaunder the absence
      // #458 removed.
      if (hasFailure) {
        status = 'failed';
        failedCount++;
        remediation = remediation || control.remediation;
      } else if (refuteOnly) {
        status = 'unverified';
        unverifiedCount++;
        remediation = control.remediation;
      } else if (hasMeasured) {
        status = 'passed';
        passedCount++;
      } else if (hasNotApplicable) {
        status = 'not-applicable';
        notApplicableCount++;
      } else {
        status = 'unverified';
        unverifiedCount++;
        remediation = control.remediation;
      }
    }

    // Count by level for compliance calculation
    // Positive gate (#458 step 3): only a MEASURED status enters a level
    // denominator. `not-applicable` leaves it exactly like `unverified`.
    if (control.scored && (status === 'passed' || status === 'failed')) {
      if (control.level === 'L1') {
        l1Total++;
        if (status === 'passed') l1Passed++;
      } else if (control.level === 'L2') {
        l2Total++;
        if (status === 'passed') l2Passed++;
      } else if (control.level === 'L3') {
        l3Total++;
        if (status === 'passed') l3Passed++;
      }
    }

    controlResults.push({ control, status, findings: relatedFindings, remediation, naSubjects });
  }

  // Compliance percentages. #458 step 0 — a level with no scored control
  // that produced a result has no figure: `null`, never a default. The two
  // L3 controls (3.5, 8.4) have no automated check, so `l3Compliance` was the
  // old `: 100` default on every target and the L3 ladder read it as perfect
  // (the sentence in #513's title); a category with no scored control read
  // `Rating: Certified` beside `Compliance: 0% (0/0)` because the overall
  // figure defaulted to 0 five lines below — the opposite default for the
  // same case. CISO 2026-08-11 / CPO 2026-08-25: zero denominator => null,
  // renders "not assessed", never feeds the ladder, never Not Passing.
  const pct = (passed: number, total: number): number | null =>
    total > 0 ? Math.round((passed / total) * 100) : null;
  const l1Compliance = pct(l1Passed, l1Total);
  const l2Compliance = pct(l2Passed, l2Total);
  const l3Compliance = pct(l3Passed, l3Total);
  const totalScored = l1Total + l2Total + l3Total;
  const totalPassed = l1Passed + l2Passed + l3Passed;
  const overallCompliance = pct(totalPassed, totalScored);

  // Group results by category
  const categoryResults: BenchmarkCategoryResult[] = [];
  for (const category of OASB_1_CATEGORIES) {
    if (categoryFilter && category.name.toLowerCase() !== categoryFilter.toLowerCase()) continue;

    const catControls = controlResults.filter((r: LocalControlResult) => r.control.category === category.name);
    if (catControls.length === 0) continue;

    const passed = catControls.filter((r: LocalControlResult) => r.status === 'passed').length;
    const failed = catControls.filter((r: LocalControlResult) => r.status === 'failed').length;
    const unverified = catControls.filter((r: LocalControlResult) => r.status === 'unverified').length;
    const notApplicable = catControls.filter((r: LocalControlResult) => r.status === 'not-applicable').length;
    const compliance = (passed + failed) > 0 ? Math.round((passed / (passed + failed)) * 100) : 0;

    categoryResults.push({
      category: category.name,
      compliance,
      passed,
      failed,
      unverified,
      notApplicable,
      controls: catControls.map((r: LocalControlResult) => ({
        controlId: r.control.id,
        name: r.control.name,
        level: r.control.level,
        status: r.status,
        findings: r.findings,
        remediation: r.remediation,
        ...(r.status === 'not-applicable' && r.naSubjects?.length ? { notApplicableSubjects: r.naSubjects } : {}),
      })),
    });
  }

  const rating = calculateRating(l1Compliance, l2Compliance, l3Compliance, level);

  return {
    benchmark: OASB_1_NAME,
    version: OASB_1_VERSION,
    level,
    timestamp: new Date(),
    compliance: overallCompliance,
    l1Compliance,
    l2Compliance,
    l3Compliance,
    rating,
    categories: categoryResults,
    totalControls: controls.length,
    passedControls: passedCount,
    failedControls: failedCount,
    unverifiedControls: unverifiedCount,
    notApplicableControls: notApplicableCount,
  };
}

