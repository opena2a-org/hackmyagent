/**
 * The settled outcome of a `secure` run — ONE projection every outbound
 * record reads (#464 #519 #283).
 *
 * Before this module, each record that left the process about a `secure` run
 * recomputed its own score, verdict or counts from `result.findings`: the
 * Registry publish payload re-derived a composite from the narrowed list
 * with a `: 100` pass-rate default, the contribution event computed
 * `passed/total` over the list (0 with any failure) and its own severity
 * ladder, and `--ci-publish` derived `status` from counts that disagreed
 * with the exit code the same run returned (#464: 49 findings displayed,
 * exit 1, `status: passed`, counts all 0). Every one of those was a second
 * spelling of a settlement the CLI had already made once.
 *
 * `settledOutcome` does NO arithmetic. It reads the object the exit floor
 * and the `--json` document already read — `ScanResult` as `applyScore`
 * settled it — plus the exit code the one settlement point decided, and
 * projects them into one record. `applyScore` (src/hardening/scanner.ts)
 * stays the only place a score is computed; `gateSet` below stays the only
 * spelling of "the findings the verdict is entitled to read".
 *
 * Wire consumers stamp `schemaVersion: 1`. The `secure --json` document does
 * NOT nest this record: its top level IS the record (flat keys; CPO ruling,
 * CA CONFIRM-FLAT), and `pickSettledOutcome` re-derives the record from a
 * parsed document so the identity `pickSettledOutcome(json) ≡
 * omit(record, 'schemaVersion')` is testable from either side. The identity
 * holds for every document the scanner emits today (its coverage record is
 * always attached); a document with NO coverage key picks back a record
 * without one, while the builder synthesizes an empty record — scoped here
 * because the narrower claim is the one that is true.
 */
import type { ScanResult } from './security-check';
import { countsAgainstScore, expandSuppressed } from '../ui/verdict-band';
import { recordedCoverage, type ReadFailureRecord } from '../check/verdict';

/** Identity row for a suppressed or out-of-scope check — `ScanResult['suppressed']` element VERBATIM (no path or byte can enter by construction). */
export type SuppressionRow = NonNullable<ScanResult['suppressed']>[number];

export interface SettledCoverage {
  /** False exactly when the run discovered an input it could not read. */
  measured: boolean;
  /** Distinct files inside the target whose contents the scan read. */
  examined: number;
  /** `examined` plus what was discovered and not read (`recordedCoverage`). */
  total: number;
  unit: 'file';
  unreadableInputs?: ReadFailureRecord;
}

export interface SettledOutcome {
  /** Wires only; not part of the picker identity. */
  schemaVersion: 1;
  score: number;
  rawScore?: number;
  scoreClamped?: boolean;
  /**
   * `null` exactly when `exitCode === 2` and the band is pass-direction —
   * the renderer's own rule ("No issues in what was examined — but ...");
   * a warn/fail band at exit 2 is displayed and therefore carried.
   */
  verdict: 'pass' | 'warn' | 'fail' | null;
  exitCode: 0 | 1 | 2;
  measured: boolean;
  /** Counts over `gateSet` — suppressed entries included, never a ratio. */
  counts: { critical: number; high: number; medium: number; low: number };
  coverage: SettledCoverage;
  suppressed?: SuppressionRow[];
  outOfScope?: SuppressionRow[];
}

/**
 * The findings the verdict is entitled to read: the visible list PLUS the
 * suppressed entries expanded back. #450's whole point is that suppressing a
 * check removes it from the report and not from the verdict; any channel
 * that filters `result.findings` directly is laundering, and
 * `--ignore CONFIG-004` moved the leaky-env corpus fixture from exit 1 to
 * exit 0 through exactly that gap. (Moved verbatim from `cli.ts`, which is
 * side-effectful to import — the same reason `benchmark-report.ts` exists.)
 */
export function gateSet(result: { findings?: unknown[]; suppressed?: ScanResult['suppressed'] }): any[] {
  return [...(result.findings ?? []), ...expandSuppressed(result.suppressed)] as any[];
}

/**
 * True when Layer 3 sent a file for analysis and could not read an answer
 * back (#462). Reads `gateSet`, NOT `result.findings`: reading the filtered
 * list let `--ignore SEM-LLM-NOT-ANALYZED` turn an incomplete deep scan back
 * into exit 0. (Moved verbatim from `cli.ts`.)
 */
export function deepScanIncomplete(result: { findings?: unknown[]; suppressed?: ScanResult['suppressed'] }): boolean {
  return gateSet(result).some((f: any) => f?.checkId === 'SEM-LLM-NOT-ANALYZED');
}

/**
 * Inputs `secure` discovered inside the target and could not read (#438).
 * The unit is inputs-discovered-but-not-read, never a files-read threshold —
 * `--fix` satisfies a files-read bar by writing into the target; it cannot
 * clear the `EACCES` recorded on the other file. (Moved verbatim from
 * `cli.ts`; `coverage-ledger.ts` decides which errnos count.)
 */
export function unreadInputCount(result: { coverage?: { unreadableInputs?: { count: number } } }): number {
  return result.coverage?.unreadableInputs?.count ?? 0;
}

/**
 * The exit code of a settled `secure` run, spelled once.
 *
 * Composes the SAME predicates the settlement point and every output arm
 * read — the unread-input floor (#438), the critical/high direction over
 * `gateSet` (#450) and the incomplete-deep-scan floor (#462) — so the
 * outbound gate and the process exit cannot disagree. `--fail-below` is
 * deliberately NOT here: a breach raises the process exit at the settlement
 * point, and the caller passes the SETTLED code in; this function is the
 * derivation for callers that need the code before the arms return.
 */
export function settleSecureExit(result: ScanResult): 0 | 1 | 2 {
  if (unreadInputCount(result) > 0) return 2;
  const critHigh = gateSet(result).filter(
    (f: any) => countsAgainstScore(f) && (f.severity === 'critical' || f.severity === 'high'),
  );
  if (critHigh.length > 0) return 1;
  if (deepScanIncomplete(result)) return 2;
  return 0;
}

/**
 * Project the settled result and the settled exit code into the one record
 * every outbound consumer reads. No arithmetic: counts are counts over
 * `gateSet`, the score fields are carried, coverage is
 * `recordedCoverage(filesExamined, 'file', unreadableInputs)`.
 */
export function settledOutcome(result: ScanResult, exitCode: 0 | 1 | 2): SettledOutcome {
  const gate = gateSet(result).filter((f: any) => countsAgainstScore(f));
  const count = (sev: string) => gate.filter((f: any) => f.severity === sev).length;
  const counts = {
    critical: count('critical'),
    high: count('high'),
    medium: count('medium'),
    low: count('low'),
  };
  const record: ReadFailureRecord = result.coverage?.unreadableInputs ?? { count: 0, codes: {}, directories: 0 };
  const coverage: SettledCoverage = {
    measured: record.count === 0,
    ...recordedCoverage(result.coverage?.filesExamined ?? 0, 'file', record),
  } as SettledCoverage;
  // The wire ladder the publish payload has always spoken (#464 makes it the
  // ONE spelling): fail on any counted critical/high, warn on any counted
  // medium/low, pass on none. `null` only where the renderer replaces the
  // green sentence — an exit-2 run with nothing counted at all ("No issues
  // in what was examined — but ..."); a warn/fail band at exit 2 is
  // displayed and therefore carried.
  const anyCounted = counts.critical + counts.high + counts.medium + counts.low > 0;
  const verdict: SettledOutcome['verdict'] =
    counts.critical > 0 || counts.high > 0
      ? 'fail'
      : counts.medium > 0 || counts.low > 0
        ? 'warn'
        : exitCode === 2 && !anyCounted
          ? null
          : 'pass';
  return {
    schemaVersion: 1,
    score: result.score,
    ...(result.rawScore !== undefined ? { rawScore: result.rawScore } : {}),
    ...(result.scoreClamped !== undefined ? { scoreClamped: result.scoreClamped } : {}),
    verdict,
    exitCode,
    measured: coverage.measured,
    counts,
    coverage,
    ...(result.suppressed?.length ? { suppressed: result.suppressed } : {}),
    ...(result.outOfScope?.length ? { outOfScope: result.outOfScope } : {}),
  };
}

/**
 * May this run publish, report, or contribute ANYTHING outbound?
 *
 * CISO invariant: a run at `EXIT_UNMEASURED` never carries `pass`/`passed`
 * anywhere, and the smaller true statement is that it carries nothing — the
 * withhold is decided here, BEFORE each arm's own preconditions, so no arm
 * can rediscover a reason to send. One line is printed at the decision site.
 */
export function outboundAllowed(settled: SettledOutcome): boolean {
  return settled.measured && settled.exitCode !== 2;
}

// The `--json` document spreads `...result` and then the record's flat keys.
// If `ScanResult` ever grows a field named like a record key, spread order
// would silently overwrite it — this assertion turns that day into a compile
// error instead (CPO pre-mortem (a)).
type _RecordKeyCollision = Extract<keyof ScanResult, 'verdict' | 'exitCode' | 'measured' | 'counts'>;
const _noRecordKeyCollision: _RecordKeyCollision extends never ? true : never = true;
void _noRecordKeyCollision;

/**
 * The three-value status vocabulary of the scan/community/ci wires, mapped
 * from the settled verdict: fail→failed, warn→warnings, pass→passed. Throws
 * on the null verdict — a run at EXIT_UNMEASURED never reaches a wire
 * (`outboundAllowed` withholds it), so a null here is a caller bug and the
 * failure is closed, not defaulted.
 */
export function wireStatus(settled: SettledOutcome): 'failed' | 'warnings' | 'passed' {
  if (settled.verdict === null) throw new Error('a run at EXIT_UNMEASURED never posts (#464)');
  return settled.verdict === 'fail' ? 'failed' : settled.verdict === 'warn' ? 'warnings' : 'passed';
}

/** The record's keys, derived from the type — a picker that drifts from the type is a compile error, not a silent hole (C3). */
export const SETTLED_OUTCOME_KEYS = [
  'score',
  'rawScore',
  'scoreClamped',
  'verdict',
  'exitCode',
  'measured',
  'counts',
  'coverage',
  'suppressed',
  'outOfScope',
] as const satisfies ReadonlyArray<keyof Omit<SettledOutcome, 'schemaVersion'>>;

/**
 * Re-derive the record from a parsed `secure --json` document (C1/C2).
 *
 * The document's top level IS the record (flat placement): this picks the
 * record keys back out, projecting the document's larger `coverage` object
 * DOWN to the record's sub-keys, so
 * `pickSettledOutcome(json) ≡ omit(record, 'schemaVersion')` holds and a
 * consumer holding only the document can reconstruct exactly what the wires
 * carried.
 */
export function pickSettledOutcome(json: Record<string, unknown>): Omit<SettledOutcome, 'schemaVersion'> {
  const out: Record<string, unknown> = {};
  for (const key of SETTLED_OUTCOME_KEYS) {
    if (json[key] === undefined) continue;
    if (key === 'coverage') {
      const c = json.coverage as Record<string, unknown>;
      out.coverage = {
        measured: c.measured,
        examined: c.examined,
        total: c.total,
        unit: c.unit,
        ...(c.unreadableInputs !== undefined ? { unreadableInputs: c.unreadableInputs } : {}),
      };
    } else {
      out[key] = json[key];
    }
  }
  return out as Omit<SettledOutcome, 'schemaVersion'>;
}
