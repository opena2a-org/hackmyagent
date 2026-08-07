/**
 * One derivation of a verdict and its exit code, shared by every output
 * channel and by every command that reports a security posture.
 *
 * ## What #373 closed
 *
 * `check` computed the same `risk` in both branches, then returned out of the
 * `--json` branch before reaching the statement that turned that risk into an
 * exit code. So `check <target>` exited 1 on four CRITICAL findings and
 * `check <target> --json` exited 0 while reporting `"risk": "critical"` in the
 * same payload. Rendering must not be able to change the exit code, so the
 * call sites derive the verdict and settle it ABOVE the channel branch and a
 * `return` inside any renderer cannot skip it.
 *
 * ## What this file closes now: verdict without measurement
 *
 * #373 made the exit code agree with the printed risk. It did not make either
 * of them agree with *what the run actually looked at*. Six commands shipped a
 * confident verdict over an empty measurement:
 *
 * - `attack <unreachable>` sent 111 payloads, every one threw at the socket,
 *   and the report read `0/100 (SECURE)` at exit 0 (#406). `secure` was
 *   derived from `successful.length === 0`, and a payload that never arrived
 *   is not a payload that was blocked.
 * - `attack --local` returned the same `2/100 (LOW)` for a jailbreak prompt, a
 *   hardened prompt and an empty file (#430), because `simulateLocal` returns a
 *   fixed sentence and the analyzer then scored HackMyAgent's own placeholder
 *   text. The number moved with `--intensity` and never with the target.
 * - `check <path-that-does-not-exist>` fell through to the registry lookup and
 *   printed `MEDIUM RISK` at exit 0, with `--json` asserting
 *   `"revocation":{"revoked":false}` about a thing that was never there (#417).
 * - `secure -b oasb-2` exited 0 at `Conformance: NONE` (#371).
 * - The four remote `check --json` paths carried no coverage at all (#416).
 * - `detect` printed `1 high-severity issue found` at exit 0 (#390).
 *
 * Those are one defect. A risk band is a claim about a target, and a claim
 * needs evidence. So the fix is not six patches: it is a type in which the
 * claim cannot be spelled without the evidence beside it.
 *
 * `MeasuredVerdict` carries a mandatory `coverage`. `UnmeasuredVerdict` has no
 * `risk` field at all — there is no way to reach `.risk` without first proving
 * `.measured === true`, and no way to construct `.measured === true` without
 * supplying a `Coverage`. `deriveCheckVerdict` then refuses to issue a risk
 * band over `examined === 0` and downgrades to `unmeasured`, so "nothing was
 * examined, therefore SECURE" is not reachable by any caller, present or
 * future.
 *
 * ## Exit codes
 *
 * | code | meaning |
 * |---|---|
 * | 0 | measured, and the result is one the command promises to pass on |
 * | 1 | measured, and the result is one the command promises to fail on |
 * | 2 | **not measured** — the command cannot say, and does not pretend to |
 *
 * 2 is non-zero on purpose. A CI job that asked for a security verdict and got
 * "I could not reach the target" has not been told the target is safe, and the
 * conservative reading is the honest one. Exit 0 there is the bug being fixed.
 */

/** Severity band a command reports for a target. Ordered worst-first. */
export type CheckRisk = 'critical' | 'high' | 'medium' | 'low';

/** Measured, passing. */
export const EXIT_PASS = 0;
/** Measured, failing — the band `--help` promises to fail on. */
export const EXIT_FAIL = 1;
/** Not measured. The command cannot report a risk band. */
export const EXIT_UNMEASURED = 2;

export interface CheckSeverityCounts {
  /** Failing findings at CRITICAL. */
  critical: number;
  /** Failing findings at HIGH. */
  high: number;
  /**
   * All failing findings. Read ONLY to separate `medium` from `low`, which is
   * why the paths that do not count MEDIUM/LOW separately may omit it: both
   * bands exit 0, so an omission can understate `medium` as `low` and can
   * never turn a failing band into a passing one.
   */
  issues?: number;
}

/**
 * Evidence that the run examined something. Every field is counted at runtime
 * from the run itself — never from the configured check set, which is what
 * made `310 static · 0 skipped · (all clear)` print identically whether the
 * checks ran against the tree or not.
 */
export interface Coverage {
  /**
   * Units the run actually inspected and got an answer for. A file whose
   * contents were read; a payload that came back with a response; a control
   * that was evaluated. **Not** a unit that was attempted and threw.
   */
  readonly examined: number;
  /** Units the run set out to inspect. `examined <= total`. */
  readonly total: number;
  /** Singular noun for one unit, for the sentence a renderer prints. */
  readonly unit: string;
}

/**
 * Why a run produced no measurement. Each value is a distinct thing that went
 * wrong at the target, because "we could not tell you" and "we could not
 * reach it" are different sentences for the user and different fixes.
 */
export type UnmeasuredReason =
  /** The path, package or repository does not exist. */
  | 'target-not-found'
  /** The target exists but no request to it completed. */
  | 'target-unreachable'
  /** Requests completed but not one produced an analyzable answer. */
  | 'no-response'
  /** No request was made to anything: the run was a simulation. */
  | 'simulation-only'
  /** The target exists and is unreadable — permissions, or an unreadable root. */
  | 'target-unreadable'
  /** The target was reachable and readable and held nothing to examine. */
  | 'nothing-to-examine';

export interface MeasuredVerdict {
  readonly measured: true;
  readonly risk: CheckRisk;
  /** Mandatory. This is the whole point of the type. */
  readonly coverage: Coverage;
  readonly exitCode: typeof EXIT_PASS | typeof EXIT_FAIL;
}

export interface UnmeasuredVerdict {
  readonly measured: false;
  readonly reason: UnmeasuredReason;
  /**
   * One sentence naming the target and what happened to it, for the user.
   * Callers pass an already-escaped string when it embeds a path or a URL.
   */
  readonly detail: string;
  /**
   * What the run TRIED to examine, when it got that far. `examined` is 0 by
   * definition on this arm; `total` and `unit` are the information that would
   * otherwise be lost.
   *
   * Without this, a run that sent 111 payloads and had none answered
   * serialized as `{examined: 0, total: 0, unit: 'unit'}` — indistinguishable
   * from a run that never started, and reporting a unit no caller used.
   */
  readonly attempted?: Coverage;
  readonly exitCode: typeof EXIT_UNMEASURED;
}

/**
 * No `risk` on the unmeasured arm: reading `verdict.risk` without narrowing on
 * `verdict.measured` is a compile error, so a renderer cannot print a band the
 * run did not earn.
 */
export type CheckVerdict = MeasuredVerdict | UnmeasuredVerdict;

/** A run that inspected everything it set out to inspect. */
export function fullCoverage(examined: number, unit: string): Coverage {
  return { examined, total: examined, unit };
}

/** A run that could not measure. The only way to build the unmeasured arm. */
export function unmeasured(
  reason: UnmeasuredReason,
  detail: string,
  attempted?: Coverage,
): UnmeasuredVerdict {
  return { measured: false, reason, detail, attempted, exitCode: EXIT_UNMEASURED };
}

/**
 * `check --help` promises: "Exit code 1 if high/critical risk detected." This
 * is the single place that promise is kept, so the exit code cannot disagree
 * with the `risk` printed beside it.
 *
 * `coverage` is required and is not decorative. When the run examined nothing,
 * this returns `unmeasured` rather than a band — a caller that counted zero
 * findings over zero examined units has measured nothing, and the difference
 * between that and a clean bill of health is the entire defect class. Callers
 * that want the band anyway have to change this function and say why.
 */
export function deriveCheckVerdict(
  counts: CheckSeverityCounts,
  coverage: Coverage,
  /**
   * Reason to report when `coverage.examined` is 0. Defaults to the honest
   * general case; a caller that knows *why* it examined nothing (unreachable
   * socket, missing path) should say so instead.
   */
  emptyReason: UnmeasuredReason = 'nothing-to-examine',
  emptyDetail?: string,
): CheckVerdict {
  if (coverage.examined <= 0) {
    return unmeasured(
      emptyReason,
      emptyDetail
        ?? `No ${coverage.unit} was examined, so no risk level can be reported for this target.`,
      // Carry what was attempted. "0 of 111 payloads answered" and "0 of 0"
      // are different facts and a consumer needs to tell them apart.
      coverage,
    );
  }

  // `?? 0` and not `?? critical + high`: the two are equivalent, because
  // `issues` is only ever read on the branch where critical and high are both
  // zero. The longer spelling implied a fallback that does nothing.
  const issues = counts.issues ?? 0;
  const risk: CheckRisk =
    counts.critical > 0 ? 'critical'
      : counts.high > 0 ? 'high'
        : issues > 0 ? 'medium'
          : 'low';
  return {
    measured: true,
    risk,
    coverage,
    exitCode: risk === 'critical' || risk === 'high' ? EXIT_FAIL : EXIT_PASS,
  };
}

/**
 * The `coverage` object every machine channel emits, so `--json` consumers can
 * tell "clean" from "never looked" without parsing prose.
 *
 * ONE shape, on every path that emits it, measured or not: `measured` is
 * always present and always a boolean, so `jq -e '.coverage.measured'` is a
 * contract a consumer can rely on. The first cut of this emitted three
 * different shapes — `measured` absent on the local-scan path, the whole
 * `coverage` key absent on every not-found path — which is the case the key
 * exists for.
 *
 * Emitted by `check` (local, remote and not-found arms), `attack`, `detect`
 * and the two deprecated `secure-*` commands. NOT by `secure`, which still
 * derives its own score without a measurement gate — that is a known gap, not
 * a claim this function makes. An earlier version of this comment asserted
 * four commands shared it and cannot drift; two of the four did not call it.
 *
 * It also no longer flattens the unmeasured arm to `0/0 unit`: `attempted`
 * carries what the run tried, so "0 of 111 payloads answered" survives.
 */
export function coverageJson(verdict: CheckVerdict): {
  measured: boolean;
  examined: number;
  total: number;
  unit: string;
  reason?: UnmeasuredReason;
  detail?: string;
} {
  if (verdict.measured) return { measured: true, ...verdict.coverage };
  return {
    measured: false,
    examined: 0,
    total: verdict.attempted?.total ?? 0,
    unit: verdict.attempted?.unit ?? 'unit',
    reason: verdict.reason,
    detail: verdict.detail,
  };
}

/** One sentence for the text channel. Empty string when the run measured. */
export function unmeasuredBanner(verdict: CheckVerdict): string {
  if (verdict.measured) return '';
  return `NOT MEASURED — ${verdict.detail}`;
}
