/**
 * One derivation of `check`'s verdict and its exit code, shared by every
 * output channel. Closes #373.
 *
 * The defect this exists to make unrepresentable: `check` computed the same
 * `risk` in both branches, then returned out of the `--json` branch before
 * reaching the statement that turned that risk into an exit code. So
 * `check <target>` exited 1 on four CRITICAL findings and
 * `check <target> --json` exited 0 while reporting `"risk": "critical"` in
 * the same payload. Live since 0.12.7 (2026-04-01); `check` has no `--ci`
 * flag, so `--json` IS the CI integration path and no automated consumer of
 * `check` has ever been able to fail on findings.
 *
 * Rendering must not be able to change the exit code. The call sites derive
 * the verdict and settle it ABOVE the channel branch, so a `return` inside
 * any renderer cannot skip it — the class of defect is removed rather than
 * the five instances being patched. `secure` reached the same outcome by
 * repeating the exit statement once per format branch (`src/cli.ts:4409`,
 * `:4423`, `:4436`, `:4455`); repeating it is what left `check` behind when
 * a sixth branch was added.
 */

/** Severity band `check` reports for a target. Ordered worst-first. */
export type CheckRisk = 'critical' | 'high' | 'medium' | 'low';

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

export interface CheckVerdict {
  readonly risk: CheckRisk;
  /** 1 when the risk band is one `check --help` promises to fail on. */
  readonly exitCode: 0 | 1;
}

/**
 * `check --help` promises: "Exit code 1 if high/critical risk detected." This
 * is the single place that promise is kept, so the exit code cannot disagree
 * with the `risk` printed beside it.
 */
export function deriveCheckVerdict(counts: CheckSeverityCounts): CheckVerdict {
  // `?? 0` and not `?? critical + high`: the two are equivalent, because
  // `issues` is only ever read on the branch where critical and high are both
  // zero. The longer spelling implied a fallback that does nothing.
  const issues = counts.issues ?? 0;
  const risk: CheckRisk =
    counts.critical > 0 ? 'critical'
      : counts.high > 0 ? 'high'
        : issues > 0 ? 'medium'
          : 'low';
  return { risk, exitCode: risk === 'critical' || risk === 'high' ? 1 : 0 };
}
