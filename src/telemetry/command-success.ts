/**
 * Whether a finished command counts as a SUCCESS in telemetry (#350).
 *
 * `successFromExitCode` in `@opena2a/telemetry` treats 0 and 1 alike and only
 * `>= 2` as a crash. That is right for `secure`, where exit 1 means "findings
 * were detected and the command did its job" — the security-tool convention.
 *
 * It is wrong for `rollback`. There, exit 1 means the command could NOT put
 * every listed file back (#327, and #344 which made it `process.exitCode` so
 * the report survives a pipe). Under the shared convention the aggregate
 * reported 100% success on exactly the runs that failed — and rollback recovery
 * is the subject that metric would have to surface. Six rounds of fixes have
 * gone into it; the fleet-level signal that would have shown any of them in
 * production was inverted for the one command they are about.
 *
 * The library's `semanticSuccessCodes` parameter cannot express this: it only
 * ADDS codes to the success set (`if (semanticSuccessCodes?.includes(n)) return
 * true; return n <= 1;`), so it can widen success and never narrow it. The
 * decision therefore belongs at the call site, which is what this module is.
 *
 * Lives outside `src/cli.ts` so it can be tested as a function. `cli.ts` builds
 * a Commander program at import time, so anything defined there can only be
 * checked by grepping its source — which is the #285 finding about #260, where
 * three `readFileSync('src/cli.ts')` substring greps gave false confidence that
 * a behaviour was covered.
 */

/**
 * Commands whose exit 1 reports a FAILURE rather than a result.
 *
 * The question to ask before adding one: does a non-zero exit here mean "I did
 * my job and the answer was bad news" (leave it out) or "I did not do my job"
 * (add it)? `secure` and `scan-soul` exit 1 for findings — the first case.
 * `rollback` exits 1 when files did not come back — the second.
 */
export const EXIT1_IS_FAILURE: ReadonlySet<string> = new Set(['rollback']);

/**
 * Commands whose exit 2 reports a RESULT rather than a crash.
 *
 * The shared convention treats `>= 2` as "the command did not do its job", which
 * is right for an unhandled throw. `red-team` exits 2 on every run to mean "I
 * generated payloads and executed none, so I reached no verdict" (#369) — the
 * command doing exactly what it is built to do. Left out, the fleet-level
 * success rate for `red-team` would read 0%.
 *
 * That is #350 in mirror image: this module exists because the aggregate
 * reported 100% success on precisely the runs that failed, and reporting 100%
 * failure on runs that succeeded is the same signal broken the other way. Unlike
 * the `rollback` case, the library CAN express this one — `semanticSuccessCodes`
 * only ever widens the success set — so this maps to that parameter rather than
 * overriding the convention.
 *
 * Before adding one, ask the same question: does this exit code mean "I did my
 * job and here is the answer" (add it) or "I did not do my job" (leave it out)?
 */
export const EXIT2_IS_SEMANTIC: ReadonlySet<string> = new Set(['red-team']);

/**
 * Resolve the success flag for a command event.
 *
 * `conventional` is `tele.successFromExitCode`, injected rather than imported so
 * this module stays free of the telemetry SDK and its config/network side
 * effects — and so a test can prove the exception is what decides the answer,
 * by passing a `conventional` that would give the opposite one.
 */
export function commandSucceeded(
  name: string,
  exitCode: number,
  conventional: (code: number, semanticSuccessCodes?: readonly number[]) => boolean,
): boolean {
  if (EXIT1_IS_FAILURE.has(name)) return exitCode === 0;
  // Widen, never narrow — the library only supports widening, and narrowing is
  // what the EXIT1_IS_FAILURE branch above is for.
  if (EXIT2_IS_SEMANTIC.has(name)) return conventional(exitCode, [2]);
  return conventional(exitCode);
}
