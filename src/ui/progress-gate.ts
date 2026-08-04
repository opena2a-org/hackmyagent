/**
 * When a long-running command may draw a live progress counter.
 *
 * #260 — `scan-soul --deep` is one LLM round-trip per undetected control, ~55s
 * on the canonical hardened-prose SOUL, and printed nothing until it finished,
 * reading as a hang.
 *
 * #285 — the gate was an inline five-term boolean inside a Commander action
 * handler, and nothing in the suite called `scanSoul` with an `onProgress`
 * callback at all. Covering the WRITE end to end needs a PTY, an
 * `ANTHROPIC_API_KEY` and ~55s of real round-trips; the write is one line and
 * is not where the risk is. The risk is the GATE, because every term in it
 * exists to keep the counter out of output something else parses: the counter
 * is `\r`-based and would corrupt a JSON document or a CI log that is diffed.
 *
 * So the gate is the thing extracted and pinned. It is deny-dominant by
 * construction — any one of `json`, `ci`, `ciMode` or a non-TTY stderr is
 * enough to suppress it, and no combination of the others can override that.
 */
export interface DeepProgressContext {
  /** `--deep` was requested. Without it there is no long pass to report on. */
  deep?: boolean;
  /** `--json`: stdout is a document a machine parses. */
  json?: boolean;
  /** `--ci`. */
  ci?: boolean;
  /** The global CI mode flag, which is a separate switch from `--ci`. */
  ciMode?: boolean;
  /** `process.stderr.isTTY`. A redirected stderr is a file or a pipe. */
  isTty?: boolean;
}

export function shouldShowDeepProgress(ctx: DeepProgressContext): boolean {
  return Boolean(ctx.deep) && !ctx.json && !ctx.ciMode && !ctx.ci && Boolean(ctx.isTty);
}
