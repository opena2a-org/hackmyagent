/**
 * `mark-stub`'s honesty half — every decision that can refuse a write-back,
 * and the evidence a recorded `integrated` carries.
 *
 * The CLI leg of DEFECT 2 in
 * `todo/roadmap/hackmyagent-pull-stubs-status-vocabulary-mismatch.md`: nothing
 * in HMA marked a stub integrated, so the observation -> shipped-check
 * transition was manual and unaudited. The value of a write-back is entirely
 * in whether the record it writes is TRUE, which is why the refusals live
 * here rather than inline in `src/cli.ts` — a predicate that can only be
 * exercised by spawning a binary is a predicate nobody adds a case to.
 *
 * The reachability probe reads `CHECK_METHOD_PREFIXES` and
 * `UNREACHABLE_PREFIXES` out of the RUNNING build's coverage inventory — the
 * same two tables `secure --json` reports from — rather than re-reading
 * `src/` or carrying a copy of either list. `UNREACHABLE_PREFIXES` is the
 * precedent the whole gate exists for: `CODEINJ`, `TMPPATH` and `ENVLEAK` are
 * implemented, emit findings, are counted in the advertised static suite, and
 * have no caller in `scanInner`, so a stub mapped to one of them would be
 * recorded as a shipped check whose detector can never fire. A copied list
 * would go stale the day one of them is wired in, and it would go stale
 * SILENTLY, in the direction that over-claims.
 *
 * Nothing here reads a flag that could supply evidence. `hmaVersion` comes
 * from the artifact's own `VERSION` and `reachable` is the probe's verdict,
 * so the only fabricable field is `sourceCommit` — which is a claim about a
 * repository the registry can check, not about this build.
 */
import { CHECK_METHOD_PREFIXES, UNREACHABLE_PREFIXES } from '../hardening/coverage-ledger';
import { VERSION } from '../index';
import { CLI_PREFIX } from '../cli-prefix';
import { citationPath } from '../ui/shell-quote';
import { escapeForDisplay } from '../ui/display-safe';

/**
 * A refusal, rendered as WHAT / Verify: / Fix: for a person and carried
 * verbatim in the `--json` envelope for a machine.
 *
 * There is no fourth field offering a way past the refusal, and there is no
 * flag that supplies one. A gate with a bypass is a gate that reports the
 * number of people who found the bypass.
 */
export interface StubRefusal {
  /** Stable machine code. Never derived from user input. */
  code: string;
  /** What was refused, and why it would not have been true. */
  what: string;
  /** A command the reader can run to check the claim for themselves. */
  verify: string;
  /** The way forward. Always the real remedy, never a bypass. */
  fix: string;
}

/** The evidence an `integrated` transition carries. Every field is measured. */
export interface StubEvidence {
  checkId: string;
  hmaVersion: string;
  sourceCommit: string;
  reachable: true;
}

/** The PATCH body, camelCase, exactly as it goes on the wire. */
export interface StubPatchBody {
  status: string;
  reason?: string;
  evidence?: StubEvidence;
}

/**
 * `--source-commit` shape. Seven is git's own short-SHA floor and forty is a
 * full SHA-1; anything outside that is not a commit the registry could
 * resolve, so it is refused here rather than recorded and disbelieved later.
 */
export const SOURCE_COMMIT_SHAPE = /^[0-9a-fA-F]{7,40}$/;

/**
 * The two statuses this command gates on, named because the CPO ruling names
 * them: `integrated` is the claim that a check SHIPPED, and `rejected` is the
 * claim that a human decided against one. Both are assertions somebody will
 * later be asked to defend.
 *
 * This is NOT a vocabulary check. Every other word — and these two — go to
 * the registry verbatim; the registry owns which words are legal. These two
 * only decide which local gate applies.
 */
export const EVIDENCE_GATED_STATUS = 'integrated';
export const REASON_GATED_STATUS = 'rejected';

/**
 * Source states out of which a transition is obviously questionable.
 *
 * Used for a WARNING only. The registry is the authority on which
 * transitions are legal — this exists so a fat-fingered re-run of an already
 * settled stub says something before the request goes out, not so the CLI can
 * hold an opinion the registry has to agree with.
 */
const SETTLED_SOURCE_STATES: ReadonlySet<string> = new Set(['integrated', 'rejected']);

/**
 * The longest prefix in `prefixes` that `checkId` belongs to, or null.
 *
 * Longest wins because the registered prefixes are not disjoint by spelling:
 * `SKILL` and `SKILL-MEM` are both registered, and `SKILL-MEM-001` belongs to
 * the second. A first-match walk credits it to `SKILL`, which is a different
 * category with a different method behind it.
 */
export function checkIdPrefix(checkId: string, prefixes: readonly string[]): string | null {
  let best: string | null = null;
  for (const prefix of prefixes) {
    if (checkId !== prefix && !checkId.startsWith(`${prefix}-`)) continue;
    if (best === null || prefix.length > best.length) best = prefix;
  }
  return best;
}

/**
 * Every check-ID prefix a registered `check*` method in THIS build emits.
 *
 * `CHECK_METHOD_PREFIXES` only — deliberately NOT widened with
 * `SEMANTIC_PREFIXES`. The semantic layer is not a `check*` method and its
 * evidence enters the rollup through a different door, so this probe cannot
 * say from the inventory alone that a `SEM-*` / `AST-*` id is called. A stub
 * carrying one is therefore refused as absent rather than recorded on a
 * lookup that proves nothing — a refusal in the honest direction, and one a
 * later unit can lift by proving the semantic side the same way.
 */
export function reachablePrefixes(): string[] {
  return [...new Set(Object.values(CHECK_METHOD_PREFIXES).flat())].sort();
}

/**
 * In-process reachability probe against the running build's inventory.
 *
 * Returns the refusal, or null when the check ID names a family this build
 * both ships and calls.
 */
export function probeReachability(checkId: string): StubRefusal | null {
  const shown = escapeForDisplay(checkId);
  const unreachable = checkIdPrefix(checkId, UNREACHABLE_PREFIXES);
  if (unreachable) {
    return {
      code: 'check-unreachable',
      what:
        `${shown} belongs to the ${escapeForDisplay(unreachable)} family, which this build (v${VERSION}) `
        + 'counts in its advertised suite and never calls. The detector cannot fire, so "integrated" '
        + 'would not be a true statement about this artifact.',
      verify: `${CLI_PREFIX} secure . --json   (the coverage block names this family under unreachableCheckPrefixes)`,
      fix: 'Wire the check into the scan orchestration, publish that build, and record the transition from it.',
    };
  }
  if (!checkIdPrefix(checkId, reachablePrefixes())) {
    return {
      code: 'check-absent',
      what:
        `No check method in this build (v${VERSION}) registers a prefix for ${shown}, so this artifact `
        + 'cannot show that the check exists at all.',
      verify: `${CLI_PREFIX} check-metadata --json   (the check catalogue this build ships)`,
      fix: 'Record the transition from a build that ships the check, or correct the check ID the stub carries.',
    };
  }
  return null;
}

/**
 * Every local gate, in the order a reader would apply them.
 *
 * Runs before any request is built, so a refusable invocation never reaches
 * the network — including under `--dry-run`, where the refusal IS the answer.
 */
export function preflight(input: {
  stubId: string;
  status: string;
  reason?: string;
  sourceCommit?: string;
}): StubRefusal | null {
  const citedId = citationPath(input.stubId) ?? '<stub-id>';
  if (input.sourceCommit !== undefined && !SOURCE_COMMIT_SHAPE.test(input.sourceCommit)) {
    return {
      code: 'source-commit-shape',
      what:
        '--source-commit must be 7 to 40 hexadecimal characters (a git short SHA or a full one); '
        + `got ${escapeForDisplay(input.sourceCommit)}.`,
      verify: 'git rev-parse HEAD',
      fix: `${CLI_PREFIX} mark-stub ${citedId} integrated --source-commit <7-40 hex>`,
    };
  }
  if (input.status === EVIDENCE_GATED_STATUS && !input.sourceCommit) {
    return {
      code: 'source-commit-required',
      what:
        'Recording "integrated" claims a check shipped, and the commit that carries it is the part '
        + 'of that claim this build cannot derive for itself.',
      verify: 'git rev-parse HEAD',
      fix: `${CLI_PREFIX} mark-stub ${citedId} integrated --source-commit <7-40 hex>`,
    };
  }
  if (input.status === REASON_GATED_STATUS && !input.reason) {
    return {
      code: 'reason-required',
      what:
        'Recording "rejected" closes a confirmed observation, and a closed observation with no '
        + 'recorded reason cannot be reviewed or reopened by anyone later.',
      verify: `${CLI_PREFIX} pull-stubs --status rejected --json`,
      fix: `${CLI_PREFIX} mark-stub ${citedId} rejected --reason "<why this stub is not becoming a check>"`,
    };
  }
  return null;
}

/**
 * The warning for a transition out of an already-settled source state.
 *
 * Returns null when there is nothing to say. Deliberately NOT a refusal: the
 * registry owns the transition table, and a CLI that refuses on its own
 * reading of it is a second vocabulary — the exact defect the pull-stubs half
 * of this unit deletes.
 */
export function settledSourceWarning(from: string, to: string): string | null {
  if (!SETTLED_SOURCE_STATES.has(from) || from === to) return null;
  return (
    `Warning: the registry records this stub as "${escapeForDisplay(from)}" and this would move it to `
    + `"${escapeForDisplay(to)}". The registry decides which transitions are legal — this is a heads-up `
    + 'before the request goes out, not a verdict, and it will answer for itself.'
  );
}

/**
 * The evidence for an `integrated` transition.
 *
 * `hmaVersion` is the running artifact's own version and `reachable` is the
 * probe's verdict; neither is reachable from the option surface. Call only
 * after `probeReachability` has returned null for this same `checkId` — the
 * `reachable: true` literal is what that call earns.
 */
export function buildEvidence(checkId: string, sourceCommit: string): StubEvidence {
  return { checkId, hmaVersion: VERSION, sourceCommit, reachable: true };
}

/** The exact PATCH body, with absent fields omitted rather than sent as null. */
export function buildPatchBody(input: {
  status: string;
  reason?: string;
  evidence?: StubEvidence;
}): StubPatchBody {
  const body: StubPatchBody = { status: input.status };
  if (input.reason) body.reason = input.reason;
  if (input.evidence) body.evidence = input.evidence;
  return body;
}
