/**
 * The credential redaction boundary.
 *
 * RIDER B1 (CA): the boundary is `SecurityFinding` CONSTRUCTION — the last
 * construction before any channel, the first construction after every
 * derivation. `ASTFinding` and `SemanticFinding` stay raw in process because
 * line derivation reads them.
 *
 * It is at construction and not at serialization because `package.json` declares
 * 13 subpath exports: a library consumer receives `SecurityFinding` OBJECTS that
 * never touch a serializer, so a serialization boundary leaves the library
 * surface leaking by construction.
 *
 * C1 — line derivation completes BEFORE any redaction of finding text. That
 * ordering is structural here rather than asserted: `emitFinding` takes a draft
 * whose `line` is already resolved and never consults finding text to locate
 * anything, so there is no path on which redaction could run first.
 */

import type { Evidence, PositiveEvidence, AbsenceEvidence } from '../types/finding-evidence';
import type { ShapeId } from '../types/credential-format';
import type { SecurityFinding, SecurityFindingDraft } from './security-check';
import { redactSecretsForReportReporting } from '../nanomind-core/security/defense-in-depth';

/**
 * Unforgeable witness that a finding passed the boundary.
 *
 * NOT exported, and that is the whole mechanism: a `unique symbol` declared in
 * this module cannot be named by any other module, so no code outside this file
 * can build a value of type `RedactedFinding`. `emitFinding` is therefore the
 * only constructor, enforced by the compiler rather than by review.
 */
declare const REDACTION_WITNESS: unique symbol;

/**
 * A `SecurityFinding` that has passed the redaction boundary (C10).
 *
 * The brand and the two runtime fields are complementary, which is why D3 ships
 * both: the brand catches an unwired site at COMPILE time and reaches the 13
 * subpath exports, where a consumer holds an object and no JSON field reaches
 * them at all; the fields catch at RUNTIME what a type cannot — a site that
 * satisfies the type by casting, and the honest reporting of a finding that was
 * never examined.
 */
export type RedactedFinding = SecurityFinding & {
  readonly [REDACTION_WITNESS]: true;
};

/**
 * The byte-carrying string fields of a finding.
 *
 * `rationale.plainEnglish` is handled separately below and is NOT optional
 * despite being absent from the settlement brief's field list (§3.2). That
 * omission is a hole, not a simplification: `finding-adapter.ts:87` assigns
 * `finding.rationale` to `message` and `:98` assigns THE SAME STRING to
 * `rationale.plainEnglish`, so redacting `message` alone leaves the identical
 * bytes on a second field of the same object.
 */
const BYTE_CARRYING_FIELDS = [
  'name',
  'message',
  'description',
  'fix',
  'manualFix',
  'guidance',
  'fixMessage',
] as const satisfies readonly (keyof SecurityFindingDraft)[];

/** Accumulates redaction outcomes across every field of one finding. */
class RedactionPass {
  private changed = false;
  private readonly shapes = new Set<ShapeId>();

  /** Redact one string; undefined passes through so optional fields stay optional. */
  run<T extends string | undefined>(value: T): T {
    if (value === undefined) return value;
    const { text, shapes } = redactSecretsForReportReporting(value);
    if (text !== value) this.changed = true;
    for (const s of shapes) this.shapes.add(s);
    return text as T;
  }

  /**
   * Record that content was altered for safety without a rule having matched.
   *
   * The recursion backstop below uses this: it drops a subtree it declined to
   * walk, and a dropped subtree must never be reported as `'clean'`.
   */
  markChanged(): void {
    this.changed = true;
  }

  get status(): 'applied' | 'clean' {
    return this.changed ? 'applied' : 'clean';
  }

  /** Sorted and deduped, per the frozen field contract. */
  get resolvedShapes(): readonly ShapeId[] {
    return [...this.shapes].sort();
  }
}

/**
 * A list sub-field as the walker will treat it: the value if it really is an
 * array, otherwise empty.
 *
 * `?? []` is NOT sufficient here and that is the whole reason this exists. It
 * guards `null` and `undefined` only, so a producer that writes a STRING (or a
 * number, or a bare object) to `lines` or `expected` still reaches `.map`, and
 * `.map is not a function` throws out of `redactEvidence` exactly as the
 * missing-field crash did. A malformed evidence object must cost its own
 * finding's evidence, never the whole scan.
 */
function asArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

/** Walk the three `Evidence` variants, redacting every byte-carrying leaf. */
function redactEvidence(evidence: Evidence, pass: RedactionPass): Evidence {
  // Every sub-field read below is optional-chained, and that is not defensive
  // habit. `Evidence` describes what a well-formed producer writes; it does not
  // constrain what actually arrives, because `ScanOptions.semanticPass` is a
  // PUBLIC hook and its output reaches here untyped at runtime. A malformed
  // shape used to throw out of `redactEvidence`, and `scan()`'s return has no
  // try/catch around it, so one bad evidence object aborted the entire scan —
  // a crash introduced by the boundary, on input that was previously inert.
  switch (evidence.kind) {
    case 'positive':
      return {
        kind: 'positive',
        lines: asArray<PositiveEvidence['lines'][number]>(evidence.lines).map(l => ({
          n: l?.n,
          content: pass.run(l?.content),
          why: pass.run(l?.why),
        })) as PositiveEvidence['lines'],
      };
    case 'absence':
      return {
        kind: 'absence',
        observed: {
          lines: asArray<AbsenceEvidence['observed']['lines'][number]>(evidence.observed?.lines).map(l => ({
            n: l?.n,
            content: pass.run(l?.content),
          })) as AbsenceEvidence['observed']['lines'],
          summary: pass.run(evidence.observed?.summary),
        },
        // `rationale` here is the constraint's rationale — prose the CHECK
        // wrote about a missing defense, never bytes read out of the artifact.
        // Redacted anyway: a rule that exempts a field by provenance is a rule
        // an attacker can aim at, and the cost of redacting our own prose is a
        // mangled token in text nobody templates a credential into.
        expected: asArray<AbsenceEvidence['expected'][number]>(evidence.expected).map(e => ({
          constraint: e?.constraint,
          rationale: pass.run(e?.rationale),
        })) as AbsenceEvidence['expected'],
      };
    case 'mixed':
      return {
        kind: 'mixed',
        positive: {
          lines: asArray<PositiveEvidence['lines'][number]>(evidence.positive?.lines).map(l => ({
            n: l?.n,
            content: pass.run(l?.content),
            why: pass.run(l?.why),
          })) as PositiveEvidence['lines'],
        },
        absence: {
          observed: {
            lines: asArray<AbsenceEvidence['observed']['lines'][number]>(evidence.absence?.observed?.lines).map(l => ({
              n: l?.n,
              content: pass.run(l?.content),
            })) as AbsenceEvidence['observed']['lines'],
            summary: pass.run(evidence.absence?.observed?.summary),
          },
          expected: asArray<AbsenceEvidence['expected'][number]>(evidence.absence?.expected).map(e => ({
            constraint: e?.constraint,
            rationale: pass.run(e?.rationale),
          })) as AbsenceEvidence['expected'],
        },
      };
    default:
      // An unrecognised `kind` FAILS CLOSED.
      //
      // Returning `undefined` — which is what a `switch` with no `default` does
      // — failed open in both directions at once: it silently DELETED the
      // evidence, and because no rule had matched, the finding then reported
      // `redactionStatus: 'clean'` over the deletion. Losing evidence and
      // claiming cleanliness are each worse than the leak this boundary exists
      // to close.
      //
      // `redactDetails` is the right fallback precisely because it assumes no
      // shape: it rebuilds the object key by key, so the discriminant and every
      // other field survive, and it redacts every string leaf at any depth. A
      // variant added to `Evidence` later is therefore redacted from the day it
      // exists rather than from the day someone remembers to add a case here.
      return redactDetails(evidence, pass) as Evidence;
  }
}

/**
 * `details` is `Record<string, unknown>` — an open bag, so it cannot be walked
 * by a field list. Every string leaf is redacted at any depth.
 *
 * Open-bag totality matters more here than anywhere else: `details.evidence` is
 * one of the four measured JSON leak paths, and the next producer to put a
 * credential in `details` will not think to add it to a list.
 */
/** A `{}`-shaped object: safe to rebuild key by key without losing structure. */
function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== 'object') return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/**
 * What replaces a container the walk declines to descend into.
 *
 * A placeholder rather than the value itself: returning the container verbatim
 * is what made the previous depth cap a leak path, because every string inside
 * it was published without ever being offered to the redactor.
 */
const CYCLE_PLACEHOLDER = '[CYCLE]';
const UNWALKED_PLACEHOLDER = '[REDACTED_UNWALKED]';

/**
 * A depth no honest `details` bag reaches, so this never fires on real data.
 *
 * It is not the cycle guard — `ancestors` is. It is a stack backstop, and it
 * exists because unbounded recursion inside `emitFinding` would throw a
 * `RangeError` from `scan()`'s return, which is the same crash-the-whole-scan
 * failure mode as the malformed-evidence defect two functions up.
 */
const MAX_DETAILS_DEPTH = 200;

function redactDetails(
  value: unknown,
  pass: RedactionPass,
  ancestors: WeakSet<object> = new WeakSet(),
  depth = 0,
): unknown {
  // A string is redacted at ANY depth, and it is checked FIRST so that no
  // guard below can return a string verbatim.
  if (typeof value === 'string') return pass.run(value);

  const isContainer = Array.isArray(value) || isPlainObject(value);
  if (isContainer) {
    const container = value as object;
    // The real cycle guard: membership of the CURRENT PATH, not of everything
    // ever seen. A visited-set would replace a legitimately shared sibling
    // reference with a placeholder, which is silent data loss on a DAG; only an
    // ancestor repeating is a cycle.
    if (ancestors.has(container)) {
      // No bytes are lost: the ancestor this points back at was already walked
      // and every string under it was already offered to the redactor.
      return CYCLE_PLACEHOLDER;
    }
    if (depth >= MAX_DETAILS_DEPTH) {
      // Declining to walk is a modification, and the status must say so. This
      // is the line that stops a deep bag from reporting `'clean'` over content
      // the boundary never examined.
      pass.markChanged();
      return UNWALKED_PLACEHOLDER;
    }

    ancestors.add(container);
    try {
      if (Array.isArray(value)) {
        return value.map(v => redactDetails(v, pass, ancestors, depth + 1));
      }
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        out[k] = redactDetails(v, pass, ancestors, depth + 1);
      }
      return out;
    } finally {
      // Leaving the path. Without this the set would behave as a visited-set
      // and collapse shared references, per the note above.
      ancestors.delete(container);
    }
  }
  // Non-plain objects (`Date`, `Map`, `Set`, class instances) are returned
  // UNCHANGED rather than rebuilt. Rebuilding them from `Object.entries` is
  // silent data loss — that yields `[]` for all three, so a `Date` in `details`
  // would serialize as `{}` where it previously became an ISO string.
  //
  // Measured: nothing in the tree puts a non-plain object in `details` today, so
  // this is a guard against a future producer, not a live path. If one is added
  // and it can carry credential bytes, it needs handling HERE — passing through
  // is safe only while the class carries no body text.
  return value;
}

/**
 * Run the redaction boundary over one draft and stamp the two always-present
 * fields.
 *
 * Returns a NEW object; the draft is never mutated, so a caller holding the
 * draft for its own bookkeeping does not observe redaction applied under it.
 */
export function emitFinding(draft: SecurityFindingDraft): RedactedFinding {
  const pass = new RedactionPass();

  // A value that has ALREADY crossed the boundary can arrive here: several
  // producers are public exports (`scanAssembly` at `src/index.ts:47`) and must
  // emit for their library consumers, and their output is then rebuilt by an
  // internal caller further down.
  //
  // Redaction is idempotent on TEXT — a marker matches no rule — but NOT on the
  // status: a second pass finds nothing to change and would conclude `'clean'`
  // for a finding that really was redacted, downgrading an honest `'applied'`
  // into a false assertion of cleanliness. Applied is therefore absorbing, and
  // shapes accumulate across passes.
  //
  // Read off the runtime value rather than the type: `SecurityFindingDraft`
  // omits these fields, but structural typing lets a full `SecurityFinding` be
  // passed as one, so the type cannot see what is actually there.
  const prior = draft as Partial<SecurityFinding>;
  const priorApplied = prior.redactionStatus === 'applied';
  const priorShapes: readonly ShapeId[] = prior.redactedShapes ?? [];

  const emitted: Record<string, unknown> = { ...draft };
  for (const field of BYTE_CARRYING_FIELDS) {
    const value = draft[field];
    if (typeof value === 'string') emitted[field] = pass.run(value);
  }

  if (draft.evidence !== undefined) {
    emitted.evidence = redactEvidence(draft.evidence, pass);
  }
  if (draft.rationale !== undefined) {
    emitted.rationale = { plainEnglish: pass.run(draft.rationale.plainEnglish) };
  }
  if (draft.details !== undefined) {
    emitted.details = redactDetails(draft.details, pass) as Record<string, unknown>;
  }

  emitted.redactionStatus = priorApplied ? 'applied' : pass.status;
  emitted.redactedShapes = [
    ...new Set([...priorShapes, ...pass.resolvedShapes]),
  ].sort();

  // The one cast that produces the brand. It is confined to this line, which is
  // why the symbol is not exported.
  return emitted as unknown as RedactedFinding;
}

/** Array form. Same boundary, per element. */
export function emitFindings(
  drafts: readonly SecurityFindingDraft[],
): RedactedFinding[] {
  return drafts.map(emitFinding);
}

// A `reemitFinding` wrapper was written here and DELETED before it shipped: it
// had zero production callers, and `emitFinding` already handles an
// already-emitted input through its absorbing-applied merge, so the wrapper
// added a second name for one behaviour and nothing else.
//
// The settlement brief §3.5 records the cost of keeping such a function:
// `redactSecretsForNanoMind` is the documented "NanoMind has zero access to
// secrets" boundary, has zero production call sites, and its presence is why the
// daemon boundary was believed to exist for as long as it did. An exported
// function with no callers is read as a guarantee. Rebuild sites call
// `emitFinding` directly.
