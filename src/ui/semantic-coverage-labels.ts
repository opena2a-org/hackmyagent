/**
 * Wording for the semantic analyzer-family coverage disclosure (#456).
 *
 * `secure` printed `1 semantic artifact` and `1 semantic (NanoMind AST)` over a
 * `doc.md` that two of the seven analyzer families looked at. Both numbers are
 * compile counts; both read as examination counts. These labels are the
 * qualifier that closes that gap, in the same register as the static Coverage
 * line's `22 unexamined (read no file)` and the `compileSetTruncated` notice:
 * name the shortfall, in absolute terms, next to the number it qualifies.
 *
 * Kept out of `cli.ts` so the phrasing is unit-testable without spawning the
 * CLI, which is also what makes the required negative control cheap to assert:
 * a coverage ledger where every artifact reached all seven families must
 * produce NO qualifier at all.
 *
 * Disclosure only. Nothing here reads or affects a finding, severity or score.
 */

import {
  ANALYZER_FAMILIES,
  ANALYZER_FAMILY_COUNT,
} from '../nanomind-core/analyzers/family-coverage.js';
import type { AnalyzerFamily } from '../nanomind-core/analyzers/family-coverage.js';
import type { SemanticFamilyCoverage } from '../nanomind-core/scanner-bridge.js';

/**
 * How each family is named in prose. The internal keys are plural and terse
 * (`capabilities`, `stego`); a user-facing sentence needs the analysis's name.
 */
const FAMILY_PROSE: Record<AnalyzerFamily, string> = {
  capabilities: 'capability',
  credentials: 'credential',
  governance: 'governance',
  scope: 'scope',
  prompt: 'prompt',
  code: 'code',
  stego: 'steganography',
};

/** `a, b and c` — an Oxford-comma-free list, matching the CLI's existing prose. */
function joinProse(items: string[]): string {
  if (items.length <= 1) return items[0] ?? '';
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}

export interface SemanticCoverageDisclosure {
  /** Appended to the Surfaces line, after `N semantic artifact(s)`. */
  surfacesSuffix: string;
  /**
   * Folded into the Checks line's `N semantic (NanoMind AST)` parenthetical.
   * Compact by design — the Surfaces line carries the explanation and the
   * artifact count, and repeating either on a line that already runs to six
   * segments would bury it.
   */
  checksQualifier: string;
  /**
   * Whether this shortfall earns the warning tone.
   *
   * True only when some compiled artifact was read by NO family at all — the
   * semantic equivalent of the static Coverage line's `unexamined (read no
   * file)`, and the same bar it uses ("yellow only for a measured shortfall").
   *
   * A merely partial route does NOT earn it. Measured on a real 30-artifact
   * tree, 26 artifacts reach fewer than seven families, so colouring that
   * yellow would make the Surfaces line permanently yellow and devalue the
   * file-cap warning that prints on the same line. The text still discloses
   * every shortfall; the colour is reserved for the sharp case.
   */
  earnsWarningTone: boolean;
}

/**
 * The disclosure for a coverage ledger, or `null` when there is nothing to
 * disclose — no ledger, nothing compiled, or every compiled artifact was
 * examined by all seven families.
 *
 * Returning `null` for full coverage is the load-bearing case. A qualifier that
 * always prints is indistinguishable from a constant, and a constant is not a
 * measurement: the test that proves this function measures anything is the one
 * asserting it stays SILENT on an artifact that genuinely reached all seven.
 */
export function describeSemanticFamilyCoverage(
  coverage: SemanticFamilyCoverage | undefined,
): SemanticCoverageDisclosure | null {
  if (!coverage || coverage.artifactsCompiled === 0) return null;
  if (coverage.partial.length === 0) return null;

  // No `|| ANALYZER_FAMILY_COUNT` fallback: a ledger reporting `totalFamilies: 0`
  // would silently print "of 7", which is a number nothing measured.
  const total = coverage.totalFamilies;
  if (total <= 0) return null;
  // An internally inconsistent ledger renders nonsense rather than a
  // measurement — `totalFamilies: 3` beside a 5-family group prints "5 of 3",
  // and `fullyExamined` above the compile count prints "all 1 artifacts" over
  // two. Neither is reachable from the bridge, but this reads a public type, and
  // printing a self-contradicting number is worse than printing nothing.
  if (coverage.fullyExamined > coverage.artifactsCompiled) return null;
  if (coverage.partial.some((g) => g.familiesExamined.length > total)) return null;
  const partialArtifacts = coverage.partial.reduce((n, g) => n + g.artifacts, 0);
  const partialCounts = coverage.partial.map((g) => g.familiesExamined.length);
  // The Surfaces line names its own subject ("26 of 30 artifacts"), so its span
  // describes the shortfall classes. The Checks line has no subject — it hangs
  // off `N semantic (NanoMind AST, …)`, i.e. the WHOLE compile count — so its
  // span must include the fully-examined artifacts too. Without them a tree
  // where 4 of 30 artifacts reached all seven printed
  // `30 semantic (NanoMind AST, 0-6 of 7 analyzer families)`, understating those
  // four and contradicting the Surfaces line one row above.
  const allCounts =
    coverage.fullyExamined > 0 ? [...partialCounts, total] : partialCounts;
  const fewest = Math.min(...partialCounts);
  const most = Math.max(...partialCounts);
  const spanOfAll = (() => {
    const lo = Math.min(...allCounts);
    const hi = Math.max(...allCounts);
    return lo === hi ? `${lo}` : `${lo}-${hi}`;
  })();

  // The whole compiled set shares one coverage class — the common case, and the
  // one where naming the blind families is both short and actionable.
  if (coverage.fullyExamined === 0 && coverage.partial.length === 1) {
    const group = coverage.partial[0];
    const examined = new Set<AnalyzerFamily>(group.familiesExamined);
    const missing = ANALYZER_FAMILIES.filter((f) => !examined.has(f));
    const subject = group.artifacts === 1 ? 'it' : 'each';
    const missingProse = joinProse(missing.map((f) => FAMILY_PROSE[f]));
    // `0 of 7` is its own sentence: "no analyzer family read it" is a stronger
    // and clearer claim than listing all seven as absent. This is the
    // documentation/metadata skip, which compiles a file and routes past every
    // analyzer.
    const head =
      group.familiesExamined.length === 0
        ? `no analyzer family examined ${subject}`
        : `${group.familiesExamined.length} of ${total} analyzer families examined ${subject} — ` +
          `${missingProse} analysis did not run`;
    return {
      // Its own ` · ` segment, matching how the rest of the line separates
      // facts. A second parenthetical would collide with the file-cap notice,
      // which prints on this same line whenever a large repo is capped:
      // `200 semantic artifacts (semantic pass capped at 200; …) (partial: …)`.
      surfacesSuffix: ` · ${head}`,
      checksQualifier: `${group.familiesExamined.length} of ${total} analyzer families`,
      earnsWarningTone: group.familiesExamined.length === 0,
      // (Reached only when fullyExamined === 0 and there is a single class, so
      // every compiled artifact really did reach exactly this many families.)
    };
  }

  // Mixed coverage across the compiled set. Report the span rather than an
  // average: a mean would let a fully-examined agent artifact pay for a
  // document nothing looked at.
  const span = fewest === most ? `${fewest}` : `${fewest}-${most}`;
  // `200 of 200 artifacts` is a clumsy way to say "all of them", and on a large
  // repo it is the usual case: measured on this repo's own self-scan, all 200
  // compiled artifacts fall short.
  const subject =
    partialArtifacts === coverage.artifactsCompiled
      ? `all ${partialArtifacts} artifacts`
      : `${partialArtifacts} of ${coverage.artifactsCompiled} artifacts`;
  return {
    surfacesSuffix: ` · ${subject} reached ${span} of ${total} analyzer families`,
    // The artifact count already prints on the Surfaces line above; repeating
    // it here would add a segment without adding a fact.
    checksQualifier: `${spanOfAll} of ${total} analyzer families`,
    earnsWarningTone: fewest === 0,
  };
}
