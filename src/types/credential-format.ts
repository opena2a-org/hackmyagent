/**
 * Shared credential-format detection.
 *
 * Two independent signals decide whether a substring "looks like a credential":
 *
 *   1. A curated vendor prefix (`sk-`, `sk_live_`, `ghp_`, `ghs_`, `hf_`,
 *      `glpat-`, `npm_`, `AKIA…`, `AIza…`, `xox[abprs]-`, `SG.`, `eyJ…` JWT).
 *      These are positively identified by their prefix and are accepted on
 *      shape alone.
 *
 *   2. A high-entropy fallback: a 40+ word-character run, anchored on word
 *      boundaries, excluding `-` and `/` so URL slugs and slug-style
 *      identifiers do not match.
 *
 * Signal 2 was a pure LENGTH test, so a fill-in-the-blank form rule
 * (`Local Office: _______________________________________________`) read as a
 * credential. That produced a HIGH "Hardcoded Secret Detected" on a public
 * incident-response contact-sheet template whose only "secret" was the heading
 * "U.S. Secret Service (Cyber Fraud)" sitting next to two form blanks.
 *
 * See `isCredibleEntropyBlob` for the rule that separates the two classes and
 * for the two weaker rules that were tried and rejected.
 *
 * Bare-keyword mentions ("credentials", "API key", "token") in descriptive text
 * do NOT count as either signal. Placeholder / env-var reference values
 * (`$OPENAI_API_KEY`, `${OPENAI_API_KEY}`, `<YOUR_KEY>`) fail the fallback
 * because the leading `$`/`<` are not word characters.
 */

/**
 * Longest run of base64url characters accepted for a JWT's HEADER segment
 * before the first `.`.
 *
 * This bound is a denial-of-service defense, not a format detail. `eyJ` is
 * followed by `[A-Za-z0-9_-]+`, a class that contains `-`, so on adversarial
 * filler (`eyJ-eyJ-eyJ-…`) the segment run extends to the end of the file. The
 * engine then walks back looking for a `.` that is not there, at every one of
 * the O(n) `eyJ` offsets: quadratic. Measured on `'_'x47 + '-' + 'eyJ-'xN`
 * before this bound existed: 58 ms at 16 KB, 808 ms at 64 KB, 13.5 s at 256 KB,
 * ~215 s extrapolated at the 1 MB scanner cap. `main` was 0.0 ms at every size
 * only because it stopped at the first candidate and never reached the filler.
 *
 * A real JWT header encodes a small JSON object (`{"alg":"RS256","typ":"JWT"}`
 * and friends), so 256 base64url characters is roughly 190 bytes of header —
 * far more than any hardcoded token carries. Segments after the first dot use
 * the larger bound below, because reaching them already required a literal
 * `eyJ<seg>.`, which adversarial filler does not produce by accident.
 */
const MAX_JWT_HEADER_CHARS = 256;

/** Bound for the JWT payload and signature segments. See above. */
const MAX_JWT_TAIL_CHARS = 4096;

/**
 * The JWT alternative, written so it cannot backtrack.
 *
 * `(?=(?<name>X))\k<name>` is the standard emulation of an atomic group: the
 * lookahead matches `X` greedily, and a lookahead is never re-entered once it
 * has succeeded, so the backreference consumes exactly that run and a
 * subsequent failure discards the whole alternative instead of walking back
 * through it one character at a time.
 *
 * NAMED, not numbered, groups: this string is spliced into more than one
 * alternation (`buildCredentialFormatRegex`, `VENDOR_PREFIX_ONLY_RE`,
 * `VENDOR_PREFIX_CONTENT_RE` in the credential analyzer) at different offsets,
 * so `\1` would refer to a different group in each one. Each name appears once
 * per built regex; do not splice this array into a single regex twice.
 */
const JWT_ALTERNATIVE =
  `eyJ(?=(?<jwtHead>[A-Za-z0-9_-]{1,${MAX_JWT_HEADER_CHARS}}))\\k<jwtHead>\\.` +
  `(?=(?<jwtBody>[A-Za-z0-9_-]{1,${MAX_JWT_TAIL_CHARS}}))\\k<jwtBody>\\.` +
  `[A-Za-z0-9_-]{1,${MAX_JWT_TAIL_CHARS}}`;

/**
 * Vendor-prefixed credential shapes, in one place.
 *
 * This is the single source of truth. The credential analyzer's
 * `hasVendorPrefixCredential` content gate and `maskCredentialValue` both build
 * from this same array; keeping separate hand-maintained lists meant a token
 * could be "vendor-known" to one gate and anonymous to another, which is how
 * `hf_`, `ghs_`, `ghu_`, `glpat-` and `npm_` ended up subject to the entropy
 * fallback in one code path and exempt in the next.
 *
 * Alternatives are NOT anchored here. Anchoring is applied once, centrally, by
 * `anchoredVendorAlternation()` — see the comment there for why every consumer
 * must use it.
 */
export const VENDOR_PREFIX_ALTERNATIVES = [
  'sk-ant-api[0-9][a-zA-Z0-9_-]{16,}',
  'sk-proj-[a-zA-Z0-9_-]{16,}',
  'sk-[a-zA-Z0-9_-]{20,}',
  'sk_live_[a-zA-Z0-9]{20,}',
  'sk_test_[a-zA-Z0-9]{20,}',
  'ghp_[a-zA-Z0-9]{20,}',
  'gho_[a-zA-Z0-9]{20,}',
  'ghs_[a-zA-Z0-9]{20,}',
  'ghu_[a-zA-Z0-9]{20,}',
  'github_pat_[a-zA-Z0-9_]{20,}',
  'hf_[a-zA-Z0-9]{20,}',
  'glpat-[a-zA-Z0-9_-]{20,}',
  'npm_[a-zA-Z0-9]{20,}',
  'AKIA[0-9A-Z]{16}',
  'AIza[0-9A-Za-z_-]{35}',
  'xox[abprs]-[0-9A-Za-z-]{10,}',
  // SendGrid keys are `SG.<key id>.<secret>` — BOTH dots are required.
  // Written as a single-dot prefix it matched any dotted identifier whose
  // namespace happened to end in `SG`, which is how `MSG.INCIDENT_ESCALATION_QUEUE`
  // and `using SG.Configuration_Providers_Internal;` became "credentials". The
  // second segment is what makes this a key rather than a namespace.
  'SG\\.[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,}',
  JWT_ALTERNATIVE,
];

/**
 * Left anchor for a vendor prefix: the prefix must not be glued to the tail of
 * an alphanumeric identifier.
 *
 * NOT `\b`. `\b` counts `_` as a word character, and the whole point of this
 * unit is that documents are full of underscore filler — `'_'x38 +
 * 'sk-ant-api03-<real key>'` has no word boundary before `sk`, so `\b` silently
 * dropped a real credential glued to a form blank. That case has a regression
 * test and it caught this exact mistake.
 *
 * `(?<![A-Za-z0-9])` blocks what the false positives actually looked like — a
 * prefix continuing an alphanumeric identifier (`MSG.…`, `MYghp_…`) — while
 * still matching a credential that follows punctuation or filler.
 */
const VENDOR_PREFIX_LEFT_ANCHOR = '(?<![A-Za-z0-9])';

/**
 * The vendor alternation with its left anchor, built once.
 *
 * Without central anchoring the consumers disagreed: only the analyzer's
 * content gate was anchored, so `MSG.INCIDENT_ESCALATION_QUEUE` was a
 * credential to the detection path and not to the suppression gate. Anchoring
 * here makes agreement a property of the module rather than a per-call-site
 * convention.
 *
 * ANCHORING IS CHOSEN BY GATE POLARITY, NOT APPLIED UNIFORMLY. Use this in
 * POSITIVE gates, where matching means "a credential is present" and a
 * narrower predicate means fewer false positives. Do NOT use it in a NEGATED
 * gate: the suppression vetoes read `!predicate(content)`, so narrowing the
 * predicate makes the carve-out fire MORE often and turns every value the
 * anchor rejects into a place to hide a secret. Those callers take
 * `VENDOR_PREFIX_ALTERNATIVES` raw and stay deliberately trigger-happy.
 */
export function anchoredVendorAlternation(): string {
  return `${VENDOR_PREFIX_LEFT_ANCHOR}(?:${VENDOR_PREFIX_ALTERNATIVES.join('|')})`;
}

/**
 * Per-vendor "recognisable prefix" matchers, derived from the alternatives.
 *
 * Derived, never hand-written. A hand-maintained copy of this list lived in
 * `maskCredentialValue` and had fallen five entries behind (`SG.`, `hf_`,
 * `glpat-`, `npm_`, `ghu_`), so those tokens took the "unknown shape" masking
 * branch, which exposes the first 8 characters. For `hf_…` that is 5
 * characters of live secret body printed into a finding's `evidence` — the one
 * thing the masking layer exists to prevent. Deriving the list means a new
 * vendor prefix cannot become detectable without also becoming maskable.
 *
 * The head is taken up to (not including) the first QUANTIFIED atom, which is
 * where the secret body begins. Unquantified single-character classes are kept,
 * so `xox[abprs]-` preserves the full `xoxb-` rather than a bare `xox` — the
 * evidence line has to stay recognisable as a Slack BOT token to be useful.
 */
const VENDOR_PREFIX_MATCHERS: readonly RegExp[] = VENDOR_PREFIX_ALTERNATIVES.map(alt => {
  const isQuantifier = (c: string | undefined) => c === '{' || c === '+' || c === '*' || c === '?';
  let head = '';
  let i = 0;
  while (i < alt.length) {
    const ch = alt[i];
    if (ch === '\\') {
      // An escaped metacharacter is a literal. Keep the escape as written.
      if (i + 1 >= alt.length || isQuantifier(alt[i + 2])) break;
      head += alt.slice(i, i + 2);
      i += 2;
      continue;
    }
    if (ch === '[') {
      const close = alt.indexOf(']', i + 1);
      if (close === -1 || isQuantifier(alt[close + 1])) break;
      head += alt.slice(i, close + 1);
      i = close + 1;
      continue;
    }
    if ('(){}+*?|^$.'.includes(ch)) break;
    if (isQuantifier(alt[i + 1])) break;
    head += ch.replace(/[-]/, '\\$&');
    i++;
  }
  return new RegExp(`^${head}`);
});

/**
 * The longest recognisable vendor prefix of `value`, or undefined when the
 * value matches no vendor shape. Longest wins, so `sk-ant-api0` beats `sk-`.
 */
export function matchVendorPrefix(value: string): string | undefined {
  let longest: string | undefined;
  for (const re of VENDOR_PREFIX_MATCHERS) {
    const m = re.exec(value);
    if (m && m[0].length > (longest?.length ?? 0)) longest = m[0];
  }
  return longest;
}

/** High-entropy fallback: 40+ word characters, word-boundary anchored. */
const ENTROPY_BLOB_ALTERNATIVE = '\\b[A-Za-z0-9+=_]{40,}\\b';

/**
 * Longest period treated as filler, and the number of times that unit must
 * repeat before the run is called filler rather than a short coincidence.
 *
 * Four covers every observed false positive (`_`, `_=`, `01`, `de`, `a1`) while
 * three full repetitions keeps the rule off short values, where a small period
 * arises by chance: `abcdabcd` is 8 characters with period 4 but only two
 * repeats, so it is NOT filler.
 */
const MAX_FILLER_PERIOD = 4;
const MIN_FILLER_REPEATS = 3;

/**
 * Share of the run a single character may occupy before the run is filler.
 *
 * A form blank with one stray mark (`'_'x46 + '1'`) is aperiodic, so the period
 * rule alone does not reach it — that is the "one character from failing" case.
 * At 40+ characters a genuine secret cannot be 90% one symbol: even a base-4
 * secret sits near 25% per symbol, and the probability of a random 40-character
 * draw reaching 90% is negligible.
 */
const MAX_DOMINANT_CHAR_SHARE = 0.9;

/**
 * Smallest p such that `value[i] === value[i - p]` for every i >= p, computed
 * from the KMP failure function's longest proper border. A string with no
 * border has period equal to its own length, i.e. it is aperiodic.
 */
function minimalPeriod(value: string): number {
  const n = value.length;
  const failure = new Int32Array(n);
  let k = 0;
  for (let i = 1; i < n; i++) {
    while (k > 0 && value[i] !== value[k]) k = failure[k - 1];
    if (value[i] === value[k]) k++;
    failure[i] = k;
  }
  return n - (n > 0 ? failure[n - 1] : 0);
}

/** True when one character occupies more than `MAX_DOMINANT_CHAR_SHARE` of the run. */
function isDominatedBySingleChar(value: string): boolean {
  const counts = new Map<string, number>();
  let max = 0;
  for (const ch of value) {
    const next = (counts.get(ch) ?? 0) + 1;
    counts.set(ch, next);
    if (next > max) max = next;
  }
  return max > value.length * MAX_DOMINANT_CHAR_SHARE;
}

/**
 * True when a fallback match could carry entropy at all.
 *
 * Two rules, both aimed at the same class: text used as visual filler.
 *
 *   1. The run is a short unit repeated at least three times
 *      (`'_'x47`, `'_='x25`, `'01'x20`, `'de'x24`, `'a1'x24`).
 *   2. One character occupies more than 90% of the run (`'_'x46 + '1'`).
 *
 * Two weaker rules were tried first and rejected, both by adversarial review:
 *
 *   - A floor of 5 DISTINCT characters. Distinct-character count is not an
 *     entropy measure: four symbols carry two bits each, so a 64-character
 *     base-4 blob holds 128 bits and would have been discarded. It silenced a
 *     planted `AST-CRED-002` CRITICAL whose only unusual property was a
 *     four-letter alphabet, and dropped real `hf_`, `ghs_` and `npm_` tokens
 *     with repetitive bodies.
 *   - "Not a single repeated character" (distinct >= 2). One character from
 *     failing: `'_'x46 + '1'` and `'_='x25` both still read as credentials.
 *
 * The rules above admit a genuine low-alphabet secret — random base-4 text has
 * no short period and no dominant symbol — which is the property the distinct-
 * character floor could not express.
 */
export function isCredibleEntropyBlob(value: string): boolean {
  if (value.length === 0) return false;
  const period = minimalPeriod(value);
  if (period <= MAX_FILLER_PERIOD && value.length >= period * MIN_FILLER_REPEATS) {
    return false;
  }
  return !isDominatedBySingleChar(value);
}

/**
 * Build the candidate matcher. Vendor alternatives are listed before the
 * entropy fallback so that at any given start offset a vendor-prefixed key
 * matches as a vendor key, not as an anonymous blob.
 *
 * Not exported: this is the CANDIDATE gate, and using it directly reproduces
 * the original defect. Callers want `hasCredentialFormat` /
 * `findCredentialFormatMatch` (filtered) or `hasAnyCredentialCandidate`
 * (deliberately unfiltered, for suppression vetoes).
 */
function buildCredentialFormatRegex(flags = ''): RegExp {
  return new RegExp(
    `${anchoredVendorAlternation()}|${ENTROPY_BLOB_ALTERNATIVE}`,
    flags,
  );
}

/**
 * The candidate matcher for NEGATED gates: same alternation, vendor prefixes
 * left UNANCHORED on purpose.
 *
 * `hasAnyCredentialCandidate` is read as `!hasAnyCredentialCandidate(content)`,
 * so every narrowing of this predicate widens a suppression carve-out. Under
 * the anchored alternation a token glued to a preceding identifier
 * (`"label":"MSGghp_AAAAAAAAAAAAAAAAAAAA"`, 27 characters and so below the
 * 40-character blob floor) matches nothing, the veto stops holding, and the
 * planted secret is suppressed. Unanchored, it still matches.
 */
function buildCandidateRegexForNegatedGate(): RegExp {
  return new RegExp(
    `(?:${VENDOR_PREFIX_ALTERNATIVES.join('|')})|${ENTROPY_BLOB_ALTERNATIVE}`,
  );
}

/**
 * Vendor-prefix-only matcher, used to tell the two signals apart.
 *
 * Module-level and deliberately WITHOUT the `g` flag: a global regex carries
 * `lastIndex` state across `.test()` calls, which would make a shared instance
 * skip matches non-deterministically. Without `g`, `.test()` is stateless and
 * the instance is safe to reuse.
 */
const VENDOR_PREFIX_ONLY_RE = new RegExp(anchoredVendorAlternation());

/**
 * True when a candidate substring should count as a credential: either it is
 * vendor-prefixed, or it clears the filler rules.
 */
export function isAcceptedCredentialMatch(candidate: string): boolean {
  return VENDOR_PREFIX_ONLY_RE.test(candidate) || isCredibleEntropyBlob(candidate);
}

/**
 * Find the first ACCEPTED credential-format substring in `text`.
 *
 * On rejecting a candidate the scan resumes one character past where that
 * candidate STARTED, not past where it ended. The entropy fallback is greedy
 * over a class that includes `_`, so a rejected filler run can begin one or two
 * characters before a real credential and swallow its prefix
 * (`KIAAKIAAKIA…` is period-4 filler that contains `AKIA…` from offset 3);
 * resuming past the whole run would skip the credential entirely.
 *
 * `MAX_REJECTED_CANDIDATES` bounds that one-character walk. It is a
 * belt-and-braces companion to the JWT bound above: the JWT bound removes the
 * quadratic cost inside a single scan, and this removes any possibility of an
 * unbounded number of scans. Reaching the cap is treated as "no accepted match"
 * — the alternative, reporting a credential, would turn a large filler file
 * into a false-positive storm, and any content with 20k rejected filler runs is
 * not a credential store.
 */
const MAX_REJECTED_CANDIDATES = 20_000;

export function findCredentialFormatMatch(
  text: string,
): { value: string; index: number } | undefined {
  const re = buildCredentialFormatRegex('g');
  let m: RegExpExecArray | null;
  let rejected = 0;
  while ((m = re.exec(text)) !== null) {
    if (isAcceptedCredentialMatch(m[0])) {
      return { value: m[0], index: m.index };
    }
    if (++rejected > MAX_REJECTED_CANDIDATES) return undefined;
    re.lastIndex = m.index + 1;
  }
  return undefined;
}

/** True when `text` contains at least one accepted credential-format value. */
export function hasCredentialFormat(text: string): boolean {
  return findCredentialFormatMatch(text) !== undefined;
}

/**
 * True when `text` contains any credential-format CANDIDATE, entropy floor NOT
 * applied.
 *
 * This exists for the suppression vetoes (the taxonomy and corpus carve-outs),
 * which ask the opposite question from the detection gates. There the
 * predicate is negated — "suppress only if there is NO credential-shaped value
 * here" — so a stricter predicate makes suppression fire MORE often, and any
 * value the floor discards becomes a place to hide a secret. A taxonomy of
 * category labels has no legitimate reason to carry a 40-character run at all,
 * so the veto is intentionally trigger-happy: any candidate at all blocks the
 * carve-out, and vendor prefixes are matched UNANCHORED here for the same
 * reason (see `buildCandidateRegexForNegatedGate`).
 */
export function hasAnyCredentialCandidate(text: string): boolean {
  return buildCandidateRegexForNegatedGate().test(text);
}
