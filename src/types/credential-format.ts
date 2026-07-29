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
 * See `isCredibleEntropyBlob` for the rule that separates the two classes, and
 * `findCredibleWindowOffset` for why that rule is applied to a sliding WINDOW
 * rather than to the whole greedy run.
 *
 * Bare-keyword mentions ("credentials", "API key", "token") in descriptive text
 * do NOT count as either signal. Placeholder / env-var reference values
 * (`$OPENAI_API_KEY`, `${OPENAI_API_KEY}`, `<YOUR_KEY>`) fail the fallback
 * because the leading `$`/`<` are not word characters.
 *
 * ## Why there is no length bound and no work budget in this file
 *
 * Three consecutive adversarial passes killed three designs here, and all three
 * failed the same way: a bound added to stop a quadratic ALSO narrowed a gate
 * that lifts suppression, so a real credential went undetected and the score
 * ROSE. A bounded JWT header silenced a live token planted in a corpus path; a
 * character budget on the filler walk lost an anonymous secret behind 12 KB of
 * padding. Both were invisible to the whole test suite because neither
 * `test/hma` nor the adversarial corpus contains an oversized JWT, an anonymous
 * high-entropy secret, or a long padded run.
 *
 * So the performance defense here is LINEARITY, never truncation:
 *
 *   - the JWT is matched by a linear scan (`findJwtMatch`), not by a regex, so
 *     it needs no segment bound;
 *   - each blob run is judged exactly once by a sliding window, so the walk
 *     needs no resume and therefore no budget.
 *
 * If a future change to this file reaches for a cap, that is the signal to
 * check which negated or suppression-lifting gate the cap just narrowed.
 */

/* ------------------------------------------------------------------ *
 * Vendor prefixes
 * ------------------------------------------------------------------ */

/**
 * Every JWT begins with the base64url encoding of `{"`.
 *
 * Declared here rather than beside `findJwtMatch` because
 * `VENDOR_PREFIX_MATCHERS` below needs it at module-initialisation time, and a
 * `const` is not hoisted.
 */
const JWT_PREFIX = 'eyJ';

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
 * The JWT is deliberately NOT here — it is the one shape whose segments are
 * unbounded, and expressing it as a regex alternative is what made every
 * consumer either quadratic or truncating. `findJwtMatch` covers it for all of
 * them; `hasAnchoredVendorCredential`, `hasAnyCredentialCandidate` and
 * `findCredentialFormatMatch` each call both.
 *
 * Alternatives are NOT anchored here. See `anchoredVendorAlternation` for who
 * anchors and who deliberately does not.
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
  // SendGrid keys are `SG.<22-char key id>.<43-char secret>`, both segments at
  // FIXED lengths. Written as `SG\.<16,>\.<16,>` this matched any dotted
  // identifier with two long segments, so
  // `MSG.INCIDENT_ESCALATION_QUEUE.HIGH_PRIORITY_ROUTE` was positively
  // identified as a credential on a benign taxonomy document — the very
  // false-positive class this module exists to remove, re-created one gate
  // over. `origin/main` has no `SG.` at all and is clean on it.
  //
  // The fixed lengths are what separate a key from a namespace, and they do it
  // in the UNANCHORED veto too, which is where the anchor could not reach. A
  // real SendGrid secret is 43 characters, so it also clears the 40-character
  // blob fallback on its own; this alternative is what names it.
  'SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}',
];

/**
 * Left anchor for a vendor prefix: the prefix must not be glued to the tail of
 * an alphanumeric identifier.
 *
 * NOT `\b`. `\b` counts `_` as a word character, and the whole point of this
 * unit is that documents are full of underscore filler — `'_'x38 +
 * 'sk-ant-api03-<real key>'` has no word boundary before `sk`, so `\b` silently
 * dropped a real credential glued to a form blank. `origin/main` uses `\b` here
 * and has that bug; `(?<![A-Za-z0-9])` matches everywhere `\b` does and also
 * after filler, so it is strictly wider than main.
 */
const VENDOR_PREFIX_LEFT_ANCHOR = '(?<![A-Za-z0-9])';

/** The vendor alternation, unanchored. */
export function vendorAlternation(): string {
  return `(?:${VENDOR_PREFIX_ALTERNATIVES.join('|')})`;
}

/**
 * The vendor alternation with its left anchor.
 *
 * ANCHORING IS CHOSEN BY GATE POLARITY, NOT APPLIED UNIFORMLY, and the choice
 * has been wrong in both directions on this branch:
 *
 *   - In a NEGATED gate (`!predicate(content)`), narrowing the predicate makes
 *     the suppression carve-out fire MORE often, so every value the anchor
 *     rejects becomes a place to hide a secret. Those callers take
 *     `vendorAlternation()` and stay deliberately trigger-happy.
 *
 *   - In the primary DETECTION path, anchoring is a pure narrowing with no
 *     remaining benefit: it dropped `tokenghp_…`, `v1AKIA…` and
 *     `prefixsk-ant-…`, all of which `origin/main` detects, while the false
 *     positives it was added for (`MSG.…`) are removed by the SendGrid fixed
 *     lengths above. So detection uses `vendorAlternation()` and matches main.
 *
 * What is left is `hasAnchoredVendorCredential`, the one gate `origin/main`
 * anchors: a POSITIVE gate whose result BLOCKS suppression.
 */
export function anchoredVendorAlternation(): string {
  return `${VENDOR_PREFIX_LEFT_ANCHOR}${vendorAlternation()}`;
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
const VENDOR_PREFIX_MATCHERS: readonly RegExp[] = [
  ...VENDOR_PREFIX_ALTERNATIVES.map(alt => {
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
  }),
  // The JWT is detected by scan rather than by an alternative, so its prefix
  // has to be added here explicitly. Leaving it out would send every detected
  // JWT down the unknown-shape masking branch, which prints the first 8
  // characters — 5 bytes of live header past `eyJ`.
  new RegExp(`^${JWT_PREFIX}`),
];

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

/* ------------------------------------------------------------------ *
 * JWT: a linear scan, not a regex alternative
 * ------------------------------------------------------------------ */

const CHAR_DOT = 46;
const CHAR_e = 101;
const CHAR_y = 121;
const CHAR_J = 74;

/** `[A-Za-z0-9_-]`, the base64url alphabet a JWT segment is drawn from. */
function isBase64UrlCode(c: number): boolean {
  return (
    (c >= 48 && c <= 57) || // 0-9
    (c >= 65 && c <= 90) || // A-Z
    (c >= 97 && c <= 122) || // a-z
    c === 45 || // -
    c === 95 // _
  );
}

/** `[A-Za-z0-9]`, the class the vendor left anchor forbids. */
function isAlphanumericCode(c: number): boolean {
  return (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
}

/**
 * The leftmost `eyJ<header>.<payload>.<signature>` in `text`, with UNBOUNDED
 * segments — identical in what it accepts to `origin/main`'s
 * `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`, and linear rather than
 * quadratic in what it costs.
 *
 * Why this is not a regex. The segment class contains `-`, so on adversarial
 * filler (`eyJ-eyJ-eyJ-…`) the greedy run reaches end-of-file and the engine
 * then walks back looking for a `.` that is not there — at every one of the
 * O(n) `eyJ` offsets. Measured: 13.5 s at 256 KB, ~215 s extrapolated at the
 * 1 MB scanner cap.
 *
 * The previous fix bounded the header at 256 characters, and that bound leaked
 * into `VENDOR_PREFIX_CONTENT_RE` — the single gate that LIFTS the corpus and
 * integrity-manifest carve-outs. A DPoP proof (550-character header carrying an
 * embedded JWK) or an `x5c` certificate-chain header stopped matching, so a
 * live token planted in a corpus path was fully suppressed, `AST-CRED-002`
 * CRITICAL included. Truncation is not available to this predicate. Linearity
 * is.
 *
 * The scan walks maximal base64url runs. Everything after the header's
 * terminating `.` is a property of the RUN, not of the `eyJ` inside it, so the
 * payload and signature are resolved once per run rather than once per `eyJ` —
 * that is what removes the quadratic without removing any input.
 */
export function findJwtMatch(
  text: string,
  anchored: boolean,
): { value: string; index: number } | undefined {
  const n = text.length;
  let i = 0;
  while (i < n) {
    if (!isBase64UrlCode(text.charCodeAt(i))) {
      i++;
      continue;
    }
    // [i, runEnd) is a maximal base64url run — a candidate header segment.
    let runEnd = i;
    while (runEnd < n && isBase64UrlCode(text.charCodeAt(runEnd))) runEnd++;

    if (runEnd < n && text.charCodeAt(runEnd) === CHAR_DOT) {
      let payloadEnd = runEnd + 1;
      while (payloadEnd < n && isBase64UrlCode(text.charCodeAt(payloadEnd))) payloadEnd++;
      if (payloadEnd > runEnd + 1 && payloadEnd < n && text.charCodeAt(payloadEnd) === CHAR_DOT) {
        let signatureEnd = payloadEnd + 1;
        while (signatureEnd < n && isBase64UrlCode(text.charCodeAt(signatureEnd))) signatureEnd++;
        if (signatureEnd > payloadEnd + 1) {
          // Leftmost `eyJ` in this run that still leaves a non-empty header
          // segment. Each is checked against the anchor separately: `_` and `-`
          // are base64url characters but not alphanumeric, so an `eyJ` in the
          // middle of a run can clear an anchor that the run's first one fails.
          for (let p = i; p + JWT_PREFIX.length < runEnd; p++) {
            if (
              text.charCodeAt(p) !== CHAR_e ||
              text.charCodeAt(p + 1) !== CHAR_y ||
              text.charCodeAt(p + 2) !== CHAR_J
            ) {
              continue;
            }
            if (anchored && p > 0 && isAlphanumericCode(text.charCodeAt(p - 1))) continue;
            return { value: text.slice(p, signatureEnd), index: p };
          }
        }
      }
    }
    i = runEnd;
  }
  return undefined;
}

/* ------------------------------------------------------------------ *
 * The high-entropy fallback
 * ------------------------------------------------------------------ */

/** High-entropy fallback: 40+ word characters, word-boundary anchored. */
const ENTROPY_BLOB_ALTERNATIVE = '\\b[A-Za-z0-9+=_]{40,}\\b';

/**
 * Width of the window the filler rules judge. Also the fallback's own length
 * floor, so a window is exactly the smallest run that could be a credential.
 */
const CREDENTIAL_WINDOW_CHARS = 40;

/**
 * The sliding walk's own counters, separate from `SPAN_CHAR_COUNTS` above and
 * hoisted so a file of many blob runs does not allocate per run.
 *
 * `WINDOW_COUNT_BUCKETS[c]` is how many distinct characters occur exactly `c`
 * times in the current window; it is what makes the running maximum O(1) to
 * maintain, since a maximum can only fall when the last character holding it
 * leaves. Both are reset at the top of every walk, so no state survives a call.
 */
const WINDOW_CHAR_COUNTS = new Uint32Array(128);
const WINDOW_COUNT_BUCKETS = new Uint32Array(CREDENTIAL_WINDOW_CHARS + 2);

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
 * Share of the span a single character may occupy before the span is filler.
 *
 * A form blank with one stray mark (`'_'x46 + '1'`) is aperiodic, so the period
 * rule alone does not reach it. At 40 characters a genuine secret cannot be 90%
 * one symbol: even a base-4 secret sits near 25% per symbol, and the
 * probability of a random 40-character draw reaching 90% is negligible.
 */
const MAX_DOMINANT_CHAR_SHARE = 0.9;

/**
 * True when `[start, start+len)` is some unit of at most `MAX_FILLER_PERIOD`
 * characters repeated at least `MIN_FILLER_REPEATS` times.
 *
 * Tests each period directly instead of computing the minimal period, which is
 * the same predicate (a span with minimal period m <= 4 and length >= 3m is
 * exactly a span with SOME period p <= 4 and length >= 3p) without the
 * per-window array allocation that made a sliding judgement unaffordable.
 */
function hasFillerPeriod(s: string, start: number, len: number): boolean {
  for (let p = 1; p <= MAX_FILLER_PERIOD; p++) {
    if (len < p * MIN_FILLER_REPEATS) break;
    let periodic = true;
    for (let i = p; i < len; i++) {
      if (s.charCodeAt(start + i) !== s.charCodeAt(start + i - p)) {
        periodic = false;
        break;
      }
    }
    if (periodic) return true;
  }
  return false;
}

/**
 * Reused across calls; the blob class is ASCII, so 128 slots always suffice.
 *
 * DELIBERATELY NOT SHARED with the sliding walk's counter below. This one is
 * filled from scratch on every call, and the walk maintains its own
 * incrementally ACROSS iterations while calling into this function — so a
 * single shared buffer would have the callee zero and rebuild the caller's live
 * state mid-walk. That happens to be harmless today, because the two always
 * count the same span, but it is a trap set for the next edit: the moment the
 * spans differ the walk silently corrupts and starts skipping windows, which is
 * a detection loss with no visible symptom. Two buffers, no coupling.
 */
const SPAN_CHAR_COUNTS = new Uint32Array(128);

/** True when one character occupies more than 90% of `[start, start+len)`. */
function isDominatedBySingleChar(s: string, start: number, len: number): boolean {
  SPAN_CHAR_COUNTS.fill(0);
  let max = 0;
  for (let i = 0; i < len; i++) {
    const next = ++SPAN_CHAR_COUNTS[s.charCodeAt(start + i)];
    if (next > max) max = next;
  }
  return max > len * MAX_DOMINANT_CHAR_SHARE;
}

/**
 * True when `[start, start+len)` could carry entropy at all.
 *
 * Two rules, both aimed at the same class: text used as visual filler.
 *
 *   1. The span is a short unit repeated at least three times
 *      (`'_'x47`, `'_='x25`, `'01'x20`, `'de'x24`, `'a1'x24`).
 *   2. One character occupies more than 90% of the span (`'_'x46 + '1'`).
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
function isCredibleSpan(s: string, start: number, len: number): boolean {
  if (len === 0) return false;
  if (hasFillerPeriod(s, start, len)) return false;
  return !isDominatedBySingleChar(s, start, len);
}

/** `isCredibleSpan` over a whole value. */
export function isCredibleEntropyBlob(value: string): boolean {
  return isCredibleSpan(value, 0, value.length);
}

/**
 * Offset of the leftmost 40-character window of `run` that could carry entropy,
 * or undefined when no window can.
 *
 * WHY A WINDOW AND NOT THE WHOLE RUN. The fallback is greedy over a class
 * containing `_`, so filler glued to a secret is absorbed into one candidate:
 * `'_'x361 + <40-char secret>` is a single 401-character run in which the
 * underscores are 90.02% of the total, just over the dominance threshold. The
 * run was rejected whole, and the secret with it. `'_'x300` happened to sit
 * under the threshold, which is the only reason the defect looked fixed — and
 * the one test covering the shape used `'_'x400 + '=' + secret`, tuned to the
 * single variant that survived, because `=` is a non-word character and so gave
 * the walk an interior `\b` to restart from. Delete the `=` and it failed.
 *
 * Judging a window instead removes the whole family: a secret is credible in
 * its own right no matter how much filler is glued to it, and no interior word
 * boundary is needed to find it. It also removes the two mechanisms that were
 * added to compensate — the "resume one character past a rejected candidate"
 * walk and the character budget that had to bound it — because each run is now
 * examined exactly once. That budget was itself a CRITICAL detection hole: 12 KB
 * of `('a'x40 + '=')` padding ahead of an anonymous secret exhausted it and the
 * score went UP.
 *
 * Cost is O(40n) worst case and linear in practice: the whole-run periodicity
 * check below disposes of uniform filler in one pass, and the dominance rule is
 * maintained incrementally, so the expensive full predicate runs only on
 * windows that are not already dominated.
 */
function findCredibleWindowOffset(run: string): number | undefined {
  const w = CREDENTIAL_WINDOW_CHARS;
  const n = run.length;
  if (n < w) return isCredibleSpan(run, 0, n) ? 0 : undefined;

  // If the run itself is a repeated short unit then so is every window of it —
  // period is inherited by substrings — so a megabyte of `'_'` or `'ab'` filler
  // costs one linear pass instead of n window judgements.
  if (hasFillerPeriod(run, 0, n)) return undefined;

  // Sliding dominance count. `bucket[c]` is how many distinct characters occur
  // exactly c times in the window, which keeps the running max O(1) per step:
  // a max can only fall when the last character holding it leaves.
  WINDOW_CHAR_COUNTS.fill(0);
  WINDOW_COUNT_BUCKETS.fill(0);
  let max = 0;
  for (let i = 0; i < w; i++) {
    const code = run.charCodeAt(i);
    const before = WINDOW_CHAR_COUNTS[code]++;
    if (before > 0) WINDOW_COUNT_BUCKETS[before]--;
    WINDOW_COUNT_BUCKETS[before + 1]++;
    if (before + 1 > max) max = before + 1;
  }

  const dominanceLimit = w * MAX_DOMINANT_CHAR_SHARE;
  for (let k = 0; ; k++) {
    // The incremental counter is an ACCELERATOR for `isCredibleSpan`, never a
    // second opinion: `max <= dominanceLimit` is exactly the negation of the
    // dominance rule, so skipping on it can only skip windows the full
    // predicate would reject anyway. `credential-format.test.ts` cross-checks
    // the two over randomised runs.
    if (max <= dominanceLimit && isCredibleSpan(run, k, w)) return k;
    if (k + w >= n) return undefined;

    const leaving = run.charCodeAt(k);
    const had = WINDOW_CHAR_COUNTS[leaving]--;
    WINDOW_COUNT_BUCKETS[had]--;
    WINDOW_COUNT_BUCKETS[had - 1]++;
    if (had === max && WINDOW_COUNT_BUCKETS[had] === 0) max = had - 1;

    const entering = run.charCodeAt(k + w);
    const has = WINDOW_CHAR_COUNTS[entering]++;
    if (has > 0) WINDOW_COUNT_BUCKETS[has]--;
    WINDOW_COUNT_BUCKETS[has + 1]++;
    if (has + 1 > max) max = has + 1;
  }
}

/* ------------------------------------------------------------------ *
 * Entry points
 * ------------------------------------------------------------------ */

/** Leftmost wins; on a tie the vendor match wins, as in `origin/main`. */
function leftmost(
  a: { value: string; index: number } | undefined,
  b: { value: string; index: number } | undefined,
): { value: string; index: number } | undefined {
  if (!a) return b;
  if (!b) return a;
  return b.index < a.index ? b : a;
}

/**
 * Find the first credential-format substring in `text`.
 *
 * Vendor prefixes and the JWT are matched over the whole input, unanchored and
 * unbounded, exactly as `origin/main` matches them. The high-entropy fallback
 * then walks maximal blob runs, judging each by sliding window.
 *
 * The reported value starts at the leftmost credible WINDOW and runs to the end
 * of its blob run. Starting at the run start would report the filler that
 * swallowed the secret; stopping at the window's own 40th character would cut a
 * longer secret in half. The index is the window's, so the derived line number
 * points at the secret rather than at the form blank preceding it.
 */
export function findCredentialFormatMatch(
  text: string,
): { value: string; index: number } | undefined {
  const vendorRe = new RegExp(vendorAlternation(), 'g');
  const vm = vendorRe.exec(text);
  let best = leftmost(
    vm ? { value: vm[0], index: vm.index } : undefined,
    findJwtMatch(text, false),
  );

  const blobRe = new RegExp(ENTROPY_BLOB_ALTERNATIVE, 'g');
  let m: RegExpExecArray | null;
  while ((m = blobRe.exec(text)) !== null) {
    // Runs are disjoint and left to right, so nothing from here on can be
    // leftmost.
    if (best && m.index >= best.index) break;
    const offset = findCredibleWindowOffset(m[0]);
    if (offset !== undefined) {
      const index = m.index + offset;
      if (!best || index < best.index) best = { value: m[0].slice(offset), index };
      break;
    }
  }
  return best;
}

/** True when `text` contains at least one accepted credential-format value. */
export function hasCredentialFormat(text: string): boolean {
  return findCredentialFormatMatch(text) !== undefined;
}

/**
 * The candidate matcher for NEGATED gates: same alternation, vendor prefixes
 * left UNANCHORED on purpose, entropy floor NOT applied.
 */
const CANDIDATE_RE_FOR_NEGATED_GATE = new RegExp(
  `${vendorAlternation()}|${ENTROPY_BLOB_ALTERNATIVE}`,
);

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
 * reason.
 *
 * Being trigger-happy is not licence to be wrong about the SHAPE. `SG\.` with
 * open-ended segments made this predicate fire on
 * `MSG.INCIDENT_ESCALATION_QUEUE.HIGH_PRIORITY_ROUTE`, which blocked the
 * taxonomy carve-out and raised a CRITICAL on a benign document — a false
 * positive the anchor could not reach precisely because this gate must stay
 * unanchored. The fix belongs in the pattern, not the anchoring.
 */
export function hasAnyCredentialCandidate(text: string): boolean {
  return CANDIDATE_RE_FOR_NEGATED_GATE.test(text) || findJwtMatch(text, false) !== undefined;
}

/** Module-level and deliberately without `g`, so `.test()` carries no state. */
const ANCHORED_VENDOR_RE = new RegExp(anchoredVendorAlternation());

/**
 * True when `text` carries a positively-identified vendor credential.
 *
 * This is the gate that LIFTS the corpus and integrity-manifest suppression, so
 * every narrowing of it suppresses MORE — the same trap as a negated gate, one
 * gate over, and the one a bounded JWT header fell into. It must see exactly
 * what `origin/main` sees, at minimum.
 */
export function hasAnchoredVendorCredential(text: string): boolean {
  return ANCHORED_VENDOR_RE.test(text) || findJwtMatch(text, true) !== undefined;
}

/* ------------------------------------------------------------------ *
 * Form blanks in KEY-NAMED config values
 * ------------------------------------------------------------------ */

/**
 * Characters a document uses to DRAW rather than to encode: form blanks, dot
 * leaders, rules, redaction bars.
 */
const FILLER_CHARS = new Set(['_', '-', '.', '*', '#', '~', '?', '=', ' ', '\t']);

/**
 * Length at which a consecutive filler run stops being punctuation and becomes
 * something someone DREW.
 *
 * This is the distinction the whole rule turns on, and dropping it is what
 * broke `dev_pass`. Filler characters appear inside real secrets constantly,
 * but as SEPARATORS, one at a time — `dev_pass`, `pass-123`, `api.key1`,
 * `super-secret-jwt-key-2024`, a UUID, `sk-ant-api03-…`. Nobody writes four in
 * a row unless they are drawing a line. So a run this long is subtracted from
 * the value and anything shorter is part of it.
 */
const MIN_DRAWN_RUN_CHARS = 4;

/**
 * Characters a value must carry, once the drawn runs are removed, to be a value.
 *
 * Matches the 8-character floor `looksLikeSecretValue` already applies to the
 * value as a whole, so a secret is judged by the same minimum whether or not
 * someone drew a line next to it.
 */
const MIN_SECRET_CORE_CHARS = 8;

/**
 * True when `value` is visual filler rather than a secret, for values that
 * arrive WITH a key name (`password:`, `api_key =`).
 *
 * Deliberately a different test from `isCredibleEntropyBlob`, because the
 * evidence is different. The entropy blob is an anonymous 40+ character run
 * found anywhere in a document, so structure is all there is to go on and a run
 * of one repeated symbol is filler. Here a key name has already said "this is a
 * secret", so the only question left is whether the VALUE is a drawn blank —
 * and the structural rules are far too blunt for that at 8 characters. They
 * dropped `Ab12Ab12Ab12…` (period 4) and the base64 of an all-zero AES key
 * (`'A'x43`), both of which are weak but entirely real secrets that a scanner
 * exists to find.
 *
 * Keying on the filler CHARACTERS instead separates the classes exactly: `_`,
 * `-` and `.` draw blanks and never carry key material in bulk, while `A` and
 * `1` do.
 *
 * `minCore` is how much value must survive the drawn runs. It defaults to the
 * caller's own 8-character floor, but a caller that applies NO length floor of
 * its own must pass a smaller one — otherwise this function silently becomes a
 * length gate for it. SEM-CRED-004 hit exactly that: routed through the
 * 8-character default it stopped reporting `supersecretpassword` and
 * `hunt3r`, real MCP env secrets that `origin/main` reported, and the score
 * rose. A gate added to suppress drawn blanks must suppress drawn blanks and
 * nothing else.
 */
export function isVisualFiller(value: string, minCore = MIN_SECRET_CORE_CHARS): boolean {
  if (value.length === 0) return true;
  // A redaction bar. `x` is not a filler character in general — it appears in
  // real base64 — but a value that is nothing else is a mask, not a key.
  if (/^x+$/i.test(value)) return true;
  // Subtract what was DRAWN — the long runs — and apply the same 8-character
  // floor the caller applies to the whole value. Separators survive, because
  // they are part of the value.
  //
  // THREE rules were tried here before this one, each failing in its own
  // direction. They are recorded because the shape of the mistake repeated:
  //
  //   - The filler SHARE of the whole value. The same whole-value judgement
  //     `findCredibleWindowOffset` exists to avoid, and it failed at the
  //     identical threshold: `'_'x361 + <40-char secret>` is 90.02%
  //     underscores, so it was called a blank and the secret dropped, while
  //     `'_'x360 + secret` was reported. A dashed trailing comment did it too,
  //     since the YAML/env value is the rest of the line. Any rule whose
  //     verdict moves with how MUCH filler is present has this bug.
  //   - The longest contiguous non-filler STRETCH. Reads every separator as a
  //     boundary, so `super-secret-jwt-key-2024` — longest stretch `secret`,
  //     six characters — stopped being a secret.
  //   - Counting non-filler characters with no notion of a run. Strictly
  //     stricter than the caller's length floor rather than equal to it, so
  //     every 8-character password carrying ONE separator went silent:
  //     `dev_pass`, `prod_key`, `pass-123`, `api.key1`, `pw#12345`. The score
  //     rose 27 points on a lost CRITICAL.
  //
  // The RUN length is what separates a drawn blank from punctuation, so it is
  // the thing to measure. Pinned in both directions: `dev_pass` (8 characters,
  // one separator, a secret) and `'_'x47` (a blank).
  let core = 0;
  let run = 0;
  for (const ch of value) {
    if (FILLER_CHARS.has(ch)) {
      run++;
      continue;
    }
    if (run > 0 && run < MIN_DRAWN_RUN_CHARS) core += run; // punctuation, kept
    run = 0;
    if (++core >= minCore) return false;
  }
  return true
}
