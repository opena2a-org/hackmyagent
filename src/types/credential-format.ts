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
 * The correction is deliberately the SMALLEST rule that separates the two
 * classes: a fallback match must not be a run of one repeated character.
 * Every false positive observed in the field has exactly ONE distinct
 * character; a credential can never occupy that case, because a repeated
 * single character carries zero entropy.
 *
 * A larger diversity floor was tried first and rejected. It is not an entropy
 * test: a string restricted to four distinct symbols still carries two bits per
 * character, so a 64-character base-4 blob holds 128 bits and would have been
 * discarded. Adversarial review demonstrated that a floor of 5 silenced a
 * planted `AST-CRED-002` CRITICAL whose only unusual property was a four-letter
 * alphabet, and also dropped real `hf_`, `ghs_`, and `npm_` tokens whose bodies
 * repeat. Detection headroom for an attacker-chosen value is not worth trading
 * for false positives nobody has observed.
 *
 * Bare-keyword mentions ("credentials", "API key", "token") in descriptive text
 * do NOT count as either signal. Placeholder / env-var reference values
 * (`$OPENAI_API_KEY`, `${OPENAI_API_KEY}`, `<YOUR_KEY>`) fail the fallback
 * because the leading `$`/`<` are not word characters.
 */

/**
 * Vendor-prefixed credential shapes, in one place.
 *
 * This is the single source of truth. `hasVendorPrefixCredential` in the
 * credential analyzer builds its own word-boundary-anchored matcher from this
 * same array; keeping two hand-maintained lists meant a token could be
 * "vendor-known" to one gate and anonymous to another, which is how `hf_`,
 * `ghs_`, `ghu_`, `glpat-` and `npm_` ended up subject to the entropy fallback
 * in one code path and exempt in the next.
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
  'SG\\.[a-zA-Z0-9_-]{16,}',
  'eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+',
];

/** High-entropy fallback: 40+ word characters, word-boundary anchored. */
const ENTROPY_BLOB_ALTERNATIVE = '\\b[A-Za-z0-9+=_]{40,}\\b';

/**
 * Minimum distinct characters for a high-entropy fallback match to be
 * credible. Two, i.e. reject only a run of one repeated character. See the
 * module comment for why this is not set higher.
 */
export const MIN_DISTINCT_CHARS_IN_ENTROPY_BLOB = 2;

/**
 * True when a fallback match is not a single repeated character, and so could
 * carry entropy at all.
 */
export function isCredibleEntropyBlob(value: string): boolean {
  return new Set(value).size >= MIN_DISTINCT_CHARS_IN_ENTROPY_BLOB;
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
    [...VENDOR_PREFIX_ALTERNATIVES, ENTROPY_BLOB_ALTERNATIVE].join('|'),
    flags,
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
const VENDOR_PREFIX_ONLY_RE = new RegExp(VENDOR_PREFIX_ALTERNATIVES.join('|'));

/**
 * True when a candidate substring should count as a credential: either it is
 * vendor-prefixed, or it is not a single repeated character.
 */
export function isAcceptedCredentialMatch(candidate: string): boolean {
  return VENDOR_PREFIX_ONLY_RE.test(candidate) || isCredibleEntropyBlob(candidate);
}

/**
 * Find the first ACCEPTED credential-format substring in `text`.
 *
 * On rejecting a candidate the scan resumes one character past where that
 * candidate STARTED, not past where it ended. The entropy fallback is greedy
 * over a class that includes `_`, so filler glued directly to a credential
 * (`____…____sk-ant-…`) is swallowed into one candidate run; resuming past the
 * whole run would skip the credential's own prefix and lose it entirely.
 */
export function findCredentialFormatMatch(
  text: string,
): { value: string; index: number } | undefined {
  const re = buildCredentialFormatRegex('g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (isAcceptedCredentialMatch(m[0])) {
      return { value: m[0], index: m.index };
    }
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
 * carve-out.
 */
export function hasAnyCredentialCandidate(text: string): boolean {
  return buildCredentialFormatRegex().test(text);
}
