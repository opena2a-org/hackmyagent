/**
 * Shared credential-format detection.
 *
 * Two independent signals decide whether a substring "looks like a credential":
 *
 *   1. A curated vendor prefix (`sk-`, `sk_live_`, `ghp_`, `gho_`,
 *      `github_pat_`, `AKIA…`, `AIza…`, `xox[abprs]-`, `eyJ…` JWT). These are
 *      positively identified by their prefix, so they are accepted on shape
 *      alone and bypass the entropy floor below.
 *
 *   2. A high-entropy fallback: a 40+ word-character run, anchored on word
 *      boundaries, excluding `-` and `/` so URL slugs and slug-style
 *      identifiers do not match.
 *
 * Signal 2 previously accepted ANY 40+ character run, which is a length test
 * rather than an entropy test. Fill-in-the-blank form rules
 * (`Local Office: _______________________________________________`) are runs
 * of a single word character and so read as credentials. That produced a HIGH
 * "Hardcoded Secret Detected" on a public incident-response contact-sheet
 * template whose only "secret" was the heading "U.S. Secret Service (Cyber
 * Fraud)" sitting next to two form blanks.
 *
 * The fix is the entropy floor below: a fallback match must show at least
 * `MIN_DISTINCT_CHARS_IN_ENTROPY_BLOB` distinct characters. This narrows
 * nothing real. A random token drawn from even a 10-symbol alphabet has
 * probability ~2.6e-14 of showing fewer than 5 distinct characters across 40
 * positions; for hex (16 symbols) or base64 (64 symbols) it is smaller still.
 * What it does exclude is the degenerate case a credential can never occupy:
 * a run of one repeated character.
 *
 * Bare-keyword mentions ("credentials", "API key", "token") in descriptive
 * text do NOT count as either signal. Placeholder / env-var reference values
 * (`$OPENAI_API_KEY`, `${OPENAI_API_KEY}`, `<YOUR_KEY>`) fail the entropy
 * fallback because the leading `$`/`<` are not word characters and the
 * all-uppercase env-var convention rarely reaches 40 consecutive characters.
 */

/**
 * Vendor-prefixed credential shapes. Accepted on prefix alone: a real key
 * whose body happens to be low-diversity (`ghp_AAAA…`) is still a real key.
 */
const VENDOR_PREFIX_ALTERNATIVES = [
  'sk-[a-zA-Z0-9_-]{20,}',
  'sk_live_[a-zA-Z0-9]{20,}',
  'sk_test_[a-zA-Z0-9]{20,}',
  'ghp_[a-zA-Z0-9]{20,}',
  'gho_[a-zA-Z0-9]{20,}',
  'github_pat_[a-zA-Z0-9_]{20,}',
  'AKIA[0-9A-Z]{16}',
  'AIza[0-9A-Za-z_-]{35}',
  'xox[abprs]-[0-9A-Za-z-]{10,}',
  'eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+',
];

/** High-entropy fallback: 40+ word characters, word-boundary anchored. */
const ENTROPY_BLOB_ALTERNATIVE = '\\b[A-Za-z0-9+=_]{40,}\\b';

/**
 * Minimum distinct characters for a high-entropy fallback match to be
 * credible. See the module comment for the false-negative analysis.
 */
export const MIN_DISTINCT_CHARS_IN_ENTROPY_BLOB = 5;

/**
 * True when a fallback match shows enough character diversity to be a
 * credential rather than a form blank, padding run, or repeated-character
 * filler.
 */
export function isCredibleEntropyBlob(value: string): boolean {
  return new Set(value).size >= MIN_DISTINCT_CHARS_IN_ENTROPY_BLOB;
}

/**
 * Build the candidate matcher. Vendor alternatives are listed before the
 * entropy fallback so that at any given start offset a vendor-prefixed key
 * matches as a vendor key, not as an anonymous blob.
 *
 * This regex is the CANDIDATE gate only. Callers must run each candidate
 * through `isAcceptedCredentialMatch` (or use the helpers below), because the
 * entropy fallback still admits low-diversity runs by construction.
 */
export function buildCredentialFormatRegex(flags = ''): RegExp {
  return new RegExp(
    [...VENDOR_PREFIX_ALTERNATIVES, ENTROPY_BLOB_ALTERNATIVE].join('|'),
    flags,
  );
}

/** Vendor-prefix-only matcher, used to tell the two signals apart. */
function buildVendorPrefixOnlyRegex(): RegExp {
  return new RegExp(VENDOR_PREFIX_ALTERNATIVES.join('|'));
}

/**
 * True when a candidate substring should count as a credential: either it is
 * vendor-prefixed, or it clears the entropy floor.
 */
export function isAcceptedCredentialMatch(candidate: string): boolean {
  return (
    buildVendorPrefixOnlyRegex().test(candidate) ||
    isCredibleEntropyBlob(candidate)
  );
}

/**
 * Find the first ACCEPTED credential-format substring in `text`.
 *
 * Iterates every candidate rather than testing only the first: a document
 * whose first 40+ char run is a form blank must not mask a real credential
 * appearing later in the same file.
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
    // Defensive: a zero-length match would spin forever. None of the
    // alternatives can match empty, but the guard costs nothing.
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return undefined;
}

/** True when `text` contains at least one accepted credential-format value. */
export function hasCredentialFormat(text: string): boolean {
  return findCredentialFormatMatch(text) !== undefined;
}
