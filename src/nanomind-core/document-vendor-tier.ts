/**
 * The vendor tier for documentation files (#1027).
 *
 * README, CHANGELOG, LICENSE, CONTRIBUTING, HISTORY and AUTHORS documents
 * (`isDocumentBasename`) used to reach no analyzer at all. They now take the
 * non-agent route, but the credential analyzer's entropy path can read
 * ordinary document text as credential format, such as a git commit ID inside
 * a commit link in a CHANGELOG. That false-positive class lives in the analyzer
 * and is to be fixed there, separately. Until then these six names get the
 * narrower tier below.
 *
 * The tier: a document keeps its `AST-CRED-*` findings only when its raw bytes
 * carry at least one anchored vendor credential (`anchoredVendorAlternation`)
 * whose body is not a placeholder. Otherwise every `AST-CRED-*` finding on the
 * file is dropped. Findings from the other families are untouched.
 *
 * KNOWN GAP, disclosed: a prefix-free secret (a bare 40-character hex value
 * after `API_SECRET=`) in one of these six documents is not reported, while the
 * same value in `notes.md` is.
 *
 * The gate applies to these documents only and lives here, not in the
 * credential analyzer, whose placeholder handling for every other file is
 * unchanged.
 */

import type { ASTFinding } from './analyzers/capability-analyzer.js';
import { anchoredVendorAlternation, matchVendorPrefix } from '../types/credential-format.js';

/**
 * The fixture words, matched case-insensitively on the body after the vendor
 * prefix. The same nine words the credential analyzer's own fixture test uses.
 * The prefix is removed first because the prefix of a real Stripe test key
 * carries the word TEST: matched with its prefix, every such key would read
 * as a placeholder.
 */
const PLACEHOLDER_WORDS: readonly string[] = [
  'FAKE',
  'EXAMPLE',
  'PLACEHOLDER',
  'TEST',
  'DUMMY',
  'SAMPLE',
  'XXX',
  'YOUR_',
  '<YOUR',
];

/** The run a placeholder spells by writing the alphabet and the digits in order. */
const ORDERED_RUN = 'abcdefghijklmnopqrstuvwxyz0123456789';

/** How much of `ORDERED_RUN` a body must contain to count as typed in order. */
const ORDERED_RUN_MIN = 16;

/**
 * Is this credential body (the value with its vendor prefix removed) a
 * placeholder? True when it contains a fixture word, is one character
 * repeated, or contains a 16-character run of `ORDERED_RUN`, case-insensitive.
 */
export function isPlaceholderCredentialBody(body: string): boolean {
  if (body.length === 0) return true;
  const upper = body.toUpperCase();
  if (PLACEHOLDER_WORDS.some((word) => upper.includes(word))) return true;
  const lower = body.toLowerCase();
  if ([...lower].every((ch) => ch === lower[0])) return true;
  for (let start = 0; start + ORDERED_RUN_MIN <= ORDERED_RUN.length; start++) {
    if (lower.includes(ORDERED_RUN.slice(start, start + ORDERED_RUN_MIN))) return true;
  }
  return false;
}

/**
 * Does `content` carry an anchored vendor credential whose body is not a
 * placeholder? Every match is tested, so a placeholder earlier in the file
 * does not hide a real token later in it.
 */
export function hasNonPlaceholderVendorCredential(content: string): boolean {
  const vendor = new RegExp(anchoredVendorAlternation(), 'g');
  for (const match of content.matchAll(vendor)) {
    const value = match[0];
    const prefix = matchVendorPrefix(value) ?? '';
    if (!isPlaceholderCredentialBody(value.slice(prefix.length))) return true;
  }
  return false;
}

/**
 * Apply the vendor tier to one document's findings: keep them all when the
 * document carries a non-placeholder vendor credential, otherwise drop its
 * `AST-CRED-*` findings and keep the rest.
 */
export function applyDocumentVendorTier(findings: ASTFinding[], content: string): ASTFinding[] {
  if (!findings.some((f) => f.checkId.startsWith('AST-CRED-'))) return findings;
  if (hasNonPlaceholderVendorCredential(content)) return findings;
  return findings.filter((f) => !f.checkId.startsWith('AST-CRED-'));
}
