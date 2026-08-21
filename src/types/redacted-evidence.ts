/**
 * Reading a finding's evidence text when part of it has been redacted.
 *
 * A finding cites `file:line`, and the citation is only trustworthy if the
 * evidence it carries actually appears at that position. That check is what
 * catches "wrong line" regressions, and it is a substring comparison — which
 * stops working the moment a redactor replaces credential bytes inside the
 * evidence with a marker, because the marker is not in the file.
 *
 * The pre-publish corpus gate already had a carve-out for this, and the
 * carve-out was keyed on ONE literal spelling, `[REDACTED]`. Measured: `src`
 * emits four families of marker —
 *
 *   - typed, uppercase: `[REDACTED_GITHUB_TOKEN]`, `[REDACTED_AWS_SECRET]`, …
 *     (the shape registry's `CREDENTIAL_REDACTION_MARKERS`, plus
 *     `[REDACTED_META_INSTRUCTION]` from the prompt redactor)
 *   - bare: `[REDACTED]` (`semantic/structural/credential-context.ts:456`,
 *     `nanomind-core/security/defense-in-depth.ts:270-274`)
 *   - lowercase: `[redacted]` and `[redacted-jwt]`
 *     (`scanner/permission-vocabulary.ts:415-421`)
 *
 * — and the literal check recognised exactly one of them:
 * `'[REDACTED_GITHUB_TOKEN]'.includes('[REDACTED]')` is `false`. So every
 * redactor except the bare one would have turned the gate red on a finding
 * that was citing its line correctly.
 *
 * The answer is a rule per spelling, expressed as a SHAPE rather than a list,
 * so that adding a marker to the registry does not require editing a second
 * table here. `credential-shape-registry.test.ts` asserts every registry marker
 * is recognised by this pattern, which is the link that keeps the two honest.
 *
 * What this module deliberately does NOT do is decide whether a marker is a
 * REGISTERED one. An unregistered marker is a registry defect and the registry
 * has its own totality check for it; giving the citation gate a second job
 * would couple two failures that need separate messages.
 */

/**
 * Every marker spelling, as a pattern.
 *
 * Returns a fresh RegExp: a shared `g`-flagged instance carries `lastIndex`
 * between callers, so the second call over the same text starts in the middle
 * of it.
 */
export function redactionMarkerPattern(): RegExp {
  return /\[REDACTED(?:_[A-Z]+)*\]|\[redacted(?:-[a-z]+)*\]/g;
}

/** True when `text` is a redaction marker and nothing else. */
export function isRedactionMarker(text: string): boolean {
  return new RegExp(`^(?:${redactionMarkerPattern().source})$`).test(text.trim());
}

/** The literal fragments of `text` either side of every marker in it. */
export function splitOnRedactionMarkers(text: string): string[] {
  return text.split(redactionMarkerPattern());
}

/** True when `text` carries at least one redaction marker. */
export function containsRedactionMarker(text: string): boolean {
  return redactionMarkerPattern().test(text);
}

export type EvidenceCitationProblem =
  /** The evidence is nothing but markers — there is no context left to verify. */
  | { readonly kind: 'pure-marker' }
  /** A literal fragment around a marker is not on the cited line. */
  | { readonly kind: 'missing-segment'; readonly missing: string }
  /** Un-redacted evidence that is simply not on the cited line. */
  | { readonly kind: 'evidence-absent' };

/**
 * Why `evidence` fails to corroborate `lineContent`, or `undefined` if it does.
 *
 * Redaction relaxes the comparison, it does not remove it: EVERY non-empty
 * fragment either side of a marker must still appear on the cited line. A
 * finding whose evidence reduces to a bare marker is a defect at the emit site
 * — it has redacted the context along with the secret and left nothing that
 * could ever be checked — so that is reported rather than waved through.
 */
export function evidenceCitationProblem(
  evidence: string,
  lineContent: string,
): EvidenceCitationProblem | undefined {
  const ev = evidence.trim();
  if (ev === '') return undefined;

  if (!containsRedactionMarker(ev)) {
    return lineContent.includes(ev) ? undefined : { kind: 'evidence-absent' };
  }

  const nonEmpty = splitOnRedactionMarkers(ev).filter(s => s !== '');
  if (nonEmpty.length === 0) return { kind: 'pure-marker' };

  const missing = nonEmpty.find(s => !lineContent.includes(s));
  return missing === undefined ? undefined : { kind: 'missing-segment', missing };
}
