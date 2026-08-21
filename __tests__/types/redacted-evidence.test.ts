/**
 * The citation gate's redaction rule.
 *
 * The pre-publish corpus harness asserts a finding's evidence appears on the
 * line it cites. Redaction breaks a plain substring test, so the comparison is
 * relaxed to the fragments either side of each marker — and the bug this file
 * pins is that the relaxation used to be keyed on ONE literal spelling,
 * `[REDACTED]`, while the tree emits four families.
 *
 * Every expectation here is a hand-written literal. Nothing derives an
 * expectation from the implementation.
 */
import { describe, it, expect } from 'vitest';
import {
  containsRedactionMarker,
  evidenceCitationProblem,
  isRedactionMarker,
  redactionMarkerPattern,
  splitOnRedactionMarkers,
} from '../../src/types/redacted-evidence';
import { CREDENTIAL_REDACTION_MARKERS } from '../../src/types/credential-format';

const LINE = 'DATABASE_URL=postgres://admin:hunter2xyzzy@db.internal:5432/app';

describe('redaction marker recognition — one rule per spelling', () => {
  it('recognises every spelling the tree emits', () => {
    for (const marker of [
      '[REDACTED]',
      '[REDACTED_GITHUB_TOKEN]',
      '[REDACTED_AWS_SECRET]',
      '[REDACTED_CONNECTION_STRING]',
      '[REDACTED_META_INSTRUCTION]',
      '[redacted]',
      '[redacted-jwt]',
    ]) {
      expect(isRedactionMarker(marker), marker).toBe(true);
    }
  });

  it('does not treat any bracketed token as a marker', () => {
    // The negative control. Without it, a pattern of `\[.*\]` would pass every
    // assertion above while waving through arbitrary evidence.
    for (const notAMarker of [
      '[REDACT]',
      '[REDACTED_lowercase]',
      '[Redacted]',
      '[redacted_underscore]',
      '[]',
      'REDACTED',
      '[REDACTED_GITHUB_TOKEN',
    ]) {
      expect(isRedactionMarker(notAMarker), notAMarker).toBe(false);
    }
  });

  it('every registry marker is recognised by the citation gate', () => {
    // The link that keeps the two vocabularies honest: a marker added to the
    // registry works with the gate on the same edit, or this reds.
    for (const [id, marker] of Object.entries(CREDENTIAL_REDACTION_MARKERS)) {
      expect(isRedactionMarker(marker), `${id} -> ${marker}`).toBe(true);
    }
  });

  it('returns a fresh pattern each call, so a g-flag lastIndex cannot leak', () => {
    expect(redactionMarkerPattern()).not.toBe(redactionMarkerPattern());
    // Called twice on the same input, the answer must not change. A shared
    // g-flagged instance would return true then false.
    const text = 'token=[REDACTED_GITHUB_TOKEN]';
    expect(containsRedactionMarker(text)).toBe(true);
    expect(containsRedactionMarker(text)).toBe(true);
  });

  it('splits on every marker family', () => {
    expect(splitOnRedactionMarkers('a=[REDACTED_AWS_KEY] b=[redacted] c')).toEqual([
      'a=',
      ' b=',
      ' c',
    ]);
  });
});

describe('evidence citation — un-redacted', () => {
  it('accepts evidence that is on the cited line', () => {
    expect(evidenceCitationProblem('postgres://admin', LINE)).toBeUndefined();
  });

  it('rejects evidence that is not on the cited line', () => {
    expect(evidenceCitationProblem('mysql://admin', LINE)).toEqual({ kind: 'evidence-absent' });
  });

  it('ignores empty evidence rather than failing on it', () => {
    expect(evidenceCitationProblem('   ', LINE)).toBeUndefined();
  });
});

describe('evidence citation — redacted', () => {
  it('accepts a BARE marker with surrounding context — the case that already worked', () => {
    expect(
      evidenceCitationProblem('DATABASE_URL=postgres://admin:[REDACTED]@db.internal:5432/app', LINE),
    ).toBeUndefined();
  });

  it('accepts a TYPED marker with surrounding context — the case that used to fail', () => {
    // This is the regression. Pre-fix, the gate tested
    // `ev.includes('[REDACTED]')`, which is false for a typed marker, so this
    // fell through to the strict substring branch and compared a redacted
    // string against the raw file line: a FAIL on a finding citing its line
    // correctly, on the gate that must be green before any publish.
    expect(
      evidenceCitationProblem(
        'DATABASE_URL=postgres://admin:[REDACTED_CONNECTION_STRING]@db.internal:5432/app',
        LINE,
      ),
    ).toBeUndefined();
  });

  it('accepts the LOWERCASE markers — the other family that used to fail', () => {
    expect(
      evidenceCitationProblem('DATABASE_URL=postgres://admin:[redacted]@db.internal:5432/app', LINE),
    ).toBeUndefined();
    expect(
      evidenceCitationProblem('DATABASE_URL=postgres://admin:[redacted-jwt]@db.internal', LINE),
    ).toBeUndefined();
  });

  it('still rejects evidence that is nothing but a marker, in every family', () => {
    for (const marker of ['[REDACTED]', '[REDACTED_GITHUB_TOKEN]', '[redacted]']) {
      expect(evidenceCitationProblem(marker, LINE), marker).toEqual({ kind: 'pure-marker' });
    }
  });

  it('still rejects a fragment that is not on the cited line', () => {
    expect(
      evidenceCitationProblem('MYSQL_URL=mysql://admin:[REDACTED_AWS_KEY]@db.internal', LINE),
    ).toEqual({ kind: 'missing-segment', missing: 'MYSQL_URL=mysql://admin:' });
  });

  it('checks EVERY fragment, not just the first', () => {
    // The multi-redaction defence. The first fragment is on the line and the
    // second is not; a first-segment-only check passes this.
    expect(
      evidenceCitationProblem(
        'DATABASE_URL=[REDACTED_GITHUB_TOKEN]@nowhere.invalid:[REDACTED]/app',
        LINE,
      ),
    ).toEqual({ kind: 'missing-segment', missing: '@nowhere.invalid:' });
  });

  it('accepts a marker at the very end with context before it', () => {
    expect(evidenceCitationProblem('DATABASE_URL=[REDACTED_SECRET]', LINE)).toBeUndefined();
  });
});
