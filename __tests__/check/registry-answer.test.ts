// What `check --no-scan` makes of a Registry answer (src/check/registry-answer.ts).
// The spawned cases are in __tests__/checker/check-no-scan-registry-answer.test.ts.

import { describe, it, expect } from 'vitest';
import {
  isNilPackageId,
  knownTrustLevel,
  parseRetryAfter,
  registryAnswerExitCode,
  registryErrorClass,
  registryErrorKind,
  registryErrorReason,
  trustLevelWords,
} from '../../src/check/registry-answer';

describe('registry answer: levels', () => {
  it('a level off the 0..4 scale, or none, is unknown, never Blocked', () => {
    expect(knownTrustLevel(undefined)).toBeNull();
    expect(knownTrustLevel(null)).toBeNull();
    expect(knownTrustLevel(7)).toBeNull();
    expect(knownTrustLevel(-1)).toBeNull();
    expect(knownTrustLevel(2.5)).toBeNull();
    expect(knownTrustLevel('0')).toBeNull();
    expect(knownTrustLevel(0)).toBe(0);
    expect(trustLevelWords(null)).toBe('unknown');
    expect(trustLevelWords(0)).toBe('Blocked (0 of 4)');
    expect(trustLevelWords(4)).toBe('Verified (4 of 4)');
  });

  it('Blocked and Warning exit 1, the other levels 0, an unknown level 2', () => {
    expect(registryAnswerExitCode(0)).toBe(1);
    expect(registryAnswerExitCode(1)).toBe(1);
    expect(registryAnswerExitCode(2)).toBe(0);
    expect(registryAnswerExitCode(3)).toBe(0);
    expect(registryAnswerExitCode(4)).toBe(0);
    expect(registryAnswerExitCode(null)).toBe(2);
  });

  it('a package id of zeros, or none, names no package', () => {
    expect(isNilPackageId('00000000-0000-0000-0000-000000000000')).toBe(true);
    expect(isNilPackageId('00000000000000000000000000000000')).toBe(true);
    expect(isNilPackageId('')).toBe(true);
    expect(isNilPackageId(undefined)).toBe(true);
    expect(isNilPackageId('7b70f85f-0000-4000-8000-000000009411')).toBe(false);
    expect(isNilPackageId('---')).toBe(false);
  });
});

describe('registry answer: a query with no answer', () => {
  it('reads Retry-After as seconds or as a date', () => {
    expect(parseRetryAfter('30')).toBe(30);
    expect(parseRetryAfter(null)).toBeUndefined();
    expect(parseRetryAfter('soon')).toBeUndefined();
    const now = Date.parse('2026-11-27T00:00:00Z');
    expect(parseRetryAfter('Fri, 27 Nov 2026 00:01:00 GMT', now)).toBe(60);
  });

  it('a 429 is rate limited, not unreachable, and the reason names the wait', () => {
    const kind = registryErrorKind({ code: 'rate_limited', statusCode: 429, retryAfterSeconds: 30 });
    expect(kind).toBe('rate-limited');
    expect(registryErrorClass(kind)).toBe('registry-rate-limited');
    expect(registryErrorReason(kind, { retryAfterSeconds: 30 }, 15000)).toBe('rate limited, try again in 30 s');
  });

  it('a timeout, a network failure and a 5xx keep the class they had', () => {
    for (const facts of [{ code: 'timeout' }, { code: 'network' }, { code: 'server_error', statusCode: 503 }]) {
      expect(registryErrorClass(registryErrorKind(facts))).toBe('registry-unreachable');
    }
    expect(registryErrorReason('timeout', {}, 15000)).toBe('it did not answer in 15 s');
  });
});
