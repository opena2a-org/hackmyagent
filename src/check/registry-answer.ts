/**
 * What `check --no-scan` makes of the Registry's answer, kept in one place so
 * the npm, PyPI and GitHub paths cannot read the same answer three ways.
 *
 * Four outcomes, and they mean different things:
 *
 *   - a record with a trust level the scale knows (0 Blocked .. 4 Verified);
 *   - a record whose level is missing or outside that scale: shown as
 *     "unknown". It used to default to 0, which printed `Blocked` for a
 *     package the Registry never said anything bad about;
 *   - no record: a 404, or an answer whose package id is missing or all
 *     zeros (the Registry's placeholder for a name it does not carry);
 *   - no answer at all: a network failure, a timeout, a 429 or a 5xx. That is
 *     not a verdict and not a "not found": the Registry could not be asked.
 */
import { EXIT_FAIL, EXIT_PASS, EXIT_UNMEASURED } from './verdict';

/** The scale's words, indexed by level. */
export const TRUST_LEVEL_NAMES = ['Blocked', 'Warning', 'Listed', 'Scanned', 'Verified'] as const;
export const MAX_TRUST_LEVEL = TRUST_LEVEL_NAMES.length - 1;

/** The level as the scale knows it, or null when it is missing or not on the scale. */
export function knownTrustLevel(raw: unknown): number | null {
  if (typeof raw !== 'number' || !Number.isInteger(raw)) return null;
  if (raw < 0 || raw > MAX_TRUST_LEVEL) return null;
  return raw;
}

/** `Blocked (0 of 4)`, or `unknown` for a level the scale does not know. */
export function trustLevelWords(level: number | null): string {
  if (level === null) return 'unknown';
  return `${TRUST_LEVEL_NAMES[level]} (${level} of ${MAX_TRUST_LEVEL})`;
}

/** The lower-case word for a JSON document: `blocked` .. `verified`, or `unknown`. */
export function trustLevelName(level: number | null): string {
  return level === null ? 'unknown' : TRUST_LEVEL_NAMES[level].toLowerCase();
}

/**
 * True when the package id names no package: missing, empty, or a UUID of
 * zeros (with or without hyphens). The Registry answers some names it does
 * not carry with such an id instead of a 404.
 */
export function isNilPackageId(id: unknown): boolean {
  if (id === undefined || id === null) return true;
  const s = String(id).trim();
  if (s === '') return true;
  return /^[0-]+$/.test(s) && s.includes('0');
}

/**
 * The exit code of `check --no-scan` for a record:
 *   1 for Blocked or Warning, the two levels the Registry gives a package it
 *     found a problem with;
 *   0 for Listed, Scanned and Verified;
 *   2 for a level it did not give, since the run has no answer to report.
 */
export function registryAnswerExitCode(level: number | null): number {
  if (level === null) return EXIT_UNMEASURED;
  return level <= 1 ? EXIT_FAIL : EXIT_PASS;
}

/**
 * `assessed` or `listed-not-assessed`: whether the Registry examined the
 * package, as opposed to only listing it.
 */
export function registryAnswerState(level: number | null, scanStatus?: string): 'assessed' | 'listed-not-assessed' {
  if (level === 2) return 'listed-not-assessed';
  if (level === null && !scanStatus) return 'listed-not-assessed';
  return 'assessed';
}

/**
 * Seconds to wait from a Retry-After header: a whole number of seconds, or an
 * HTTP date. Undefined when the header is absent or unreadable.
 */
export function parseRetryAfter(header: string | null | undefined, now: number = Date.now()): number | undefined {
  if (header === null || header === undefined) return undefined;
  const v = header.trim();
  if (v === '') return undefined;
  if (/^\d+$/.test(v)) return Number(v);
  const at = Date.parse(v);
  if (Number.isNaN(at)) return undefined;
  return Math.max(0, Math.ceil((at - now) / 1000));
}

/** What happened to a Registry query that produced no answer. */
export type RegistryErrorKind =
  | 'rate-limited'
  | 'timeout'
  | 'network'
  | 'server-error'
  | 'refused'
  | 'invalid-response'
  | 'client-unavailable';

export interface RegistryErrorFacts {
  /** The registry client's error code, when it gave one (`rate_limited`, `timeout`, ...). */
  code?: string;
  statusCode?: number;
  /** Seconds the Registry asked the caller to wait, from Retry-After. */
  retryAfterSeconds?: number;
}

export function registryErrorKind(facts: RegistryErrorFacts): RegistryErrorKind {
  const { code, statusCode } = facts;
  if (statusCode === 429 || code === 'rate_limited') return 'rate-limited';
  if (code === 'timeout') return 'timeout';
  if (code === 'network') return 'network';
  if (code === 'invalid_response') return 'invalid-response';
  if (code === 'client_unavailable') return 'client-unavailable';
  if (statusCode === 401 || statusCode === 403 || code === 'unauthorized' || code === 'forbidden') return 'refused';
  if (code === 'bad_request' || statusCode === 400) return 'refused';
  return 'server-error';
}

/**
 * The `errorClass` a JSON document carries. `registry-unreachable` is kept for
 * every case it already named; a 429 is not that, the Registry answered and
 * asked the caller to wait.
 */
export function registryErrorClass(kind: RegistryErrorKind): string {
  return kind === 'rate-limited' ? 'registry-rate-limited' : 'registry-unreachable';
}

/** `30 s`, `2 min`, `2 min 5 s`. */
export function formatWait(seconds: number): string {
  if (seconds < 60) return `${seconds} s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return s === 0 ? `${m} min` : `${m} min ${s} s`;
}

/** What happened, in words: `rate limited, try again in 30 s`. */
export function registryErrorReason(kind: RegistryErrorKind, facts: RegistryErrorFacts, timeoutMs: number): string {
  switch (kind) {
    case 'rate-limited':
      return typeof facts.retryAfterSeconds === 'number'
        ? `rate limited, try again in ${formatWait(facts.retryAfterSeconds)}`
        : 'rate limited, wait a minute and try again';
    case 'timeout':
      return `it did not answer in ${Math.round(timeoutMs / 1000)} s`;
    case 'network':
      return 'it could not be reached; check your network or proxy';
    case 'refused':
      return `it refused the request${typeof facts.statusCode === 'number' ? ` (${facts.statusCode})` : ''}`;
    case 'invalid-response':
      return 'its answer could not be read';
    case 'client-unavailable':
      return 'the registry client could not be loaded';
    case 'server-error':
    default:
      return `it returned a server error${typeof facts.statusCode === 'number' ? ` (${facts.statusCode})` : ''}`;
  }
}
