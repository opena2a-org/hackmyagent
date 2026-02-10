import * as crypto from 'crypto';
import type { DLPPattern } from './types';

/**
 * Mask a value based on the specified strategy.
 *
 * Strategies:
 *   full:    Replace entirely with [REDACTED:<id>]
 *   partial: Show first 4 and last 4 chars, mask middle with ***
 *   hash:    Replace with SHA-256 hash prefix
 */
export function mask(value: string, pattern: DLPPattern): string {
  switch (pattern.maskStrategy) {
    case 'full':
      return `[REDACTED:${pattern.id}]`;

    case 'partial':
      return maskPartial(value, pattern.id);

    case 'hash':
      return maskHash(value, pattern.id);

    default:
      return `[REDACTED:${pattern.id}]`;
  }
}

function maskPartial(value: string, id: string): string {
  if (value.length <= 8) {
    return `[REDACTED:${id}]`;
  }
  const prefix = value.slice(0, 4);
  const suffix = value.slice(-4);
  return `${prefix}***${suffix}`;
}

function maskHash(value: string, id: string): string {
  const hash = crypto.createHash('sha256').update(value).digest('hex').slice(0, 8);
  return `[HASH:${id}:${hash}]`;
}

/**
 * Mask all occurrences of a pattern in text.
 * Returns the masked text and info about each replacement.
 */
export function maskAll(
  text: string,
  patterns: DLPPattern[],
): { maskedText: string; replacements: Array<{ patternId: string; original: string; masked: string; offset: number }> } {
  const replacements: Array<{ patternId: string; original: string; masked: string; offset: number }> = [];

  // Collect all matches first (to handle overlapping patterns)
  const allMatches: Array<{ start: number; end: number; pattern: DLPPattern; original: string }> = [];

  for (const pattern of patterns) {
    // Reset regex state
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
      allMatches.push({
        start: match.index,
        end: match.index + match[0].length,
        pattern,
        original: match[0],
      });
    }
  }

  // Sort by position (earliest first), then longest match first for overlaps
  allMatches.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));

  // Apply replacements from end to start to preserve offsets
  let maskedText = text;
  let lastEnd = -1;
  const deduped: typeof allMatches = [];

  for (const m of allMatches) {
    if (m.start >= lastEnd) {
      deduped.push(m);
      lastEnd = m.end;
    }
  }

  // Apply from end to preserve earlier offsets
  for (let i = deduped.length - 1; i >= 0; i--) {
    const m = deduped[i];
    const masked = mask(m.original, m.pattern);
    maskedText = maskedText.slice(0, m.start) + masked + maskedText.slice(m.end);
    replacements.unshift({
      patternId: m.pattern.id,
      original: m.original,
      masked,
      offset: m.start,
    });
  }

  return { maskedText, replacements };
}
