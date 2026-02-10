import { PII_PATTERNS } from './pii-detector';
import { SECRET_PATTERNS } from './secret-detector';
import { mask, maskAll } from './masking';
import { getDLPAction, defaultDLPPolicy } from './policy';
import type { DLPPattern, DLPMatch, DLPScanResult, DLPPolicy } from './types';

export type { DLPPattern, DLPMatch, DLPScanResult, DLPPolicy } from './types';
export { PII_PATTERNS } from './pii-detector';
export { SECRET_PATTERNS } from './secret-detector';
export { mask, maskAll } from './masking';
export { getDLPAction, defaultDLPPolicy } from './policy';

/** All built-in DLP patterns */
export const ALL_PATTERNS: DLPPattern[] = [...PII_PATTERNS, ...SECRET_PATTERNS];

/**
 * Scan text for DLP violations — PII, credentials, and sensitive data.
 * Returns detection results with masked text.
 */
export function scanText(
  text: string,
  options?: { patterns?: DLPPattern[]; policy?: DLPPolicy },
): DLPScanResult {
  const patterns = options?.patterns ?? ALL_PATTERNS;
  const policy = options?.policy;

  const matches: DLPMatch[] = [];
  let hasBlocked = false;
  let hasMasked = false;

  // Run detection
  for (const pattern of patterns) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let regexMatch: RegExpExecArray | null;

    while ((regexMatch = regex.exec(text)) !== null) {
      const action = getDLPAction(pattern, policy);

      if (action === 'allow') continue;

      const masked = mask(regexMatch[0], pattern);

      matches.push({
        patternId: pattern.id,
        patternName: pattern.name,
        severity: pattern.severity,
        category: pattern.category,
        offset: regexMatch.index,
        length: regexMatch[0].length,
        original: regexMatch[0],
        masked,
      });

      if (action === 'block') hasBlocked = true;
      if (action === 'mask') hasMasked = true;
    }
  }

  // Sort by offset
  matches.sort((a, b) => a.offset - b.offset);

  // Determine overall action
  let action: DLPScanResult['action'];
  if (hasBlocked) {
    action = 'blocked';
  } else if (hasMasked || matches.length > 0) {
    action = 'masked';
  } else {
    action = 'allowed';
  }

  // Build masked text (apply all mask/block replacements)
  const patternsToMask = patterns.filter((p) => {
    const a = getDLPAction(p, policy);
    return a === 'mask' || a === 'block';
  });
  const { maskedText } = maskAll(text, patternsToMask);

  return {
    detected: matches.length > 0,
    matches,
    maskedText,
    action,
  };
}

/**
 * Mask metadata before writing to audit log.
 * Scans string values in metadata for sensitive data and masks them.
 */
export function maskMetadata(
  metadata: Record<string, unknown>,
  policy?: DLPPolicy,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(metadata)) {
    if (typeof value === 'string') {
      const scan = scanText(value, { policy });
      result[key] = scan.detected ? scan.maskedText : value;
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      result[key] = maskMetadata(value as Record<string, unknown>, policy);
    } else {
      result[key] = value;
    }
  }

  return result;
}
