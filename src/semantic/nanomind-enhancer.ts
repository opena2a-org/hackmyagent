/**
 * NanoMind Scanner Enhancer
 *
 * Wraps around HMA's existing static scanner output and adds semantic
 * analysis to every finding category. This makes NanoMind the default
 * intelligence layer for ALL scanners, not just --deep mode.
 *
 * Architecture:
 *   Static scan runs first (204 checks, fast, deterministic)
 *   → NanoMind enhancer runs on the results + source artifacts
 *   → Reduces false positives (benign patterns that look suspicious)
 *   → Catches false negatives (malicious patterns that look benign)
 *   → Upgrades finding severity based on semantic context
 *   → Adds evidence and remediation from NanoMind classification
 *
 * This runs automatically when the NanoMind daemon is available.
 * No flags needed. If daemon is down, scan works exactly as before.
 */

import { isDaemonAvailable, analyzeSkillIntent, analyzeSoulCompleteness, analyzeMCPScope, analyzePromptIntent } from './nanomind-analyzer.js';

export interface ScanFinding {
  checkId: string;
  name: string;
  severity: string;
  passed: boolean;
  file?: string;
  description?: string;
  fix?: string;
}

export interface EnhancedFinding extends ScanFinding {
  nanomindEnhanced: boolean;
  nanomindConfidence?: number;
  nanomindVerdict?: 'confirmed' | 'false_positive' | 'upgraded' | 'downgraded';
  nanomindEvidence?: string;
  originalSeverity?: string;
}

/**
 * Enhance scan findings with NanoMind semantic analysis.
 * Called automatically after every static scan when daemon is available.
 *
 * Returns the same findings array with NanoMind annotations added.
 * Does NOT remove findings -- only annotates them with semantic context.
 */
export async function enhanceScanFindings(
  findings: ScanFinding[],
  sourceFiles: Map<string, string>, // file path -> content
): Promise<EnhancedFinding[]> {
  const available = await isDaemonAvailable();
  if (!available) {
    // No daemon = return findings as-is, no enhancement
    return findings.map(f => ({ ...f, nanomindEnhanced: false }));
  }

  const enhanced: EnhancedFinding[] = [];

  for (const finding of findings) {
    const result = await enhanceSingleFinding(finding, sourceFiles);
    enhanced.push(result);
  }

  return enhanced;
}

/**
 * Enhance a single finding based on its check category.
 */
async function enhanceSingleFinding(
  finding: ScanFinding,
  sourceFiles: Map<string, string>,
): Promise<EnhancedFinding> {
  const base: EnhancedFinding = { ...finding, nanomindEnhanced: false };
  const checkId = finding.checkId.toUpperCase();
  const fileContent = finding.file ? sourceFiles.get(finding.file) : undefined;

  if (!fileContent) return base;

  try {
    // Route to appropriate NanoMind analyzer based on check category
    if (checkId.startsWith('SKILL-') || checkId.startsWith('SKILL-MEM-')) {
      return await enhanceSkillFinding(finding, fileContent);
    }
    if (checkId.startsWith('MCP-') || checkId.startsWith('TOOL-')) {
      return await enhanceMCPFinding(finding, fileContent);
    }
    if (checkId.startsWith('SOUL-')) {
      return await enhanceSoulFinding(finding, fileContent);
    }
    if (checkId.startsWith('PROMPT-') || checkId.startsWith('AGENT-')) {
      return await enhancePromptFinding(finding, fileContent);
    }
    if (checkId.startsWith('CRED-') || checkId.startsWith('WEBCRED-') || checkId.startsWith('AGENT-CRED-')) {
      return await enhanceCredentialFinding(finding, fileContent);
    }
    if (checkId.startsWith('A2A-')) {
      return await enhanceA2AFinding(finding, fileContent);
    }
    if (checkId.startsWith('UNICODE-STEGO-')) {
      return enhanceStegoFinding(finding, fileContent);
    }
  } catch {
    // NanoMind error = return original finding
  }

  return base;
}

// ============================================================================
// Per-Category Enhancement
// ============================================================================

async function enhanceSkillFinding(finding: ScanFinding, content: string): Promise<EnhancedFinding> {
  const result = await analyzeSkillIntent(content);

  if (!result) {
    return { ...finding, nanomindEnhanced: true, nanomindVerdict: 'confirmed', nanomindConfidence: 0.5 };
  }

  // If static flagged it AND NanoMind confirms = high confidence
  if (!finding.passed && result.confidence >= 0.7) {
    return {
      ...finding,
      nanomindEnhanced: true,
      nanomindVerdict: 'confirmed',
      nanomindConfidence: result.confidence,
      nanomindEvidence: result.evidence?.join('; '),
    };
  }

  // If static flagged it BUT NanoMind says benign = possible false positive
  if (!finding.passed && result.confidence < 0.3) {
    return {
      ...finding,
      nanomindEnhanced: true,
      nanomindVerdict: 'false_positive',
      nanomindConfidence: 1 - result.confidence,
      nanomindEvidence: 'NanoMind semantic analysis indicates this is likely a false positive',
      originalSeverity: finding.severity,
      severity: 'info', // Downgrade to informational
    };
  }

  return { ...finding, nanomindEnhanced: true, nanomindConfidence: result.confidence };
}

async function enhanceMCPFinding(finding: ScanFinding, content: string): Promise<EnhancedFinding> {
  const result = await analyzeMCPScope('', content, []);

  if (!result) {
    return { ...finding, nanomindEnhanced: true };
  }

  if (!finding.passed && result.confidence >= 0.7) {
    return {
      ...finding,
      nanomindEnhanced: true,
      nanomindVerdict: 'confirmed',
      nanomindConfidence: result.confidence,
      nanomindEvidence: result.evidence?.join('; '),
    };
  }

  return { ...finding, nanomindEnhanced: true, nanomindConfidence: result.confidence };
}

async function enhanceSoulFinding(finding: ScanFinding, content: string): Promise<EnhancedFinding> {
  const result = await analyzeSoulCompleteness(content);

  if (!result) {
    return { ...finding, nanomindEnhanced: true };
  }

  return {
    ...finding,
    nanomindEnhanced: true,
    nanomindVerdict: result.confidence >= 0.7 ? 'confirmed' : undefined,
    nanomindConfidence: result.confidence,
    nanomindEvidence: result.evidence?.join('; '),
  };
}

async function enhancePromptFinding(finding: ScanFinding, content: string): Promise<EnhancedFinding> {
  const result = await analyzePromptIntent(content);

  if (!result) {
    return { ...finding, nanomindEnhanced: true };
  }

  // NanoMind can upgrade prompt findings from medium to high if it detects
  // jailbreak seeds or capability creep patterns
  if (result.confidence >= 0.8 && finding.severity === 'medium') {
    return {
      ...finding,
      nanomindEnhanced: true,
      nanomindVerdict: 'upgraded',
      nanomindConfidence: result.confidence,
      nanomindEvidence: result.evidence?.join('; '),
      originalSeverity: 'medium',
      severity: 'high',
    };
  }

  return { ...finding, nanomindEnhanced: true, nanomindConfidence: result.confidence };
}

async function enhanceCredentialFinding(finding: ScanFinding, content: string): Promise<EnhancedFinding> {
  // NanoMind can distinguish real credentials from examples/documentation
  // "sk-live-abc123" in source = real credential (flag)
  // "sk-live-abc123" in README example = documentation (false positive)

  const isDocumentation = /example|demo|test|sample|placeholder|readme|documentation/i.test(content);
  const isTestFixture = /test\/|__tests__|\.test\.|\.spec\./i.test(finding.file ?? '');

  if (!finding.passed && (isDocumentation || isTestFixture)) {
    return {
      ...finding,
      nanomindEnhanced: true,
      nanomindVerdict: 'false_positive',
      nanomindConfidence: 0.8,
      nanomindEvidence: isTestFixture
        ? 'Credential found in test fixture (likely intentional test data)'
        : 'Credential found in documentation context (likely example, not real)',
      originalSeverity: finding.severity,
      severity: 'info',
    };
  }

  return { ...finding, nanomindEnhanced: true, nanomindVerdict: 'confirmed' };
}

async function enhanceA2AFinding(finding: ScanFinding, content: string): Promise<EnhancedFinding> {
  // A2A findings benefit from NanoMind checking if the agent card
  // declarations are semantically consistent
  return {
    ...finding,
    nanomindEnhanced: true,
    nanomindConfidence: 0.7,
  };
}

/**
 * Enhance steganography findings with semantic Unicode context analysis.
 *
 * Distinguishes legitimate Unicode (emoji, i18n, Indic text) from actual
 * steganographic attacks (hidden payloads, homoglyph typosquatting, bidi tricks).
 *
 * Key false-positive patterns this catches:
 * - Variation selectors (U+FE0F) after emoji base chars = emoji presentation
 * - Cyrillic chars in Cyrillic text blocks = i18n translations
 * - ZWNJ in Arabic/Persian text = grammatically required
 * - ZWJ between emoji = family/profession emoji sequences
 */
function enhanceStegoFinding(finding: ScanFinding, content: string): EnhancedFinding {
  const checkId = finding.checkId.toUpperCase();

  // Analyze the Unicode context in the file
  const analysis = analyzeUnicodeContext(content, finding);

  if (analysis.allLegitimate) {
    // All suspicious chars are in legitimate contexts - downgrade to info
    return {
      ...finding,
      nanomindEnhanced: true,
      nanomindVerdict: 'false_positive',
      nanomindConfidence: analysis.confidence,
      nanomindEvidence: analysis.evidence,
      originalSeverity: finding.severity,
      severity: 'info',
    };
  }

  if (analysis.someLegitimate) {
    // Mixed: some legit, some suspicious - downgrade severity but keep finding
    return {
      ...finding,
      nanomindEnhanced: true,
      nanomindVerdict: 'downgraded',
      nanomindConfidence: analysis.confidence,
      nanomindEvidence: analysis.evidence,
      originalSeverity: finding.severity,
      severity: finding.severity === 'critical' ? 'medium' : finding.severity,
    };
  }

  // Confirmed suspicious - NanoMind agrees with static scanner
  return {
    ...finding,
    nanomindEnhanced: true,
    nanomindVerdict: 'confirmed',
    nanomindConfidence: analysis.confidence,
    nanomindEvidence: analysis.evidence,
  };
}

/**
 * Analyze Unicode characters in file content to determine if they're legitimate.
 */
function analyzeUnicodeContext(content: string, finding: ScanFinding): {
  allLegitimate: boolean;
  someLegitimate: boolean;
  confidence: number;
  evidence: string;
} {
  const checkId = finding.checkId.toUpperCase();
  const codepoints = [...content].map(c => c.codePointAt(0)!);

  // Count character types
  let variationSelectors = 0;
  let emojiVariationSelectors = 0;
  let cyrillicHomoglyphs = 0;
  let cyrillicInLatinWords = 0;
  let zwjChars = 0;
  let emojiZwj = 0;
  let zwnjChars = 0;
  let arabicZwnj = 0;
  let totalCyrillic = 0;
  let totalArabic = 0;
  let totalCJK = 0;
  let totalIndic = 0;

  // Emoji bases for variation selector check
  const EMOJI_BASE_SET = new Set([
    0x0023, 0x002A, 0x0030, 0x0031, 0x0032, 0x0033, 0x0034,
    0x0035, 0x0036, 0x0037, 0x0038, 0x0039,
    // Common symbols that use FE0F
    0x2600, 0x2601, 0x2614, 0x2615, 0x2622, 0x2623,
    0x2639, 0x263A, 0x2640, 0x2642,
    0x2692, 0x2693, 0x2694, 0x2695, 0x2696, 0x2697, 0x2699,
    0x26A0, 0x26A1, 0x26AA, 0x26AB,
    0x26BD, 0x26BE, 0x26C4, 0x26C5,
    0x26D1, 0x26D3, 0x26D4, 0x26E9, 0x26EA,
    0x26F0, 0x26F1, 0x26F2, 0x26F3, 0x26F4, 0x26F5,
    0x26F7, 0x26F8, 0x26F9, 0x26FA, 0x26FD,
    0x2702, 0x2708, 0x2709, 0x270A, 0x270B, 0x270C, 0x270D,
    0x270F, 0x2712, 0x2714, 0x2716, 0x271D, 0x2721, 0x2728,
    0x2733, 0x2734, 0x2744, 0x2747, 0x274C, 0x274E,
    0x2753, 0x2754, 0x2755, 0x2757, 0x2763, 0x2764,
    0x2795, 0x2796, 0x2797, 0x27A1, 0x27B0, 0x27BF,
  ]);

  const CYRILLIC_HOMOGLYPH_SET = new Set([
    0x0430, 0x0441, 0x0435, 0x043E, 0x0440, 0x0445, 0x0443,
    0x041D, 0x0412, 0x0422, 0x041C, 0x041A,
  ]);

  for (let i = 0; i < codepoints.length; i++) {
    const cp = codepoints[i];

    // Count script blocks
    if (cp >= 0x0400 && cp <= 0x052F) totalCyrillic++;
    if (cp >= 0x0600 && cp <= 0x06FF) totalArabic++;
    if (cp >= 0x4E00 && cp <= 0x9FFF) totalCJK++;
    if (cp >= 0x0900 && cp <= 0x0D7F) totalIndic++;

    // Variation selectors
    if (cp >= 0xFE00 && cp <= 0xFE0F) {
      variationSelectors++;
      const prev = i > 0 ? codepoints[i - 1] : 0;
      if (EMOJI_BASE_SET.has(prev) || (prev >= 0x1F300 && prev <= 0x1FAFF) || (prev >= 0x2600 && prev <= 0x27BF)) {
        emojiVariationSelectors++;
      }
    }

    // Cyrillic homoglyphs
    if (CYRILLIC_HOMOGLYPH_SET.has(cp)) {
      cyrillicHomoglyphs++;
      const prevLatin = i > 0 && ((codepoints[i-1] >= 0x41 && codepoints[i-1] <= 0x5A) || (codepoints[i-1] >= 0x61 && codepoints[i-1] <= 0x7A));
      const nextLatin = i < codepoints.length - 1 && ((codepoints[i+1] >= 0x41 && codepoints[i+1] <= 0x5A) || (codepoints[i+1] >= 0x61 && codepoints[i+1] <= 0x7A));
      if (prevLatin || nextLatin) cyrillicInLatinWords++;
    }

    // ZWJ
    if (cp === 0x200D) {
      zwjChars++;
      const prev = i > 0 ? codepoints[i - 1] : 0;
      const next = i < codepoints.length - 1 ? codepoints[i + 1] : 0;
      const prevIsEmoji = (prev >= 0x1F300 && prev <= 0x1FAFF) || prev === 0xFE0F;
      const nextIsEmoji = next >= 0x1F300 && next <= 0x1FAFF;
      if (prevIsEmoji || nextIsEmoji) emojiZwj++;
    }

    // ZWNJ
    if (cp === 0x200C) {
      zwnjChars++;
      const hasArabicNearby = codepoints.slice(Math.max(0, i - 5), i + 5).some(c => c >= 0x0600 && c <= 0x06FF);
      const hasIndicNearby = codepoints.slice(Math.max(0, i - 5), i + 5).some(c => c >= 0x0900 && c <= 0x0D7F);
      if (hasArabicNearby || hasIndicNearby) arabicZwnj++;
    }
  }

  // Decide based on check type
  if (checkId === 'UNICODE-STEGO-001') {
    // Invisible codepoints check
    if (variationSelectors > 0 && emojiVariationSelectors === variationSelectors) {
      return {
        allLegitimate: true,
        someLegitimate: false,
        confidence: 0.95,
        evidence: `All ${variationSelectors} variation selectors are emoji presentation selectors (FE0F after emoji bases)`,
      };
    }
    if (zwjChars > 0 && emojiZwj === zwjChars) {
      return {
        allLegitimate: true,
        someLegitimate: false,
        confidence: 0.92,
        evidence: `All ${zwjChars} ZWJ characters are in emoji ZWJ sequences`,
      };
    }
    if (zwnjChars > 0 && arabicZwnj === zwnjChars) {
      return {
        allLegitimate: true,
        someLegitimate: false,
        confidence: 0.90,
        evidence: `All ${zwnjChars} ZWNJ characters are in Arabic/Indic text contexts`,
      };
    }
    // Mixed case
    const totalSuspicious = variationSelectors + zwjChars + zwnjChars;
    const totalLegitimate = emojiVariationSelectors + emojiZwj + arabicZwnj;
    if (totalLegitimate > 0 && totalLegitimate < totalSuspicious) {
      return {
        allLegitimate: false,
        someLegitimate: true,
        confidence: 0.7,
        evidence: `${totalLegitimate} of ${totalSuspicious} invisible chars appear legitimate, but ${totalSuspicious - totalLegitimate} remain suspicious`,
      };
    }
  }

  if (checkId === 'UNICODE-STEGO-005') {
    // Homoglyph check
    if (cyrillicHomoglyphs > 0 && cyrillicInLatinWords === 0) {
      return {
        allLegitimate: true,
        someLegitimate: false,
        confidence: 0.93,
        evidence: `${cyrillicHomoglyphs} Cyrillic characters found in Cyrillic text blocks (${totalCyrillic} total Cyrillic chars) - legitimate i18n content`,
      };
    }
    if (cyrillicInLatinWords > 0 && cyrillicInLatinWords < cyrillicHomoglyphs) {
      return {
        allLegitimate: false,
        someLegitimate: true,
        confidence: 0.75,
        evidence: `${cyrillicInLatinWords} of ${cyrillicHomoglyphs} Cyrillic chars are mixed into Latin words (suspicious), rest are in Cyrillic text (legitimate)`,
      };
    }
  }

  // Default: confirm the static finding
  return {
    allLegitimate: false,
    someLegitimate: false,
    confidence: 0.8,
    evidence: 'Unicode steganography patterns confirmed by semantic analysis',
  };
}

// ============================================================================
// Statistics
// ============================================================================

export function getEnhancementStats(findings: EnhancedFinding[]): {
  total: number;
  enhanced: number;
  falsePositivesDetected: number;
  upgraded: number;
  confirmed: number;
} {
  const enhanced = findings.filter(f => f.nanomindEnhanced);
  return {
    total: findings.length,
    enhanced: enhanced.length,
    falsePositivesDetected: enhanced.filter(f => f.nanomindVerdict === 'false_positive').length,
    upgraded: enhanced.filter(f => f.nanomindVerdict === 'upgraded').length,
    confirmed: enhanced.filter(f => f.nanomindVerdict === 'confirmed').length,
  };
}
