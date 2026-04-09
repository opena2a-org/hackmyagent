/**
 * Steganography Analyzer -- AST-based UNICODE-STEGO-* checks
 *
 * Provides semantic context that the static byte-level scanner cannot:
 * - Distinguishes emoji variation selectors from data-encoding variation selectors
 * - Distinguishes Cyrillic in Cyrillic text (i18n) from Cyrillic in Latin words (homoglyphs)
 * - Distinguishes ZWNJ/ZWJ in Indic/Arabic text from hidden payload encoding
 * - Uses TME classifier for file-level intent as a secondary signal
 *
 * Defense-in-depth: this analyzer can DOWNGRADE stego findings from the static
 * scanner but cannot SUPPRESS them entirely. A downgraded finding still appears
 * in results with evidence explaining why it's benign.
 *
 * Addresses false positives like @upstash/context7-mcp where emoji headers
 * and i18n translation badges triggered CRITICAL steganography findings.
 */

import type { SecurityAST } from '../types.js';
import type { ASTFinding } from './capability-analyzer.js';

// ============================================================================
// Unicode Constants
// ============================================================================

// Steganographic characters (invisible, format-control)
const STEGO_RANGES: Array<[number, number]> = [
  [0x200B, 0x200D],   // Zero-width space, ZWNJ, ZWJ
  [0x2060, 0x2060],   // Word joiner
  [0x00AD, 0x00AD],   // Soft hyphen
  [0x202A, 0x202E],   // Bidi overrides (LRE, RLE, PDF, LRO, RLO)
  [0x2066, 0x2069],   // Bidi isolates (LRI, RLI, FSI, PDI)
  [0xFE00, 0xFE0F],   // Variation selectors
  [0xE0000, 0xE01EF], // Tag characters
];

// Cyrillic characters commonly used as Latin homoglyphs
const CYRILLIC_HOMOGLYPHS: Set<number> = new Set([
  0x0430, // а (a)
  0x0441, // с (c)
  0x0435, // е (e)
  0x043E, // о (o)
  0x0440, // р (p)
  0x0445, // х (x)
  0x0443, // у (y)
  0x041D, // Н (H)
  0x0412, // В (B)
  0x0422, // Т (T)
  0x041C, // М (M)
  0x041A, // К (K)
]);

// Emoji base characters that legitimately precede variation selectors
// Includes keycap bases, symbols, and common emoji
const EMOJI_BASES: Set<number> = new Set([
  0x0023, // # (keycap)
  0x002A, // * (keycap)
  0x0030, 0x0031, 0x0032, 0x0033, 0x0034, // 0-4 (keycaps)
  0x0035, 0x0036, 0x0037, 0x0038, 0x0039, // 5-9 (keycaps)
  0x2600, 0x2601, 0x2602, 0x2603, // weather symbols
  0x2614, 0x2615, // umbrella, hot beverage
  0x2622, 0x2623, // radioactive, biohazard
  0x2626, 0x262A, 0x262E, 0x262F, // religious symbols
  0x2639, 0x263A, // frowning, smiling face
  0x2640, 0x2642, // gender symbols
  0x2660, 0x2663, 0x2665, 0x2666, // card suits
  0x2692, 0x2693, 0x2694, 0x2695, 0x2696, 0x2697, // tools
  0x2699, // gear
  0x269B, 0x269C, // atom, fleur-de-lis
  0x26A0, 0x26A1, // warning, high voltage
  0x26AA, 0x26AB, // circles
  0x26B0, 0x26B1, // coffin, urn
  0x26BD, 0x26BE, // sports
  0x26C4, 0x26C5, // weather
  0x26CE, 0x26CF, // Ophiuchus, pick
  0x26D1, // helmet
  0x26D3, 0x26D4, // chains, no entry
  0x26E9, 0x26EA, // shinto, church
  0x26F0, 0x26F1, 0x26F2, 0x26F3, 0x26F4, 0x26F5, // misc
  0x26F7, 0x26F8, 0x26F9, 0x26FA, // sports/tent
  0x26FD, // fuel pump
  0x2702, // scissors
  0x2708, 0x2709, // airplane, envelope
  0x270A, 0x270B, 0x270C, 0x270D, // hands
  0x270F, // pencil
  0x2712, // pen
  0x2714, // check mark
  0x2716, // x mark
  0x271D, // cross
  0x2721, // star of david
  0x2728, // sparkles
  0x2733, 0x2734, // asterisks
  0x2744, // snowflake
  0x2747, // sparkle
  0x274C, 0x274E, // cross marks
  0x2753, 0x2754, 0x2755, // question/exclamation
  0x2757, // exclamation
  0x2763, 0x2764, // heart exclamation, heart
  0x2795, 0x2796, 0x2797, // math symbols
  0x27A1, // right arrow
  0x27B0, 0x27BF, // curly loop
]);

// CJK Unicode ranges
const CJK_RANGES: Array<[number, number]> = [
  [0x4E00, 0x9FFF],   // CJK Unified Ideographs
  [0x3400, 0x4DBF],   // CJK Extension A
  [0x3000, 0x303F],   // CJK Symbols and Punctuation
  [0x3040, 0x309F],   // Hiragana
  [0x30A0, 0x30FF],   // Katakana
  [0xAC00, 0xD7AF],   // Hangul Syllables
  [0xFF00, 0xFFEF],   // Fullwidth Forms
];

// Cyrillic Unicode ranges
const CYRILLIC_RANGES: Array<[number, number]> = [
  [0x0400, 0x04FF],   // Cyrillic
  [0x0500, 0x052F],   // Cyrillic Supplement
];

// Arabic Unicode ranges
const ARABIC_RANGES: Array<[number, number]> = [
  [0x0600, 0x06FF],   // Arabic
  [0x0750, 0x077F],   // Arabic Supplement
  [0xFB50, 0xFDFF],   // Arabic Presentation Forms-A
  [0xFE70, 0xFEFF],   // Arabic Presentation Forms-B
];

// Devanagari/Indic ranges (where ZWNJ/ZWJ are grammatically required)
const INDIC_RANGES: Array<[number, number]> = [
  [0x0900, 0x097F],   // Devanagari
  [0x0980, 0x09FF],   // Bengali
  [0x0A00, 0x0A7F],   // Gurmukhi
  [0x0A80, 0x0AFF],   // Gujarati
  [0x0B00, 0x0B7F],   // Oriya
  [0x0B80, 0x0BFF],   // Tamil
  [0x0C00, 0x0C7F],   // Telugu
  [0x0C80, 0x0CFF],   // Kannada
  [0x0D00, 0x0D7F],   // Malayalam
];

// ============================================================================
// Helper Functions
// ============================================================================

function inRanges(cp: number, ranges: Array<[number, number]>): boolean {
  return ranges.some(([lo, hi]) => cp >= lo && cp <= hi);
}

function isStegoChar(cp: number): boolean {
  return inRanges(cp, STEGO_RANGES);
}

function isCJK(cp: number): boolean {
  return inRanges(cp, CJK_RANGES);
}

function isCyrillic(cp: number): boolean {
  return inRanges(cp, CYRILLIC_RANGES);
}

function isArabic(cp: number): boolean {
  return inRanges(cp, ARABIC_RANGES);
}

function isIndic(cp: number): boolean {
  return inRanges(cp, INDIC_RANGES);
}

function isLatinAlpha(cp: number): boolean {
  return (cp >= 0x41 && cp <= 0x5A) || (cp >= 0x61 && cp <= 0x7A);
}

/**
 * Check if a high-codepoint character (>= 0x10000) is a standard emoji.
 * Most emoji are in the Supplementary Multilingual Plane.
 */
function isEmoji(cp: number): boolean {
  return (
    (cp >= 0x1F300 && cp <= 0x1F9FF) || // Misc Symbols, Emoticons, etc.
    (cp >= 0x1FA00 && cp <= 0x1FAFF) || // Symbols Extended-A
    (cp >= 0x2600 && cp <= 0x27BF) ||   // Misc symbols (also in BMP)
    EMOJI_BASES.has(cp)
  );
}

// ============================================================================
// Context Analysis
// ============================================================================

interface CharContext {
  /** The suspicious codepoint */
  codepoint: number;
  /** Position in text */
  position: number;
  /** Line number (1-based) */
  line: number;
  /** Characters before (up to 10) */
  before: number[];
  /** Characters after (up to 10) */
  after: number[];
}

function extractContexts(text: string): CharContext[] {
  const contexts: CharContext[] = [];
  const codepoints = [...text].map(c => c.codePointAt(0)!);

  for (let i = 0; i < codepoints.length; i++) {
    const cp = codepoints[i];
    if (!isStegoChar(cp) && !CYRILLIC_HOMOGLYPHS.has(cp)) continue;

    const line = text.slice(0, [...text].slice(0, i + 1).join('').length).split('\n').length;
    const before = codepoints.slice(Math.max(0, i - 10), i);
    const after = codepoints.slice(i + 1, Math.min(codepoints.length, i + 11));

    contexts.push({ codepoint: cp, position: i, line, before, after });
  }

  return contexts;
}

// ============================================================================
// Benign Pattern Detectors
// ============================================================================

/**
 * Check if a variation selector (U+FE0F) is a legitimate emoji presentation selector.
 * Returns true if it follows an emoji base character or is part of a keycap sequence.
 */
function isLegitimateVariationSelector(ctx: CharContext): boolean {
  if (ctx.codepoint < 0xFE00 || ctx.codepoint > 0xFE0F) return false;

  // Check if preceded by an emoji base or emoji character
  if (ctx.before.length > 0) {
    const prev = ctx.before[ctx.before.length - 1];
    if (EMOJI_BASES.has(prev) || isEmoji(prev)) return true;

    // Keycap sequence: digit/# + FE0F + 20E3
    if ((prev >= 0x30 && prev <= 0x39) || prev === 0x23 || prev === 0x2A) return true;
  }

  // Check if followed by combining enclosing keycap (U+20E3)
  if (ctx.after.length > 0 && ctx.after[0] === 0x20E3) return true;

  return false;
}

/**
 * Check if a ZWJ (U+200D) is a legitimate emoji ZWJ sequence or Indic conjunct.
 * Returns true for family emoji, profession emoji, flag sequences, or Indic text.
 */
function isLegitimateZWJ(ctx: CharContext): boolean {
  if (ctx.codepoint !== 0x200D) return false;

  // Check for emoji context (emoji before and after ZWJ)
  const prevEmoji = ctx.before.length > 0 && (isEmoji(ctx.before[ctx.before.length - 1]) || ctx.before[ctx.before.length - 1] === 0xFE0F);
  const nextEmoji = ctx.after.length > 0 && isEmoji(ctx.after[0]);
  if (prevEmoji && nextEmoji) return true;

  // Check for Indic conjunct context
  const hasIndic = ctx.before.some(c => isIndic(c)) || ctx.after.some(c => isIndic(c));
  if (hasIndic) return true;

  return false;
}

/**
 * Check if a ZWNJ (U+200C) is a legitimate Persian/Arabic text separator.
 * In Persian, ZWNJ is grammatically required between prefix and word.
 */
function isLegitimateZWNJ(ctx: CharContext): boolean {
  if (ctx.codepoint !== 0x200C) return false;

  // Arabic/Persian context: ZWNJ between Arabic chars
  const hasArabic = ctx.before.some(c => isArabic(c)) || ctx.after.some(c => isArabic(c));
  if (hasArabic) return true;

  // Indic context: ZWNJ for half-forms
  const hasIndic = ctx.before.some(c => isIndic(c)) || ctx.after.some(c => isIndic(c));
  if (hasIndic) return true;

  return false;
}

/**
 * Check if a Cyrillic character is a homoglyph attack (Cyrillic mixed into Latin)
 * vs legitimate Cyrillic text (i18n badges, translations, etc.).
 *
 * Attack pattern: "cоnfig" (Cyrillic о in a Latin word)
 * Benign pattern: "Документация" (pure Cyrillic text)
 */
function isCyrillicHomoglyphAttack(ctx: CharContext): boolean {
  if (!CYRILLIC_HOMOGLYPHS.has(ctx.codepoint)) return false;

  // Check if surrounded by Latin characters (= homoglyph attack)
  const prevLatin = ctx.before.length > 0 && isLatinAlpha(ctx.before[ctx.before.length - 1]);
  const nextLatin = ctx.after.length > 0 && isLatinAlpha(ctx.after[0]);

  // If both neighbors are Latin, this is almost certainly a homoglyph attack
  if (prevLatin && nextLatin) return true;

  // If one neighbor is Latin and the other is space/punctuation, still suspicious
  if (prevLatin || nextLatin) {
    // But check if there's more Cyrillic nearby (might be a Cyrillic word adjacent to Latin)
    const nearbyCyrillic = [...ctx.before, ...ctx.after].filter(c => isCyrillic(c)).length;
    // If very few Cyrillic chars among mostly Latin = attack
    return nearbyCyrillic < 3;
  }

  // Surrounded by Cyrillic or non-Latin = legitimate i18n text
  return false;
}

// ============================================================================
// Main Analyzer
// ============================================================================

/**
 * Analyze a SecurityAST for steganography patterns.
 * Produces findings compatible with the static UNICODE-STEGO-* checks,
 * but with semantic context that enables false-positive reduction.
 *
 * Each finding includes:
 * - passed: true if the Unicode is benign (legitimate emoji, i18n, etc.)
 * - confidence: how sure we are about the verdict
 * - evidence: human-readable explanation
 */
export function analyzeSteganography(
  ast: SecurityAST,
): ASTFinding[] {
  const findings: ASTFinding[] = [];

  // Get the raw text from evidence spans or declared purpose
  const text = ast.evidenceSpans.map(s => s.text).join('\n') || ast.declaredPurpose || '';
  if (!text) return findings;

  const contexts = extractContexts(text);
  if (contexts.length === 0) return findings;

  // Analyze each suspicious character in context
  const variationSelectors = contexts.filter(c => c.codepoint >= 0xFE00 && c.codepoint <= 0xFE0F);
  const zwjChars = contexts.filter(c => c.codepoint === 0x200D);
  const zwnjChars = contexts.filter(c => c.codepoint === 0x200C);
  const homoglyphs = contexts.filter(c => CYRILLIC_HOMOGLYPHS.has(c.codepoint));
  const zwsChars = contexts.filter(c => c.codepoint === 0x200B);
  const bidiChars = contexts.filter(c => (c.codepoint >= 0x202A && c.codepoint <= 0x202E) ||
                                          (c.codepoint >= 0x2066 && c.codepoint <= 0x2069));
  const tagChars = contexts.filter(c => c.codepoint >= 0xE0000 && c.codepoint <= 0xE01EF);
  const softHyphens = contexts.filter(c => c.codepoint === 0x00AD);
  const wordJoiners = contexts.filter(c => c.codepoint === 0x2060);

  // ── Variation Selectors ──
  if (variationSelectors.length > 0) {
    const legitimate = variationSelectors.filter(isLegitimateVariationSelector);
    const suspicious = variationSelectors.length - legitimate.length;

    if (suspicious === 0) {
      // ALL variation selectors are legitimate emoji presentation selectors
      findings.push({
        checkId: 'UNICODE-STEGO-001',
        name: 'Variation Selectors - Legitimate Emoji',
        description: `Found ${variationSelectors.length} variation selector(s), all in emoji contexts`,
        category: 'unicode-stego',
        severity: 'info',
        passed: true,
        message: `All ${variationSelectors.length} variation selectors are emoji presentation selectors (U+FE0F after emoji base characters)`,
        fixable: false,
        file: ast.artifactPath,
        attackClass: 'UNICODE-STEGO',
        confidence: 0.95,
        evidence: `Emoji patterns: ${legitimate.slice(0, 3).map(c =>
          `U+${c.codepoint.toString(16).toUpperCase()} at L${c.line}`
        ).join(', ')}`,
      });
    } else {
      // Some variation selectors are NOT in emoji contexts
      findings.push({
        checkId: 'UNICODE-STEGO-001',
        name: 'Suspicious Variation Selectors',
        description: `Found ${suspicious} variation selector(s) outside emoji contexts`,
        category: 'unicode-stego',
        severity: 'high',
        passed: false,
        message: `${suspicious} of ${variationSelectors.length} variation selectors are not emoji presentation selectors - possible data encoding`,
        fixable: false,
        file: ast.artifactPath,
        attackClass: 'UNICODE-STEGO',
        confidence: 0.85,
        evidence: `Suspicious at lines: ${variationSelectors.filter(c => !isLegitimateVariationSelector(c)).slice(0, 5).map(c => `L${c.line}`).join(', ')}`,
      });
    }
  }

  // ── ZWJ Characters ──
  if (zwjChars.length > 0) {
    const legitimate = zwjChars.filter(isLegitimateZWJ);
    const suspicious = zwjChars.length - legitimate.length;

    if (suspicious === 0) {
      findings.push({
        checkId: 'UNICODE-STEGO-001',
        name: 'Zero-Width Joiners - Legitimate',
        description: `Found ${zwjChars.length} ZWJ(s), all in emoji/Indic contexts`,
        category: 'unicode-stego',
        severity: 'info',
        passed: true,
        message: `All ${zwjChars.length} ZWJ characters are legitimate (emoji sequences or Indic conjuncts)`,
        fixable: false,
        file: ast.artifactPath,
        attackClass: 'UNICODE-STEGO',
        confidence: 0.92,
        evidence: 'ZWJ used in emoji ZWJ sequences or Indic text rendering',
      });
    }
    // If suspicious, let static scanner handle it (defense-in-depth)
  }

  // ── ZWNJ Characters ──
  if (zwnjChars.length > 0) {
    const legitimate = zwnjChars.filter(isLegitimateZWNJ);
    const suspicious = zwnjChars.length - legitimate.length;

    if (suspicious === 0) {
      findings.push({
        checkId: 'UNICODE-STEGO-001',
        name: 'Zero-Width Non-Joiners - Legitimate',
        description: `Found ${zwnjChars.length} ZWNJ(s), all in Arabic/Indic contexts`,
        category: 'unicode-stego',
        severity: 'info',
        passed: true,
        message: `All ${zwnjChars.length} ZWNJ characters are legitimate (Persian/Arabic grammar or Indic half-forms)`,
        fixable: false,
        file: ast.artifactPath,
        attackClass: 'UNICODE-STEGO',
        confidence: 0.90,
        evidence: 'ZWNJ used in Persian/Arabic text separation or Indic rendering',
      });
    }
  }

  // ── Cyrillic Homoglyphs ──
  if (homoglyphs.length > 0) {
    const attacks = homoglyphs.filter(isCyrillicHomoglyphAttack);
    const legitimate = homoglyphs.length - attacks.length;

    if (attacks.length === 0) {
      // All Cyrillic chars are in Cyrillic text blocks (i18n)
      findings.push({
        checkId: 'UNICODE-STEGO-005',
        name: 'Cyrillic Characters - Legitimate i18n',
        description: `Found ${homoglyphs.length} Cyrillic character(s) in Cyrillic text context`,
        category: 'unicode-stego',
        severity: 'info',
        passed: true,
        message: `${homoglyphs.length} Cyrillic characters are in legitimate Cyrillic text blocks (translations, i18n badges)`,
        fixable: false,
        file: ast.artifactPath,
        attackClass: 'UNICODE-STEGO',
        confidence: 0.93,
        evidence: `Cyrillic in i18n context at lines: ${homoglyphs.slice(0, 5).map(c => `L${c.line}`).join(', ')}`,
      });
    } else {
      // Cyrillic chars mixed into Latin words (homoglyph attack)
      findings.push({
        checkId: 'UNICODE-STEGO-005',
        name: 'Homoglyph Attack Detected',
        description: `Found ${attacks.length} Cyrillic character(s) embedded in Latin words`,
        category: 'unicode-stego',
        severity: 'high',
        passed: false,
        message: `${attacks.length} Cyrillic homoglyphs mixed into Latin words - likely typosquatting or identifier spoofing`,
        fixable: false,
        file: ast.artifactPath,
        attackClass: 'UNICODE-STEGO',
        confidence: 0.88,
        evidence: `Homoglyphs at lines: ${attacks.slice(0, 5).map(c => `U+${c.codepoint.toString(16).toUpperCase()} at L${c.line}`).join(', ')}`,
      });
    }
  }

  // ── Zero-Width Spaces (always suspicious unless very few) ──
  if (zwsChars.length > 0) {
    findings.push({
      checkId: 'UNICODE-STEGO-001',
      name: 'Zero-Width Spaces Detected',
      description: `Found ${zwsChars.length} zero-width space(s)`,
      category: 'unicode-stego',
      severity: zwsChars.length > 10 ? 'critical' : 'high',
      passed: false,
      message: `${zwsChars.length} zero-width space characters detected - may encode hidden data`,
      fixable: false,
      file: ast.artifactPath,
      attackClass: 'UNICODE-STEGO',
      confidence: 0.85,
      evidence: `ZWS at lines: ${zwsChars.slice(0, 5).map(c => `L${c.line}`).join(', ')}`,
    });
  }

  // ── Bidi Overrides (almost always suspicious in configs/code) ──
  if (bidiChars.length > 0) {
    // Check if file has significant Arabic/Hebrew content (where bidi is normal)
    const allCps = [...text].map(c => c.codePointAt(0)!);
    const arabicCount = allCps.filter(c => isArabic(c)).length;
    const hebrewCount = allCps.filter(c => c >= 0x0590 && c <= 0x05FF).length;
    const rtlTextRatio = (arabicCount + hebrewCount) / Math.max(allCps.length, 1);

    if (rtlTextRatio > 0.1) {
      // Significant RTL text present - bidi overrides might be legitimate
      findings.push({
        checkId: 'UNICODE-STEGO-001',
        name: 'Bidi Controls in RTL Text',
        description: `Found ${bidiChars.length} bidi control(s) in content with ${Math.round(rtlTextRatio * 100)}% RTL text`,
        category: 'unicode-stego',
        severity: 'medium',
        passed: true,
        message: `Bidi controls in document with significant Arabic/Hebrew text - likely legitimate`,
        fixable: false,
        file: ast.artifactPath,
        attackClass: 'UNICODE-STEGO',
        confidence: 0.75,
        evidence: 'RTL text detected, bidi controls may be required for correct rendering',
      });
    } else {
      findings.push({
        checkId: 'UNICODE-STEGO-001',
        name: 'Bidi Override Attack',
        description: `Found ${bidiChars.length} bidi override(s) in non-RTL content`,
        category: 'unicode-stego',
        severity: 'critical',
        passed: false,
        message: `${bidiChars.length} bidi overrides in content without RTL text - likely text direction attack`,
        fixable: false,
        file: ast.artifactPath,
        attackClass: 'UNICODE-STEGO',
        confidence: 0.92,
        evidence: `Bidi chars at lines: ${bidiChars.slice(0, 5).map(c => `U+${c.codepoint.toString(16).toUpperCase()} at L${c.line}`).join(', ')}`,
      });
    }
  }

  // ── Tag Characters (almost always malicious) ──
  if (tagChars.length > 0) {
    findings.push({
      checkId: 'UNICODE-STEGO-004',
      name: 'Tag Character Encoding',
      description: `Found ${tagChars.length} tag character(s)`,
      category: 'unicode-stego',
      severity: 'critical',
      passed: false,
      message: `${tagChars.length} Unicode tag characters detected - these encode hidden ASCII data`,
      fixable: false,
      file: ast.artifactPath,
      attackClass: 'UNICODE-STEGO',
      confidence: 0.95,
      evidence: `Tag chars at lines: ${tagChars.slice(0, 5).map(c => `L${c.line}`).join(', ')}`,
    });
  }

  // ── Soft Hyphens (suspicious in configs, benign in prose) ──
  if (softHyphens.length > 0) {
    const inCode = ast.artifactType === 'source_code' || ast.artifactType === 'mcp_config';
    findings.push({
      checkId: 'UNICODE-STEGO-001',
      name: 'Soft Hyphens Detected',
      description: `Found ${softHyphens.length} soft hyphen(s)`,
      category: 'unicode-stego',
      severity: inCode ? 'high' : 'medium',
      passed: !inCode && softHyphens.length < 5,
      message: inCode
        ? `${softHyphens.length} soft hyphens in code/config - may hide commands`
        : `${softHyphens.length} soft hyphens in document (may be legitimate hyphenation)`,
      fixable: false,
      file: ast.artifactPath,
      attackClass: 'UNICODE-STEGO',
      confidence: inCode ? 0.85 : 0.6,
      evidence: `Soft hyphens at lines: ${softHyphens.slice(0, 5).map(c => `L${c.line}`).join(', ')}`,
    });
  }

  // ── Word Joiners (suspicious in configs) ──
  if (wordJoiners.length > 0) {
    findings.push({
      checkId: 'UNICODE-STEGO-001',
      name: 'Word Joiners Detected',
      description: `Found ${wordJoiners.length} word joiner(s)`,
      category: 'unicode-stego',
      severity: wordJoiners.length > 5 ? 'high' : 'medium',
      passed: false,
      message: `${wordJoiners.length} word joiner characters detected - may encode hidden data`,
      fixable: false,
      file: ast.artifactPath,
      attackClass: 'UNICODE-STEGO',
      confidence: 0.80,
      evidence: `Word joiners at lines: ${wordJoiners.slice(0, 5).map(c => `L${c.line}`).join(', ')}`,
    });
  }

  return findings;
}
