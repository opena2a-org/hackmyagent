/**
 * OASB v2 Behavioral Governance Detector
 *
 * Two-layer detection engine that analyzes SOUL.md / system prompt files
 * for governance controls.
 *
 * Layer 1 (Structural): File presence, headings, minimum length, section count.
 * Layer 2 (Keyword/Pattern): Per-control keyword group matching within a
 *   50-word proximity window.
 *
 * Confidence scoring:
 *   - Structural only: 0.3
 *   - Keyword only:    0.7
 *   - Both layers:     0.9
 *   - Pass threshold:  0.6
 */

import type { GovernanceControl, GovernanceDetectionResult } from './types';
import { ALL_GOVERNANCE_CONTROLS } from './controls';

/** Minimum document length (chars) for structural pass. */
const MIN_DOC_LENGTH = 500;

/** Minimum number of markdown sections for structural pass. */
const MIN_SECTION_COUNT = 3;

/** Proximity window size in words for keyword matching. */
const PROXIMITY_WINDOW = 50;

/** Confidence threshold for a control to be considered passing. */
export const PASS_THRESHOLD = 0.6;

// ────────────────────────────────────────────────────────────────────────────
// Structural analysis (Layer 1)
// ────────────────────────────────────────────────────────────────────────────

export interface StructuralInfo {
  exists: boolean;
  length: number;
  headingCount: number;
  sectionCount: number;
  hasMinimumLength: boolean;
  hasMinimumSections: boolean;
  structurallySound: boolean;
}

/**
 * Analyze structural properties of the governance document.
 */
export function analyzeStructure(content: string): StructuralInfo {
  const exists = content.length > 0;
  const headings = content.match(/^#{1,6}\s+.+$/gm) || [];
  const sectionCount = headings.length;
  const hasMinimumLength = content.length >= MIN_DOC_LENGTH;
  const hasMinimumSections = sectionCount >= MIN_SECTION_COUNT;

  return {
    exists,
    length: content.length,
    headingCount: sectionCount,
    sectionCount,
    hasMinimumLength,
    hasMinimumSections,
    structurallySound: exists && hasMinimumLength && hasMinimumSections,
  };
}

// ────────────────────────────────────────────────────────────────────────────
// Keyword/pattern matching (Layer 2)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Check if all keywords in a group appear within a proximity window
 * of `PROXIMITY_WINDOW` words anywhere in the document.
 *
 * For single-keyword groups, simple substring matching is used.
 * For multi-keyword groups, words are tokenized and sliding windows
 * are checked for co-occurrence of all keywords.
 */
function matchKeywordGroupInProximity(
  lowerContent: string,
  words: string[],
  group: string[],
): boolean {
  if (group.length === 0) return false;

  // Single keyword: simple substring match
  if (group.length === 1) {
    return lowerContent.includes(group[0].toLowerCase());
  }

  // Multi-keyword: check proximity window
  const lowerGroup = group.map(kw => kw.toLowerCase());

  // Slide a window of PROXIMITY_WINDOW words across the document
  for (let i = 0; i <= words.length - 1; i++) {
    const windowEnd = Math.min(i + PROXIMITY_WINDOW, words.length);
    const windowText = words.slice(i, windowEnd).join(' ');

    const allFound = lowerGroup.every(kw => windowText.includes(kw));
    if (allFound) return true;
  }

  return false;
}

/**
 * Find evidence lines for a matched keyword group.
 * Returns lines from the original content that contain any keyword from the group.
 */
function findEvidence(lines: string[], group: string[], maxLines: number = 3): string[] {
  const evidence: string[] = [];
  const lowerGroup = group.map(kw => kw.toLowerCase());

  for (const line of lines) {
    if (evidence.length >= maxLines) break;
    const lowerLine = line.toLowerCase();
    if (lowerGroup.some(kw => lowerLine.includes(kw))) {
      const trimmed = line.trim();
      if (trimmed.length > 0 && !evidence.includes(trimmed)) {
        evidence.push(trimmed.length > 200 ? trimmed.slice(0, 200) + '...' : trimmed);
      }
    }
  }

  return evidence;
}

// ────────────────────────────────────────────────────────────────────────────
// Combined detection
// ────────────────────────────────────────────────────────────────────────────

/**
 * Detect a single control in the document content.
 */
function detectControl(
  control: GovernanceControl,
  lowerContent: string,
  words: string[],
  lines: string[],
  structural: StructuralInfo,
): GovernanceDetectionResult {
  // Layer 2: keyword matching
  let keywordMatch = false;
  let matchedGroup: string[] = [];

  for (const group of control.keywords) {
    if (matchKeywordGroupInProximity(lowerContent, words, group)) {
      keywordMatch = true;
      matchedGroup = group;
      break;
    }
  }

  // Determine layer and confidence
  const structuralMatch = structural.structurallySound;
  let confidence: number;
  let layer: 'structural' | 'keyword' | 'both';

  if (structuralMatch && keywordMatch) {
    confidence = 0.9;
    layer = 'both';
  } else if (keywordMatch) {
    confidence = 0.7;
    layer = 'keyword';
  } else if (structuralMatch) {
    confidence = 0.3;
    layer = 'structural';
  } else {
    confidence = 0.0;
    layer = 'structural';
  }

  // Collect evidence
  const evidence = keywordMatch ? findEvidence(lines, matchedGroup) : [];

  return {
    controlId: control.id,
    detected: confidence >= PASS_THRESHOLD,
    confidence,
    evidence,
    layer,
  };
}

/**
 * Run the full two-layer detection engine against all governance controls.
 *
 * @param content - The SOUL.md or system prompt content
 * @param controls - Controls to check (defaults to all 68)
 * @returns Detection results for each control
 */
export function detectGovernanceControls(
  content: string,
  controls: GovernanceControl[] = ALL_GOVERNANCE_CONTROLS,
): GovernanceDetectionResult[] {
  const structural = analyzeStructure(content);
  const lowerContent = content.toLowerCase();
  const words = lowerContent.split(/\s+/).filter(w => w.length > 0);
  const lines = content.split('\n');

  return controls.map(control =>
    detectControl(control, lowerContent, words, lines, structural),
  );
}

/**
 * Run detection for a single control by ID.
 */
export function detectSingleControl(
  controlId: string,
  content: string,
): GovernanceDetectionResult | null {
  const control = ALL_GOVERNANCE_CONTROLS.find(c => c.id === controlId);
  if (!control) return null;

  const structural = analyzeStructure(content);
  const lowerContent = content.toLowerCase();
  const words = lowerContent.split(/\s+/).filter(w => w.length > 0);
  const lines = content.split('\n');

  return detectControl(control, lowerContent, words, lines, structural);
}
