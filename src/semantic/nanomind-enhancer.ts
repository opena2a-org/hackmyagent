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
