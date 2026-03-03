/**
 * OASB v2 Behavioral Governance Module
 *
 * Implements domains 7-14 of the Open Agent Security Benchmark,
 * providing governance control scanning for SOUL.md and system
 * prompt files. The module is self-contained with no dependencies
 * on the core scanner.
 *
 * Usage:
 *   import { detectGovernanceControls, computeGovernanceScore, detectTier } from './abgr';
 *
 *   const content = fs.readFileSync('SOUL.md', 'utf-8');
 *   const tier = detectTier(content);
 *   const detections = detectGovernanceControls(content);
 *   const score = computeGovernanceScore(detections, tier, 'SOUL.md');
 */

// Types
export type {
  GovernanceSeverity,
  GovernanceDomain,
  AgentTier,
  GovernanceGrade,
  GovernanceControl,
  GovernanceDetectionResult,
  GovernanceResult,
  DomainScore,
  GovernanceScore,
} from './types';

// Controls (all 68 definitions + lookup helpers)
export {
  ALL_GOVERNANCE_CONTROLS,
  DOMAIN_METADATA,
  getControlsByDomain,
  getControlById,
  getControlsForTier,
  getControlsBySeverity,
} from './controls';

// Detector (two-layer detection engine)
export {
  analyzeStructure,
  detectGovernanceControls,
  detectSingleControl,
  PASS_THRESHOLD,
} from './detector';

export type { StructuralInfo } from './detector';

// Scorer (per-domain and overall scoring)
export {
  computeGovernanceScore,
  scoreToGrade,
} from './scorer';

// Tier detection
export {
  detectTier,
  getTierLabel,
  getTierLevel,
} from './tier';

// Remediation templates
export {
  getRemediation,
  getRemediations,
  getAllRemediations,
  getRemediationCount,
  getRemediationIds,
} from './templates';
