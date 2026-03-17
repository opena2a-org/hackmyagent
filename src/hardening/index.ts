/**
 * Hardening module
 */

export { HardeningScanner } from './scanner';
export type { ScanOptions } from './scanner';

export type {
  SecurityCheck,
  CheckResult,
  FixResult,
  SecurityFinding,
  ScanResult,
  Severity,
} from './security-check';

export { getAttackClass, enrichWithTaxonomy } from './taxonomy';
export { classifySkillSection, isLikelyFalsePositive } from './skill-context';
export type { SkillSection } from './skill-context';
export {
  parseDeclaredCapabilities,
  inferActualCapabilities,
  validateCapabilities,
} from './skill-capability-validator';
export type {
  SkillDeclaredCapabilities,
  InferredCapability,
} from './skill-capability-validator';
