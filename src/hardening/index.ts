/**
 * Hardening module
 */

export { HardeningScanner, calculateSecurityScore } from './scanner';
export type { ScanOptions, ScanDepth } from './scanner';

// The `.hmaignore` grammar: one parser, one matcher and one scope predicate,
// exported so a dependent tool reads the file the way `secure` and `check` do.
export { parseHmaIgnore, matchHmaIgnore } from './scanner';
export type {
  HmaIgnoreRule,
  HmaIgnoreParseError,
  ParsedHmaIgnore,
  HmaIgnoreMatch,
} from './scanner';
export { isScopeChannel } from './security-check';
export type {
  ScopeChannel,
  PresentationalChannel,
  SuppressionChannel,
} from './security-check';
/** The finding shape `matchHmaIgnore` reads, taken from its own signature. */
export type HmaIgnoreFinding = Parameters<typeof import('./scanner').matchHmaIgnore>[0];

export type {
  SecurityCheck,
  CheckResult,
  FixResult,
  SecurityFinding,
  ScanResult,
  MachinePostureSummary,
  Severity,
} from './security-check';

export { getAttackClass, enrichWithTaxonomy } from './taxonomy';
export { NemoClawScanner, NEMOCLAW_CATEGORIES } from './nemoclaw-scanner';
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
