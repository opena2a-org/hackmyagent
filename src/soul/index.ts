/**
 * Soul module - Behavioral Governance Scanner
 */

export { SoulScanner, CONTROL_DEFS, DOMAIN_ORDER, GOVERNANCE_FILES, GOVERNANCE_CATALOG_SIZE, PROFILE_DOMAINS } from './scanner';
export type {
  AgentTier,
  AgentProfile,
  SoulGrade,
  SoulLevel,
  ControlCheck,
  DomainResult,
  SoulScanResult,
  HardenResult,
} from './scanner';
export { DOMAIN_TEMPLATES } from './templates';
export type { DomainTemplate } from './templates';
