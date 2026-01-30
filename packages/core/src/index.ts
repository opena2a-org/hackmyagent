/**
 * @hackmyagent/core
 * Core library for HackMyAgent security scanning
 */

export const VERSION = '0.1.0';

// Checker module
export {
  checkSkill,
  parseSkillIdentifier,
  analyzePermissions,
} from './checker';

export type {
  CheckResult,
  CheckOptions,
  PublisherInfo,
  PermissionInfo,
  RevocationInfo,
  RiskLevel,
  SkillIdentifier,
  PermissionAnalysis,
} from './checker';

// Hardening module
export { HardeningScanner } from './hardening';
export type { ScanOptions, SecurityFinding, Severity } from './hardening';

// External scanner module
export { ExternalScanner } from './scanner';
export type {
  ExternalScanResult,
  ExternalFinding,
  ScannerOptions,
  FindingSeverity,
} from './scanner';

// Legacy scanner (for scan command)
export interface ScanResult {
  target: string;
  findings: Finding[];
  timestamp: Date;
}

export interface Finding {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
}

export function createScanner(): Scanner {
  return new Scanner();
}

export class Scanner {
  async scan(target: string): Promise<ScanResult> {
    // Placeholder implementation
    return {
      target,
      findings: [],
      timestamp: new Date(),
    };
  }
}
