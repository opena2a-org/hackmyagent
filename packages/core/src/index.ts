/**
 * @hackmyagent/core
 * Core library for HackMyAgent security scanning
 */

export const VERSION = '0.3.6';

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

// Attack module
export { AttackScanner } from './attack';

export {
  ATTACK_CATEGORIES,
  ALL_PAYLOADS,
  PAYLOAD_STATS,
  getPayloads,
  getPayloadById,
  getPayloadsByCategory,
  getPayloadsByIntensity,
} from './attack';

export type {
  AttackCategory,
  AttackIntensity,
  AttackSeverity,
  AttackPayload,
  AttackResult,
  AttackReport,
  AttackTarget,
  AttackOptions,
} from './attack';

// Benchmarks module
export {
  OASB_1_CATEGORIES,
  OASB_1_VERSION,
  OASB_1_NAME,
  getControlsForLevel,
  getControlsForCategory,
  getCheckIdsForLevel,
  calculateRating,
  AVAILABLE_BENCHMARKS,
  isValidBenchmark,
} from './benchmarks';

export type {
  BenchmarkLevel,
  BenchmarkControl,
  BenchmarkCategory,
  BenchmarkResult,
  BenchmarkCategoryResult,
  BenchmarkControlResult,
  BenchmarkName,
} from './benchmarks';

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
