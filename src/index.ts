/**
 * hackmyagent — Find it. Break it. Fix it.
 * Unified security toolkit for AI agents.
 */

export const VERSION = '0.8.0';

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

// Shell & MCP checks
export { checkShellEnvironment, checkShellHistory } from './hardening';
export { discoverMcpConfigs, classifyTools, checkMcpToolEnumeration } from './hardening';
export type { McpServerConfig, McpToolInfo, McpServerResult } from './hardening';

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
  parseCustomPayloads,
  shouldFail,
  MCP_EXPLOITATION_PAYLOADS,
  A2A_ATTACK_PAYLOADS,
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
  CustomPayloadInput,
  CustomPayloadFile,
  FailPolicy,
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

// OASB v2 Behavioral Governance (domains 7-14)
export {
  ALL_GOVERNANCE_CONTROLS,
  DOMAIN_METADATA,
  getControlsByDomain,
  getControlById,
  getControlsForTier,
  getControlsBySeverity,
  analyzeStructure,
  detectGovernanceControls,
  detectSingleControl,
  PASS_THRESHOLD,
  computeGovernanceScore,
  scoreToGrade,
  detectTier,
  getTierLabel,
  getTierLevel,
  getRemediation,
  getRemediations,
  getAllRemediations,
  getRemediationCount,
  getRemediationIds,
} from './abgr';

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
  StructuralInfo,
} from './abgr';

// Registry module
export {
  RegistryClient,
  buildScanReport,
  buildAttackReport,
  buildCommunityReport,
  buildCommunityAttackReport,
} from './registry';

export type {
  RegistryConfig,
  RegistryPackage,
  ScanReportPayload,
  CommunityScanPayload,
} from './registry';

// Anonymous contribution
export {
  hashArtifact,
  generateContributionId,
  extractFindingIds,
  countBySeverity,
  buildHardeningContribution,
  buildGovernanceContribution,
  buildMcpContribution,
  buildAttackContribution,
  submitContribution,
} from './registry';

export type {
  ContributionType,
  ContributionPayload,
} from './registry';

// Semantic engine (Layer 2 + Layer 3 analysis)
export {
  StructuralAnalyzer,
  CredentialContextAnalyzer,
  McpConfigAnalyzer,
  InstructionAnalyzer,
  PermissionModelAnalyzer,
  LLMAnalyzer,
  AnthropicClient,
  LLMCache,
  BudgetTracker,
  toSecurityFinding,
  toSecurityFindings,
  SEMANTIC_OASB_MAPPINGS,
  CostEstimator,
  buildDeepScanResult,
} from './semantic';

// Plugin system
export {
  registerPlugin,
  getPlugin,
  listPlugins,
  clearRegistry,
} from './plugins/core';

export type {
  OpenA2APlugin,
  PluginMetadata,
  Finding as PluginFinding,
  Remediation,
  FixOptions,
  PluginStatus,
  PluginInitOptions,
} from './plugins/core';

// OpenClaw plugins
export { createPlugin as createCredVaultPlugin } from './plugins/credvault';
export { createPlugin as createSigncryptPlugin } from './plugins/signcrypt';
export { createPlugin as createSkillguardPlugin } from './plugins/skillguard';

// Agent Runtime Protection
export { AgentRuntimeProtection } from './arp';

// Legacy scanner (for scan command)
export interface ScanResult {
  target: string;
  findings: LegacyFinding[];
  timestamp: Date;
}

export interface LegacyFinding {
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
    return {
      target,
      findings: [],
      timestamp: new Date(),
    };
  }
}
