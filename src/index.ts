/**
 * hackmyagent — Find it. Break it. Fix it.
 * Unified security toolkit for AI agents.
 */

export const VERSION = '0.11.7';

// Checker module
export {
  checkSkill,
  parseSkillIdentifier,
  analyzePermissions,
  analyzeSkillDependencies,
  buildDependencyGraph,
  detectCircularDeps,
  detectPhantomDeps,
  detectUnpinnedDeps,
  parseSkillFrontmatter,
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
  SkillMetadata,
  DependencyGraph,
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

// Hardening sub-modules
export { classifySkillSection, isLikelyFalsePositive } from './hardening';
export type { SkillSection } from './hardening';
export {
  parseDeclaredCapabilities as parseSkillDeclaredCapabilities,
  inferActualCapabilities,
  validateCapabilities,
} from './hardening';
export type { SkillDeclaredCapabilities, InferredCapability } from './hardening';

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
  MEMORY_WEAPONIZATION_PAYLOADS,
  CONTEXT_WINDOW_PAYLOADS,
  SUPPLY_CHAIN_PAYLOADS,
  TOOL_SHADOW_PAYLOADS,
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

// Registry module
export {
  RegistryClient,
  buildScanReport,
  buildAttackReport,
  buildCommunityReport,
  buildCommunityAttackReport,
  // ATP Publish flow
  readAgentKeypair,
  signPayload,
  buildPublishPayload,
  publishScanResults,
  formatPublishOutput,
} from './registry';

export type {
  RegistryConfig,
  RegistryPackage,
  ScanReportPayload,
  CommunityScanPayload,
  AgentKeypair,
  PublishScanData,
  PublishResult,
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
export { SkillCapabilityMonitor, createCapabilityMonitor, parseDeclaredCapabilities } from './arp';
export type { DeclaredCapabilities, ObservedBehavior, CapabilityViolation } from './arp';

// Soul module (Behavioral Governance Scanner)
export { SoulScanner, CONTROL_DEFS, DOMAIN_ORDER, GOVERNANCE_FILES, PROFILE_DOMAINS } from './soul';
export type {
  AgentTier,
  AgentProfile,
  SoulGrade,
  SoulLevel,
  ControlCheck,
  DomainResult,
  SoulScanResult,
  HardenResult,
} from './soul';
export { DOMAIN_TEMPLATES } from './soul';
export type { DomainTemplate } from './soul';

// Telemetry — community contribution of anonymized scan findings
export {
  generateContributorToken,
  getContributorToken,
  buildScanEvent,
  buildContributionPayloadFromDir,
  queueEvent,
  queueAndMaybeFlush,
  flushQueue,
  submitContribution,
  isContributeEnabled,
  shouldPromptContribute,
  incrementScanCount,
  saveContributeChoice,
  showContributePrompt,
  recordScanAndMaybeShowTip,
} from './telemetry';

export type {
  ContributionEvent,
  ContributionBatch,
} from './telemetry';

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
