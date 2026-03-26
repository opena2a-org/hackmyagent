/**
 * Semantic analysis engine
 *
 * Semantic analysis engine for AI agent security scanning.
 * Provides Layer 2 (structural) and Layer 3 (LLM) analysis.
 *
 * Zero runtime dependencies. Imported by core scanner and MCP server.
 */

// Layer 2: Structural Analysis
export { StructuralAnalyzer } from './structural';
export {
  CredentialContextAnalyzer,
  McpConfigAnalyzer,
  InstructionAnalyzer,
  PermissionModelAnalyzer,
} from './structural';

// Layer 3: LLM Analysis
export { LLMAnalyzer, AnthropicClient, LLMCache, BudgetTracker } from './llm';

// Integration
export { toSecurityFinding, toSecurityFindings } from './integration/finding-adapter';
export { SEMANTIC_OASB_MAPPINGS, getSemanticCheckIds, getUpgradedControlIds } from './integration/oasb-upgrader';
export { CostEstimator } from './integration/cost-estimator';

// Layer 4: NanoMind Local Semantic Analysis (--semantic flag)
export {
  isDaemonAvailable,
  analyzeSkillIntent,
  analyzeSoulCompleteness,
  analyzeMCPScope,
  analyzePromptIntent,
  explainFinding,
} from './nanomind-analyzer';
export type {
  NanoMindInferRequest,
  NanoMindInferResponse,
  SemanticFinding as NanoMindFinding,
} from './nanomind-analyzer';

// Deep scan builder (for MCP server)
export { buildDeepScanResult } from './deep-scan';

// Types
export type {
  SemanticFinding,
  SemanticSeverity,
  SemanticCategory,
  AnalysisContext,
  AnalysisFile,
  FileType,
  ExistingFinding,
  LLMAnalysisOptions,
  CostEstimate,
  DeepScanResult,
  DeepAnalysisFile,
  McpServerConfig,
  McpConfigFile,
  ClaudeSettings,
} from './types';
