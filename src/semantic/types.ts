/**
 * Semantic Analysis Engine Types
 *
 * Types shared across Layer 2 (structural) and Layer 3 (LLM) analysis.
 * These are internal to the semantic engine — the integration layer
 * converts SemanticFinding → SecurityFinding for the core scanner.
 */

export type SemanticSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type SemanticCategory =
  | 'credential'      // SEM-CRED-*
  | 'mcp-config'      // SEM-MCP-*
  | 'instruction'     // SEM-INST-*
  | 'permission';     // SEM-PERM-*

export interface SemanticFinding {
  /** Check ID (e.g., SEM-CRED-001) */
  id: string;
  /** Short title */
  title: string;
  /** Detailed description of the finding */
  description: string;
  /** Why this is a threat */
  rationale: string;
  /** Category for grouping */
  category: SemanticCategory;
  severity: SemanticSeverity;
  /** Relative file path where the issue was found */
  file: string;
  /** Line number (1-based), if applicable */
  line?: number;
  /** Specific fix recommendation */
  recommendation: string;
  /** Which analysis layer found this */
  layer: 2 | 3;
  /** Whether this can be auto-fixed */
  autoFixable: boolean;
}

export interface AnalysisContext {
  /** Root directory being analyzed */
  targetDir: string;
  /** Files discovered for analysis, keyed by category */
  files: AnalysisFile[];
  /** Findings from Layer 1 (regex) — used as context for deeper analysis */
  existingFindings?: ExistingFinding[];
}

export interface AnalysisFile {
  /** Relative path from targetDir */
  path: string;
  /** File type classification */
  type: FileType;
  /** File content (truncated if over maxContentSize) */
  content: string;
  /** Whether content was truncated */
  truncated: boolean;
}

export type FileType =
  | 'agent_instructions'    // CLAUDE.md, .cursorrules, .windsurfrules, copilot-instructions.md
  | 'mcp_config'            // mcp.json, .cursor/mcp.json, .vscode/mcp.json
  | 'claude_settings'       // .claude/settings.json
  | 'env_file'              // .env, .env.local
  | 'config_file'           // config.json, settings.json, etc.
  | 'other';

export interface ExistingFinding {
  checkId: string;
  severity: string;
  file?: string;
  message: string;
}

export interface LLMAnalysisOptions {
  /** Anthropic API key for standalone CLI mode */
  apiKey: string;
  /** Max daily spend in USD (default: 1.0) */
  budgetCap?: number;
  /** Cache directory (default: .hackmyagent-cache/) */
  cacheDir?: string;
  /** Progress callback */
  onProgress?: (message: string) => void;
}

export interface CostEstimate {
  /** Number of files to analyze */
  fileCount: number;
  /** Estimated total input tokens */
  estimatedInputTokens: number;
  /** Estimated total output tokens */
  estimatedOutputTokens: number;
  /** Estimated cost in USD */
  estimatedCostUsd: number;
  /** Number of files that have cached results */
  cachedFiles: number;
}

export interface DeepScanResult {
  /** Layer 1+2 findings from automated analysis */
  layer1Findings: ExistingFinding[];
  layer2Findings: SemanticFinding[];
  /** Security-relevant files with analysis guidance for the host LLM */
  filesForDeepAnalysis: DeepAnalysisFile[];
  /** Overall guidance for the host LLM */
  overallGuidance: string;
}

export interface DeepAnalysisFile {
  /** Relative file path */
  path: string;
  /** File type classification */
  type: FileType;
  /** File content (truncated to ~4KB) */
  content: string;
  /** Per-file analysis guidance */
  analysisGuidance: string;
}

/**
 * MCP config structure for parsing
 */
export interface McpServerConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  allowedTools?: string[];
  allowedCommands?: string[];
}

export interface McpConfigFile {
  mcpServers?: Record<string, McpServerConfig>;
}

/**
 * Claude settings structure
 */
export interface ClaudeSettings {
  permissions?: {
    allow?: string[];
    deny?: string[];
  };
  mcpServers?: Record<string, McpServerConfig>;
}
