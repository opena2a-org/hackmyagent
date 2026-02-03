/**
 * Security check types and interfaces
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low';

/**
 * Project types for filtering relevant checks
 * - cli: Command-line tools (bin field in package.json)
 * - library: NPM packages for use by other code
 * - webapp: Web applications (React, Vue, etc.)
 * - api: Backend API servers (Express, Fastify, etc.)
 * - mcp: MCP server implementations
 * - openclaw: OpenClaw AI agent projects (SKILL.md, HEARTBEAT.md)
 * - all: Applies to all project types
 */
export type ProjectType = 'cli' | 'library' | 'webapp' | 'api' | 'mcp' | 'openclaw' | 'all';

export interface SecurityCheck {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: Severity;
  /** Function to detect if the issue exists */
  detect: () => Promise<CheckResult>;
  /** Function to fix the issue (if auto-fixable) */
  fix?: () => Promise<FixResult>;
}

export interface CheckResult {
  passed: boolean;
  message: string;
  details?: Record<string, unknown>;
}

export interface FixResult {
  success: boolean;
  message: string;
  details?: Record<string, unknown>;
}

export interface SecurityFinding {
  checkId: string;
  name: string;
  description: string;
  category: string;
  severity: Severity;
  passed: boolean;
  message: string;
  fixable: boolean;
  fixed?: boolean;
  fixMessage?: string;
  /** Set in dry-run mode to indicate this would be fixed */
  wouldFix?: boolean;
  /** File path where the issue was found (relative to scan directory) */
  file?: string;
  /** Line number in the file where the issue was found */
  line?: number;
  /** Specific fix instruction for this issue */
  fix?: string;
  details?: Record<string, unknown>;
}

export interface ScanResult {
  timestamp: Date;
  platform: string;
  /** Detected project type */
  projectType: ProjectType;
  findings: SecurityFinding[];
  score: number;
  maxScore: number;
  /** Path to backup directory (only set when autoFix is true and not dryRun) */
  backupPath?: string;
  /** True if this was a dry-run (no changes made) */
  dryRun?: boolean;
  /** True if all fixes completed atomically (or rolled back on failure) */
  atomicFix?: boolean;
  /** List of check IDs that were ignored */
  ignored?: string[];
}
