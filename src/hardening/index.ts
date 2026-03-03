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

// Shell environment and history checks
export { checkShellEnvironment, checkShellHistory } from './shell-checks';

// MCP tool enumeration
export {
  discoverMcpConfigs,
  enumerateStdioTools,
  classifyTools,
  checkMcpToolEnumeration,
} from './mcp-tool-enum';

export type {
  McpServerConfig,
  McpToolInfo,
  McpServerResult,
} from './mcp-tool-enum';
