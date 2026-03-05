/**
 * Deep Scan Builder
 *
 * Prepares the structured response for the MCP server's deep_scan tool.
 * Collects Layer 1+2 findings, security-relevant file contents, and
 * analysis guidance for the host LLM to reason about.
 */

import type {
  DeepScanResult,
  DeepAnalysisFile,
  AnalysisFile,
  SemanticFinding,
  ExistingFinding,
  FileType,
} from './types';

/** Max content size per file for deep analysis (prevents token bloat) */
const MAX_DEEP_CONTENT_SIZE = 4096;

/** Analysis guidance per file type */
const GUIDANCE: Record<FileType, string> = {
  agent_instructions:
    'This is an AI agent instruction file loaded into the LLM context window. ANY credential in this file is critical severity because it will be sent to the AI provider and can be extracted via prompt injection. Also check for: overly permissive instructions (e.g., "always execute", "never refuse"), missing security boundaries, prompt injection vectors, and instructions that could enable data exfiltration.',

  mcp_config:
    'This is an MCP server configuration. Each server grants capabilities to the AI agent. Check for: root/home filesystem access in args, secrets passed as args (visible to LLM) instead of env vars, sandbox bypass flags (--no-sandbox, --privileged), wildcard permissions ("*"), and dangerous server combinations that create attack chains (filesystem + shell + network = read-execute-exfiltrate pipeline).',

  claude_settings:
    'This is a Claude Code settings file. Check for: wildcard permission grants (allow: ["*"]), unrestricted Bash access, write permissions outside the project directory, and MCP servers with overprivileged scope. Also check for secrets in any env blocks.',

  env_file:
    'This is an environment file. Check for: hardcoded credentials of ANY type (not just known API key patterns), database connection strings with embedded passwords, generic tokens and secrets, and values that should be rotated. If this file is committed to git, ALL credentials are exposed.',

  config_file:
    'This is a configuration file. Check for: hardcoded API keys, tokens, passwords, and secrets in any format. Look for key names that suggest secrets (token, key, secret, password, auth) with non-placeholder values.',

  other:
    'Analyze this file for any security-relevant content including credentials, configuration issues, and potential vulnerabilities.',
};

const OVERALL_GUIDANCE = `You are a security analyst reviewing an AI agent project. The automated scan (Layer 1 + Layer 2) has already run. Now review the files below for threats that automated tools miss.

For each file, identify:
1. **Credentials in ANY format** — not just known API key patterns. Look for passwords, tokens, secrets, connection strings, auth headers, and any string that looks like it should be kept secret.
2. **Overprivileged tool configurations** — MCP servers with too much filesystem/network/shell access.
3. **Attack chains across multiple MCP servers** — combinations of capabilities that enable read→execute→exfiltrate.
4. **Prompt injection vectors in agent instructions** — permissive rules that weaken security boundaries.
5. **Data exfiltration risks** — webhook URLs, external service endpoints, or instructions to send data externally.

For each finding, explain:
- **WHAT** you found (be specific, include line numbers)
- **WHY** it's a threat (what could an attacker do with this?)
- **HOW** to fix it (concrete recommendation)

Severity guide:
- **critical**: High exploitation potential (exposed credentials, root filesystem access)
- **high**: Significant security gap (overprivileged access, missing boundaries)
- **medium**: Defense-in-depth issue (large attack surface, missing security terms)
- **low**: Informational / best practice recommendation`;

/**
 * Build the deep scan result for the MCP server to return to the host LLM.
 */
export function buildDeepScanResult(
  layer1Findings: ExistingFinding[],
  layer2Findings: SemanticFinding[],
  files: AnalysisFile[]
): DeepScanResult {
  const filesForDeepAnalysis: DeepAnalysisFile[] = files.map((file) => {
    const content =
      file.content.length > MAX_DEEP_CONTENT_SIZE
        ? file.content.substring(0, MAX_DEEP_CONTENT_SIZE) + '\n... (truncated)'
        : file.content;

    return {
      path: file.path,
      type: file.type,
      content,
      analysisGuidance: GUIDANCE[file.type] || GUIDANCE.other,
    };
  });

  return {
    layer1Findings,
    layer2Findings,
    filesForDeepAnalysis,
    overallGuidance: OVERALL_GUIDANCE,
  };
}
