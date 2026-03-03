/**
 * MCP Tool Enumeration (MCPTOOL-001 to MCPTOOL-005)
 *
 * Connects to configured MCP servers, discovers their tools via JSON-RPC,
 * and classifies dangerous capabilities. Only runs with --deep or --live-mcp flag.
 */

import { spawn, type ChildProcess } from 'child_process';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import type { SecurityFinding, Severity } from './security-check';

export interface McpServerConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string; // For SSE servers
}

export interface McpToolInfo {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface McpServerResult {
  serverName: string;
  configPath: string;
  tools: McpToolInfo[];
  error?: string;
}

// Dangerous capability classification
const EXECUTION_TOOLS = new Set([
  'execute_command', 'bash', 'shell', 'run_command', 'exec',
  'run_script', 'terminal', 'execute', 'run', 'system',
  'execute_shell', 'run_shell', 'subprocess',
]);

const FILESYSTEM_WRITE_TOOLS = new Set([
  'write_file', 'create_file', 'delete_file', 'edit_file',
  'write', 'remove_file', 'mkdir', 'rename_file', 'move_file',
  'append_file', 'overwrite_file', 'file_write',
]);

const NETWORK_TOOLS = new Set([
  'fetch', 'http_request', 'curl', 'wget', 'request',
  'http_get', 'http_post', 'web_request', 'send_request',
  'make_request', 'api_call',
]);

const CREDENTIAL_TOOLS = new Set([
  'get_secret', 'read_env', 'get_credential', 'get_password',
  'read_secret', 'fetch_secret', 'env_var', 'get_token',
  'read_keychain', 'get_api_key',
]);

const SPAWN_TIMEOUT_MS = 5_000;
const JSON_RPC_VERSION = '2.0';

/**
 * Discover MCP server configurations from known config file locations.
 */
export async function discoverMcpConfigs(
  targetDir: string,
): Promise<Map<string, { config: McpServerConfig; configPath: string }>> {
  const configs = new Map<string, { config: McpServerConfig; configPath: string }>();

  const configPaths = [
    path.join(targetDir, 'mcp.json'),
    path.join(targetDir, '.cursor', 'mcp.json'),
    path.join(targetDir, '.vscode', 'mcp.json'),
    path.join(os.homedir(), '.claude', 'settings.json'),
  ];

  for (const configPath of configPaths) {
    try {
      const content = await fs.readFile(configPath, 'utf-8');
      const parsed = JSON.parse(content);

      // Handle different config formats
      const servers = parsed.mcpServers || parsed.servers || {};

      for (const [name, serverConfig] of Object.entries(servers)) {
        const config = serverConfig as Record<string, unknown>;
        if (config.command || config.url) {
          configs.set(name, {
            config: {
              command: config.command as string,
              args: config.args as string[] | undefined,
              env: config.env as Record<string, string> | undefined,
              url: config.url as string | undefined,
            },
            configPath,
          });
        }
      }
    } catch {
      // Config file doesn't exist or is invalid, skip
    }
  }

  return configs;
}

/**
 * Connect to a stdio MCP server and enumerate its tools.
 */
export async function enumerateStdioTools(
  serverName: string,
  config: McpServerConfig,
): Promise<McpServerResult> {
  return new Promise((resolve) => {
    let child: ChildProcess | null = null;
    let buffer = '';
    let resolved = false;

    const cleanup = () => {
      if (child && !child.killed) {
        child.kill('SIGTERM');
      }
    };

    const finish = (result: McpServerResult) => {
      if (!resolved) {
        resolved = true;
        cleanup();
        resolve(result);
      }
    };

    // Timeout
    const timer = setTimeout(() => {
      finish({ serverName, configPath: '', tools: [], error: 'Timeout after 5s' });
    }, SPAWN_TIMEOUT_MS);

    try {
      child = spawn(config.command, config.args || [], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env, ...config.env },
      });

      child.on('error', (err) => {
        clearTimeout(timer);
        finish({ serverName, configPath: '', tools: [], error: err.message });
      });

      child.stdout?.on('data', (data: Buffer) => {
        buffer += data.toString();

        // Try to parse JSON-RPC responses
        const lines = buffer.split('\n');
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;

          try {
            const msg = JSON.parse(trimmed);

            // Response to initialize
            if (msg.id === 1 && msg.result) {
              // Send tools/list
              const toolsRequest = JSON.stringify({
                jsonrpc: JSON_RPC_VERSION,
                id: 2,
                method: 'tools/list',
                params: {},
              }) + '\n';
              child?.stdin?.write(toolsRequest);
            }

            // Response to tools/list
            if (msg.id === 2 && msg.result) {
              clearTimeout(timer);
              const tools: McpToolInfo[] = (msg.result.tools || []).map(
                (t: Record<string, unknown>) => ({
                  name: t.name as string,
                  description: t.description as string | undefined,
                  inputSchema: t.inputSchema as Record<string, unknown> | undefined,
                }),
              );
              finish({ serverName, configPath: '', tools });
            }
          } catch {
            // Not valid JSON, skip
          }
        }
        // Keep only the last incomplete line in buffer
        buffer = lines[lines.length - 1] || '';
      });

      // Send initialize request
      const initRequest = JSON.stringify({
        jsonrpc: JSON_RPC_VERSION,
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'hackmyagent-scanner', version: '0.8.0' },
        },
      }) + '\n';
      child.stdin?.write(initRequest);
    } catch (err) {
      clearTimeout(timer);
      finish({ serverName, configPath: '', tools: [], error: (err as Error).message });
    }
  });
}

/**
 * Classify tool capabilities and generate security findings.
 */
export function classifyTools(
  serverName: string,
  configPath: string,
  tools: McpToolInfo[],
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // MCPTOOL-001: Execution tools
  const execTools = tools.filter((t) => EXECUTION_TOOLS.has(t.name.toLowerCase()));
  if (execTools.length > 0) {
    findings.push({
      checkId: 'MCPTOOL-001',
      name: 'MCP server exposes command execution',
      description: `MCP server "${serverName}" provides tools that can execute arbitrary commands: ${execTools.map((t) => t.name).join(', ')}. This allows the AI to run any system command.`,
      category: 'mcp-capability',
      severity: 'critical' as Severity,
      passed: false,
      message: `${serverName}: ${execTools.length} execution tool(s) exposed`,
      fixable: false,
      file: configPath,
      fix: 'Restrict command execution tools or add an allowlist of permitted commands.',
    });
  }

  // MCPTOOL-002: Filesystem write tools
  const fsWriteTools = tools.filter((t) => FILESYSTEM_WRITE_TOOLS.has(t.name.toLowerCase()));
  if (fsWriteTools.length > 0) {
    findings.push({
      checkId: 'MCPTOOL-002',
      name: 'MCP server exposes filesystem write',
      description: `MCP server "${serverName}" provides tools that can write/delete files: ${fsWriteTools.map((t) => t.name).join(', ')}. This allows modifying system files.`,
      category: 'mcp-capability',
      severity: 'high' as Severity,
      passed: false,
      message: `${serverName}: ${fsWriteTools.length} filesystem write tool(s) exposed`,
      fixable: false,
      file: configPath,
      fix: 'Add path restrictions to filesystem write tools.',
    });
  }

  // MCPTOOL-003: Unrestricted network tools
  const netTools = tools.filter((t) => NETWORK_TOOLS.has(t.name.toLowerCase()));
  if (netTools.length > 0) {
    findings.push({
      checkId: 'MCPTOOL-003',
      name: 'MCP server exposes unrestricted network access',
      description: `MCP server "${serverName}" provides tools for network requests: ${netTools.map((t) => t.name).join(', ')}. This allows data exfiltration.`,
      category: 'mcp-capability',
      severity: 'high' as Severity,
      passed: false,
      message: `${serverName}: ${netTools.length} network tool(s) exposed`,
      fixable: false,
      file: configPath,
      fix: 'Restrict network access to specific domains or add an allowlist.',
    });
  }

  // MCPTOOL-004: Credential-accessing tools
  const credTools = tools.filter((t) => CREDENTIAL_TOOLS.has(t.name.toLowerCase()));
  if (credTools.length > 0) {
    findings.push({
      checkId: 'MCPTOOL-004',
      name: 'MCP server exposes credential access',
      description: `MCP server "${serverName}" provides tools that access credentials: ${credTools.map((t) => t.name).join(', ')}.`,
      category: 'mcp-capability',
      severity: 'critical' as Severity,
      passed: false,
      message: `${serverName}: ${credTools.length} credential-accessing tool(s) exposed`,
      fixable: false,
      file: configPath,
      fix: 'Remove credential access tools or use secretless-ai broker for credential isolation.',
    });
  }

  // MCPTOOL-005: Server with 10+ tools and no apparent access control
  if (tools.length >= 10) {
    findings.push({
      checkId: 'MCPTOOL-005',
      name: 'MCP server exposes excessive tools',
      description: `MCP server "${serverName}" exposes ${tools.length} tools. Large tool surfaces increase the attack area for prompt injection.`,
      category: 'mcp-capability',
      severity: 'medium' as Severity,
      passed: false,
      message: `${serverName}: ${tools.length} tools exposed (threshold: 10)`,
      fixable: false,
      file: configPath,
      fix: 'Reduce the number of exposed tools or implement per-tool access controls.',
    });
  }

  return findings;
}

/**
 * Run full MCP tool enumeration scan.
 * Discovers MCP configs, connects to each server, enumerates tools, classifies dangers.
 */
export async function checkMcpToolEnumeration(
  targetDir: string,
  onProgress?: (message: string) => void,
): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];

  const configs = await discoverMcpConfigs(targetDir);
  if (configs.size === 0) return findings;

  onProgress?.(`Found ${configs.size} MCP server(s), enumerating tools...`);

  for (const [serverName, { config, configPath }] of configs) {
    onProgress?.(`Scanning ${serverName}...`);

    if (config.command) {
      const result = await enumerateStdioTools(serverName, config);
      if (result.error) {
        // Non-fatal: server couldn't be reached
        onProgress?.(`  ${serverName}: ${result.error}`);
        continue;
      }

      const serverFindings = classifyTools(serverName, configPath, result.tools);
      findings.push(...serverFindings);

      onProgress?.(
        `  ${serverName}: ${result.tools.length} tools, ${serverFindings.length} findings`,
      );
    }
    // SSE servers would go here (future)
  }

  return findings;
}
