/**
 * HackMyAgent init-mcp Command
 *
 * Detects the user's AI coding tool and adds HackMyAgent as an MCP server.
 * Supports: Claude Code, Cursor, VS Code.
 */

import * as fs from 'fs';
import * as path from 'path';

interface McpConfig {
  mcpServers?: Record<string, {
    command: string;
    args: string[];
  }>;
}

interface InitResult {
  tool: string;
  configPath: string;
  created: boolean;
}

const HACKMYAGENT_MCP_CONFIG = {
  command: 'npx',
  args: ['-y', 'hackmyagent', 'mcp-serve'],
};

/** Config file locations, in detection priority order */
const IDE_CONFIGS: Array<{
  name: string;
  configPath: string;
  mcpKey: string;
}> = [
  {
    name: 'Claude Code',
    configPath: '.claude/settings.json',
    mcpKey: 'mcpServers',
  },
  {
    name: 'Cursor',
    configPath: '.cursor/mcp.json',
    mcpKey: 'mcpServers',
  },
  {
    name: 'VS Code',
    configPath: '.vscode/mcp.json',
    mcpKey: 'mcpServers',
  },
];

function detectIde(targetDir: string): typeof IDE_CONFIGS[number] | null {
  // Check for existing config files to detect IDE
  for (const config of IDE_CONFIGS) {
    const configFile = path.join(targetDir, config.configPath);
    if (fs.existsSync(configFile)) {
      return config;
    }
  }

  // Check for IDE-specific directories
  if (fs.existsSync(path.join(targetDir, '.claude'))) return IDE_CONFIGS[0];
  if (fs.existsSync(path.join(targetDir, '.cursor'))) return IDE_CONFIGS[1];
  if (fs.existsSync(path.join(targetDir, '.vscode'))) return IDE_CONFIGS[2];

  return null;
}

export function initMcp(targetDir: string, forceTool?: string): InitResult {
  let ideConfig: typeof IDE_CONFIGS[number] | null = null;

  if (forceTool) {
    const lower = forceTool.toLowerCase();
    ideConfig = IDE_CONFIGS.find((c) => c.name.toLowerCase().includes(lower)) || null;
    if (!ideConfig) {
      throw new Error(`Unknown tool: ${forceTool}. Supported: Claude Code, Cursor, VS Code`);
    }
  } else {
    ideConfig = detectIde(targetDir);
    if (!ideConfig) {
      // Default to Claude Code
      ideConfig = IDE_CONFIGS[0];
    }
  }

  const configFile = path.join(targetDir, ideConfig.configPath);
  const configDir = path.dirname(configFile);

  // Ensure directory exists
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
  }

  // Read existing config or create new. Only suppress ENOENT — a read failure
  // from EACCES/EISDIR must not silently fall through to a write that would
  // clobber unreadable content.
  let config: McpConfig = {};
  try {
    config = JSON.parse(fs.readFileSync(configFile, 'utf-8'));
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code && code !== 'ENOENT') throw e;
    // ENOENT or parse error on missing/empty file: start with empty config
  }

  // Check if already configured
  if (config.mcpServers?.hackmyagent) {
    return {
      tool: ideConfig.name,
      configPath: ideConfig.configPath,
      created: false,
    };
  }

  // Add HackMyAgent MCP server
  if (!config.mcpServers) {
    config.mcpServers = {};
  }
  config.mcpServers.hackmyagent = HACKMYAGENT_MCP_CONFIG;

  // Write config
  fs.writeFileSync(configFile, JSON.stringify(config, null, 2) + '\n');

  return {
    tool: ideConfig.name,
    configPath: ideConfig.configPath,
    created: true,
  };
}
