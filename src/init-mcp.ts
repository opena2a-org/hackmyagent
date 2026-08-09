/**
 * HackMyAgent init-mcp Command
 *
 * Detects the user's AI coding tool and adds HackMyAgent as an MCP server.
 * Supports: Claude Code, Cursor, VS Code.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { rootTooBroad, describeRootRefusal } from './mcp/roots';

/**
 * The real path when it exists, the lexical one when it does not.
 *
 * The policy compares against a realpath'd home, so a root reached through a
 * symlinked ancestor (`/tmp`, an external-volume home) has to be realpath'd
 * here too or the two sides compare different strings for the same directory.
 */
function realpathSyncOrSelf(p: string): string {
  try {
    return fs.realpathSync(p);
  } catch {
    return p;
  }
}

interface McpConfig {
  mcpServers?: Record<string, {
    command: string;
    args: string[];
    cwd?: string;
  }>;
}

interface InitResult {
  tool: string;
  configPath: string;
  created: boolean;
  /** An existing entry that was rewritten to carry roots (#463). */
  updated: boolean;
  roots: string[];
}

/**
 * The server entry written into the client config.
 *
 * #463 — this used to be `npx -y hackmyagent mcp-serve` with no roots and no
 * `cwd`, so the server's working directory was whatever the client happened to
 * choose, commonly the user's home directory. Every root the server will accept
 * is now named here explicitly, because `mcp-serve` no longer has an implicit
 * one, and `cwd` is pinned so a relative path in a tool call resolves somewhere
 * predictable.
 */
export function buildMcpServerEntry(roots: string[]): { command: string; args: string[]; cwd?: string } {
  return {
    command: 'npx',
    args: ['-y', 'hackmyagent', 'mcp-serve', ...roots.flatMap((r) => ['--root', r])],
    cwd: roots[0],
  };
}

/** True when an existing entry predates roots, so re-running init-mcp must repair it. */
export function entryNeedsRoots(entry: { args?: string[] } | undefined): boolean {
  return !entry?.args?.includes('--root');
}

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

export function initMcp(targetDir: string, forceTool?: string, roots: string[] = []): InitResult {
  // No `--root` means "the project you ran this in", which is still an explicit
  // human act naming a directory — unlike the server inheriting a cwd it was
  // never told about.
  const resolvedRoots = (roots.length > 0 ? roots : [targetDir]).map((r) => path.resolve(r));

  // The SAME policy `mcp-serve` enforces, applied here, because this is the
  // command its refusal text sends people to. Writing a root the server will
  // refuse produced "Added HackMyAgent MCP server" at exit 0 and then a client
  // whose every tool call failed for the life of the install — the dead end
  // that ruling was meant to close, reintroduced by the recovery path itself.
  // Refusing at configuration time is the only point where the person is still
  // present to fix it.
  for (const real of resolvedRoots.map((r) => realpathSyncOrSelf(r))) {
    const why = rootTooBroad(real, os.homedir());
    if (why) {
      throw new Error(describeRootRefusal({ kind: 'root-too-broad', root: real, why }));
    }
  }
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

  const existing = config.mcpServers?.hackmyagent;

  // An entry that already carries the roots the caller asked for is left alone.
  // One that predates `--root`, or that names different roots, is REWRITTEN:
  // #463's refusal text tells the user to run this command, so returning
  // "already configured" and changing nothing would be a dead end inside the
  // command that exists to unblock them.
  if (existing && !entryNeedsRoots(existing) && roots.length === 0) {
    return {
      tool: ideConfig.name,
      configPath: ideConfig.configPath,
      created: false,
      updated: false,
      roots: existing.args.filter((a, i) => existing.args[i - 1] === '--root'),
    };
  }

  if (!config.mcpServers) {
    config.mcpServers = {};
  }
  config.mcpServers.hackmyagent = buildMcpServerEntry(resolvedRoots);

  // Write config
  fs.writeFileSync(configFile, JSON.stringify(config, null, 2) + '\n');

  return {
    tool: ideConfig.name,
    configPath: ideConfig.configPath,
    created: !existing,
    updated: Boolean(existing),
    roots: resolvedRoots,
  };
}
