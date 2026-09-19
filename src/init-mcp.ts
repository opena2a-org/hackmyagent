/**
 * HackMyAgent init-mcp Command
 *
 * Detects the user's AI coding tool and adds HackMyAgent as an MCP server.
 * Supports: Claude Code, Cursor, VS Code.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { rootTooBroad, describeRootRefusal, RootRefusalError } from './mcp/roots';
import { MCP_CLIENT_TARGETS, MCP_SERVER_MAP_KEYS, type McpClientTarget } from './mcp-clients';

/**
 * The real path when it exists, the lexical one when it does not.
 *
 * The policy compares against a realpath'd home, so a root reached through a
 * symlinked ancestor (`/tmp`, an external-volume home) has to be realpath'd
 * here too or the two sides compare different strings for the same directory.
 */
function realpathSyncOrSelf(p: string): string {
  try {
    // `.native` — the JS implementation is case-PRESERVING and the native one is
    // case-CANONICALISING, and `roots.ts` uses the native one via fs.promises. On
    // a case-insensitive filesystem that divergence let init-mcp accept
    // `/Users/Ecolibria` while mcp-serve refused it: one predicate, two answers.
    return fs.realpathSync.native(p);
  } catch {
    return p;
  }
}

interface McpServerEntry {
  command: string;
  args: string[];
  cwd?: string;
}

/**
 * A client config document. The server map hangs off a top-level key the
 * CLIENT chooses, so the document is indexed by key rather than typed with one
 * spelling baked in.
 */
type McpConfig = Record<string, unknown>;

/** The server map under `key`, or undefined when the key is absent or not an object. */
function serverMap(config: McpConfig, key: string): Record<string, McpServerEntry> | undefined {
  const map = config[key];
  return map && typeof map === 'object' && !Array.isArray(map)
    ? (map as Record<string, McpServerEntry>)
    : undefined;
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

/**
 * Config file locations, in detection priority order. ONE definition, shared
 * with the checks that read the same files — see `./mcp-clients`.
 */
const IDE_CONFIGS = MCP_CLIENT_TARGETS;

/**
 * Compare tool names with the separators dropped, so every spelling of one
 * name reaches the same target.
 *
 * `'vs code'.includes('vscode')` is false, so `--tool vscode` — the spelling
 * the option's OWN help text advertises — threw `Unknown tool: vscode` while
 * `--tool "vs code"`, which the help does not mention, worked.
 */
function normalizeToolName(name: string): string {
  return name.toLowerCase().replace(/[\s_-]+/g, '');
}

function detectIde(targetDir: string): McpClientTarget | null {
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
    const why = rootTooBroad(real, realpathSyncOrSelf(os.homedir()));
    if (why) {
      throw new RootRefusalError(describeRootRefusal({ kind: 'root-too-broad', root: real, why }));
    }
  }
  let ideConfig: McpClientTarget | null = null;

  if (forceTool) {
    const wanted = normalizeToolName(forceTool);
    ideConfig = IDE_CONFIGS.find((c) => normalizeToolName(c.name).includes(wanted)) || null;
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

  // The key THIS client reads, off the client's own record. Hard-coding
  // `config.mcpServers` here is what wrote the VS Code entry under a key VS
  // Code does not load — and under a key this tree's own VSCODE-002 does not
  // read either, so `secure` could not see what `init-mcp` had just written.
  const mcpKey = ideConfig.mcpKey;
  const otherKeys = MCP_SERVER_MAP_KEYS.filter((k) => k !== mcpKey);

  const own = serverMap(config, mcpKey)?.hackmyagent;
  // An entry an earlier release put under a key this client does not read: the
  // file is misconfigured however complete that entry looks, so it counts as
  // an existing entry to REPAIR, never as one to leave alone.
  const misplaced = otherKeys.map((k) => serverMap(config, k)?.hackmyagent).find(Boolean);
  const existing = own ?? misplaced;

  // An entry that already carries the roots the caller asked for, under the key
  // the client reads, is left alone. One that predates `--root`, that names
  // different roots, or that sits under the wrong key is REWRITTEN: #463's
  // refusal text tells the user to run this command, so returning "already
  // configured" and changing nothing would be a dead end inside the command
  // that exists to unblock them.
  if (own && !entryNeedsRoots(own) && roots.length === 0) {
    return {
      tool: ideConfig.name,
      configPath: ideConfig.configPath,
      created: false,
      updated: false,
      roots: own.args.filter((a, i) => own.args[i - 1] === '--root'),
    };
  }

  const map = serverMap(config, mcpKey) ?? {};
  map.hackmyagent = buildMcpServerEntry(resolvedRoots);
  config[mcpKey] = map;

  // The repair half of #463's discipline, for a key instead of an argument:
  // OUR entry under a key this client does not read is removed, so one file
  // never advertises two hackmyagent servers and the stale one cannot be the
  // one a client picks up. Every other entry, under either key, is left
  // exactly as it was — they are not ours to move.
  for (const key of otherKeys) {
    const stale = serverMap(config, key);
    if (!stale?.hackmyagent) continue;
    delete stale.hackmyagent;
    if (Object.keys(stale).length === 0) delete config[key];
  }

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
