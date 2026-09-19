/**
 * The MCP client targets: one file and one top-level key per client.
 *
 * Which file a client loads its MCP servers from, and which key inside that
 * file it reads, is an EXTERNAL fact — the client's, not this tree's. It is
 * recorded once, here, and routed to everything that acts on it: the writer
 * (`init-mcp`), the deterministic checks that read those files
 * (`checkVscodeConfig`, and the root spellings through
 * `ROOT_MCP_CONFIG_FILES`), and the Layer-2 analyzer that walks their server
 * maps.
 *
 * #757 and HMA-71 are the same defect twice, on two rows of this table: the
 * command wrote the `mcpServers` block into `.claude/settings.json`, which
 * Claude Code does not read for project MCP servers, and into
 * `.vscode/mcp.json` under `mcpServers`, which is not the key VS Code's
 * workspace file carries. Both shipped at exit 0 with a success line naming a
 * file the client would never load. A `mcpKey` field existed for the second
 * one and was read by NO code — four occurrences, all inside the table — while
 * the writer hard-coded `config.mcpServers` for every target, so the table
 * SAID `servers` and the writer wrote `mcpServers` with nothing to fail.
 *
 * Dependency-free on purpose: `init-mcp` is a CLI-startup import, so this
 * cannot reach for the scanner module, and the scanner reaches for this.
 * Pinned both ways by __tests__/mcp-client-targets-contract.test.ts.
 */

/** One client: the tool's name, the file it loads, the key it loads from. */
export interface McpClientTarget {
  /** The tool name `init-mcp` detects, reports and matches `--tool` against. */
  name: string;
  /** The config file, relative to the project root, forward-slashed. */
  configPath: string;
  /** The TOP-LEVEL key this client reads its server map from. */
  mcpKey: string;
}

/**
 * Every client target, in `init-mcp`'s detection priority order.
 *
 * - Claude Code reads the project-scope `.mcp.json` (#757, measured with
 *   `claude mcp list` at Claude Code 2.1.273), keyed `mcpServers`.
 * - Cursor reads `.cursor/mcp.json`, keyed `mcpServers`.
 * - VS Code reads the workspace `.vscode/mcp.json`, keyed `servers` — the key
 *   this tree's own reader of that file, VSCODE-002, has always walked.
 */
export const MCP_CLIENT_TARGETS: readonly McpClientTarget[] = [
  {
    name: 'Claude Code',
    configPath: '.mcp.json',
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
    mcpKey: 'servers',
  },
];

/** The record for one client by name. Throws rather than returning a target nobody named. */
export function mcpClientTarget(name: string): McpClientTarget {
  const target = MCP_CLIENT_TARGETS.find((t) => t.name === name);
  if (!target) throw new Error(`No MCP client target named ${name}`);
  return target;
}

/** The VS Code record, the subject of the VSCODE- checks. */
export const VSCODE_CLIENT = mcpClientTarget('VS Code');

/**
 * Every top-level key some client carries its server map under, DERIVED from
 * the records above rather than listed a second time.
 *
 * A reader that walks one of these files reads all of them: the key is the
 * client's choice, a file can be reached by more than one client, and a file
 * an older release wrote carries the key that release chose. Reading one key
 * is how a live `.mcp.json` read clean under MCP-001 and how an
 * `.vscode/mcp.json` reached Layer 2 as an empty server map.
 */
export const MCP_SERVER_MAP_KEYS: readonly string[] = [
  ...new Set(MCP_CLIENT_TARGETS.map((t) => t.mcpKey)),
];
