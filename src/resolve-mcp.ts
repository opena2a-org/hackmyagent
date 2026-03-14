/**
 * MCP package name shorthand resolution.
 *
 * Converts short forms like "server-filesystem" or "mcp-server-fetch"
 * into the full scoped name "@modelcontextprotocol/server-*".
 */

const MCP_SCOPE = '@modelcontextprotocol';

/**
 * Resolve a package name, expanding MCP shorthand if applicable.
 *
 * Rules (applied in order):
 * 1. Starts with `@` -- use as-is (already scoped).
 * 2. Starts with `server-` -- prefix with @modelcontextprotocol/.
 * 3. Starts with `mcp/server-` or `mcp-server-` -- convert to @modelcontextprotocol/server-*.
 * 4. Otherwise -- use as-is (regular npm package).
 */
export function resolveMcpShorthand(name: string): string {
  if (name.startsWith('@')) return name;
  if (name.startsWith('server-')) return `${MCP_SCOPE}/${name}`;
  if (name.startsWith('mcp/server-')) return `${MCP_SCOPE}/${name.slice('mcp/'.length)}`;
  if (name.startsWith('mcp-server-')) return `${MCP_SCOPE}/${name.slice('mcp-'.length)}`;
  return name;
}

/**
 * Resolve and log to stderr if the name changed.
 */
export function resolveAndLogMcpShorthand(name: string): string {
  const resolved = resolveMcpShorthand(name);
  if (resolved !== name) {
    process.stderr.write(`Resolved: ${name} -> ${resolved}\n`);
  }
  return resolved;
}
