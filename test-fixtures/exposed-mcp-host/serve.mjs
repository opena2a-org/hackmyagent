#!/usr/bin/env node
/**
 * A host that exposes what `scan` looks for: an MCP tools listing at
 * /mcp/tools and an MCP client configuration at /mcp.json. Every other path
 * answers 404.
 *
 * Usage: node serve.mjs <port-file>
 *
 * Listens on 127.0.0.1 at a free port, writes that port and a newline to
 * <port-file> once it accepts connections, and serves until it receives
 * SIGTERM or its standard input closes. The example of the exposed-host
 * choice in docs/chooser.json runs it.
 */
import { renameSync, writeFileSync } from 'node:fs';
import http from 'node:http';

const portFile = process.argv[2];
if (!portFile) {
  process.stderr.write('Usage: node serve.mjs <port-file>\n');
  process.exit(2);
}

const ROUTES = {
  '/mcp/tools': {
    tools: [
      { name: 'read_file', description: 'Read a file under the data folder', inputSchema: { type: 'object', properties: { path: { type: 'string' } } } },
      { name: 'run_command', description: 'Run a shell command', inputSchema: { type: 'object', properties: { command: { type: 'string' } } } },
    ],
  },
  '/mcp.json': {
    mcpServers: {
      files: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/srv/data'] },
    },
  },
};

const server = http.createServer((req, res) => {
  const body = Object.hasOwn(ROUTES, req.url) ? ROUTES[req.url] : undefined;
  if (body === undefined) {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found\n');
    return;
  }
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(`${JSON.stringify(body, null, 2)}\n`);
});

server.listen(0, '127.0.0.1', () => {
  // Written beside the file and renamed, so a reader never sees half a port.
  writeFileSync(`${portFile}.tmp`, `${server.address().port}\n`);
  renameSync(`${portFile}.tmp`, portFile);
});

// The process that started this server holds its standard input; when that
// process ends, however it ends, the server ends with it.
process.stdin.on('end', () => process.exit(0));
process.stdin.resume();
