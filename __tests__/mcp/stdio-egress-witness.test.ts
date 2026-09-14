/**
 * HMA-39.AC3 — the egress witness at the network boundary.
 *
 * The MCP contract for this server is READ inside the granted roots, WRITE
 * nothing, REACH nothing by default. The read half is witnessed over stdio in
 * stdio-confinement-witness.test.ts; this file witnesses REACH: a whole scan
 * session runs behind an in-process logging proxy and the log stays empty.
 *
 * A zero from a proxy nobody routes through proves nothing, so the witness
 * carries a control: a direct request from the test process through the same
 * proxy produces exactly one logged line, proving the log path records both
 * plain requests and CONNECT tunnels. The child is pointed at the proxy by
 * every conventional channel: HTTP_PROXY / HTTPS_PROXY (upper and lower case),
 * NO_PROXY='', and — for node's fetch, which ignores those env vars unless
 * told — NODE_USE_ENV_PROXY=1, the env switch that activates undici's
 * EnvHttpProxyAgent as the global dispatcher (verified honored on this node:
 * the child emits the UNDICI-EHPA experimental warning).
 *
 * `mcp-serve` at this commit registers no egress opt-in flag (src/cli.ts
 * declares only `--root`), so the flag-armed control the criterion describes
 * has nothing to run against; the delivery report records that.
 *
 * This witness found a real leak while being written: the Commander postAction
 * telemetry hook fires the moment the `mcp-serve` action returns — i.e. at
 * transport startup — and posted the default-on command event from inside the
 * session (`CONNECT api.oa2a.org:443`, one line, before the first tool call).
 * `mcp-serve` is now in NON_TRACKED_TELEMETRY_COMMANDS (src/cli.ts); this
 * file is what keeps it there.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as http from 'http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';

const REPO = path.resolve(__dirname, '../..');

let tmp: string;
let root: string;
let childHome: string;

const proxyLog: string[] = [];
let proxy: http.Server;
let proxyUrl: string;

beforeAll(async () => {
  // A missing dist/cli.js is an ERROR naming the build step, never a skip.
  assertDistFresh();

  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hma39-egress-')));
  root = path.join(tmp, 'project');
  childHome = path.join(tmp, 'child-home');
  fs.mkdirSync(root, { recursive: true });
  fs.mkdirSync(childHome, { recursive: true });
  fs.writeFileSync(
    path.join(root, 'mcp.json'),
    JSON.stringify({ mcpServers: { fs: { command: 'npx', args: ['-y', 'server-filesystem', '/'] } } }),
  );
  fs.writeFileSync(path.join(root, '.gitignore'), 'node_modules\n');

  // The logging proxy. It records BOTH shapes traffic can take: the plain
  // request line of an absolute-form HTTP request, and the CONNECT line undici
  // sends before tunnelling (it tunnels even plain-http targets).
  proxy = http.createServer((req, res) => {
    proxyLog.push(`${req.method} ${req.url}`);
    console.log(`[egress-proxy] ${req.method} ${req.url}`);
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('proxied');
  });
  proxy.on('connect', (req, socket) => {
    proxyLog.push(`CONNECT ${req.url}`);
    console.log(`[egress-proxy] CONNECT ${req.url}`);
    // Refuse rather than accept-then-close: undici treats an established
    // tunnel that dies mid-TLS as retryable and the child stalls for minutes;
    // a proxy 403 fails the attempt immediately. The LOG line above is the
    // witness either way.
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.end();
  });
  await new Promise<void>((resolve) => proxy.listen(0, '127.0.0.1', resolve));
  const addr = proxy.address();
  if (addr === null || typeof addr === 'string') throw new Error('proxy failed to bind');
  proxyUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => proxy.close(() => resolve()));
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('HMA-39.AC3 egress witness at the network boundary', () => {
  it('HMA-39.AC3 a full scan + deep_scan session behind the logging proxy produces zero proxy log lines', async () => {
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [BUILT_CLI, 'mcp-serve', '--root', root],
      cwd: REPO,
      env: {
        PATH: process.env.PATH ?? '',
        HOME: childHome,
        OPENA2A_CORPUS_DETERMINISTIC: '1',
        HTTP_PROXY: proxyUrl,
        HTTPS_PROXY: proxyUrl,
        http_proxy: proxyUrl,
        https_proxy: proxyUrl,
        NO_PROXY: '',
        no_proxy: '',
        // node's fetch (undici) ignores HTTP(S)_PROXY unless this is set; with
        // it, undici installs EnvHttpProxyAgent as the global dispatcher, so a
        // fetch-based egress attempt would hit the proxy too.
        NODE_USE_ENV_PROXY: '1',
      },
    });
    const client = new Client({ name: 'hma-39-egress-witness', version: '0.0.0' });
    await client.connect(transport);
    try {
      const before = proxyLog.length;
      const scan = (await client.callTool({
        name: 'hackmyagent_scan',
        arguments: { directory: root },
      })) as { content: Array<{ text: string }>; isError?: boolean };
      expect(scan.isError).toBeFalsy();
      expect(scan.content[0].text).toContain('Score:');

      const deep = (await client.callTool({
        name: 'hackmyagent_deep_scan',
        arguments: { directory: root },
      })) as { content: Array<{ text: string }>; isError?: boolean };
      expect(deep.isError).toBeFalsy();

      // The boundary assertion: nothing in the session reached out.
      expect(proxyLog.slice(before)).toEqual([]);
    } finally {
      await client.close();
    }
    expect(proxyLog).toEqual([]);
  });

  it('HMA-39.AC3 control: one direct request through the same proxy produces exactly one logged line', async () => {
    // Distinguishes a genuine zero from a proxy whose log path is broken: the
    // identical server, addressed the way proxied traffic addresses it,
    // records exactly one line.
    const before = proxyLog.length;
    const body = await new Promise<string>((resolve, reject) => {
      const u = new URL(proxyUrl);
      const req = http.request(
        {
          host: u.hostname,
          port: u.port,
          method: 'GET',
          path: 'http://egress-witness.invalid/control-probe',
          headers: { host: 'egress-witness.invalid' },
        },
        (res) => {
          let data = '';
          res.on('data', (d) => (data += d));
          res.on('end', () => resolve(data));
        },
      );
      req.on('error', reject);
      req.end();
    });
    expect(body).toBe('proxied');
    const after = proxyLog.slice(before);
    expect(after).toEqual(['GET http://egress-witness.invalid/control-probe']);
  });

  it('HMA-39.AC3 control: a child node process under the same env DOES route its fetch through the proxy', async () => {
    // Distinguishes a genuine zero from a child that silently ignored the
    // proxy variables: a bare node child, spawned with the identical env the
    // session child gets, makes one fetch and the proxy logs its CONNECT.
    const { spawn } = await import('child_process');
    const before = proxyLog.length;
    await new Promise<void>((resolve) => {
      const child = spawn(
        process.execPath,
        ['-e', "fetch('https://egress-witness.invalid/child-probe').then(()=>process.exit(0),()=>process.exit(0))"],
        {
          env: {
            PATH: process.env.PATH ?? '',
            HOME: childHome,
            HTTP_PROXY: proxyUrl,
            HTTPS_PROXY: proxyUrl,
            http_proxy: proxyUrl,
            https_proxy: proxyUrl,
            NO_PROXY: '',
            no_proxy: '',
            NODE_USE_ENV_PROXY: '1',
          },
          stdio: 'ignore',
        },
      );
      child.on('exit', () => resolve());
    });
    expect(proxyLog.slice(before)).toEqual(['CONNECT egress-witness.invalid:443']);
  });
});
