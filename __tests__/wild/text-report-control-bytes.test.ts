/**
 * #1085: the wild text report printed the robots.txt payload excerpt and the
 * category name taken from a sitemap URL as they came, so a target could put
 * terminal escape sequences on the operator's screen. Both are now escaped.
 *
 * The payloads are FAKE strings built at run time, not captured traffic.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFile } from 'node:child_process';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import * as path from 'node:path';
import { assertDistFresh } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

const ESC = '\u001b';
const BEL = '\u0007';

describe('#1085 wild text report escapes target-controlled text', { timeout: 120_000 }, () => {
  const CLI = path.join(__dirname, '..', '..', 'dist', 'cli.js');
  let server: http.Server;
  let base: string;

  beforeAll(async () => {
    assertDistFresh();
    server = http.createServer((req, res) => {
      const url = req.url ?? '';
      let body: string | undefined;
      if (url === '/robots.txt') {
        body = `User-agent: *\nhackmyagent FAKE ${ESC}[2J${ESC}]0;owned${BEL} marker\nDisallow:\n`;
      } else if (url === '/sitemap.xml') {
        body = `<urlset>\n<url><loc>${base}/attacks/inj${ESC}[31mred/1</loc></url>\n</urlset>\n`;
      } else if (url.startsWith('/attacks/')) {
        body = '<html><body><p>Nothing to see.</p></body></html>';
      }
      res.writeHead(body === undefined ? 404 : 200, { 'content-type': 'text/plain; charset=utf-8' });
      res.end(body ?? 'not found');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  /** Asynchronous on purpose: the server above runs on this process's event loop. */
  function run(args: string[]): Promise<{ status: number; out: string; err: string }> {
    return new Promise((resolve) => {
      execFile(
        process.execPath,
        [CLI, ...args],
        { encoding: 'utf-8', timeout: 60_000, env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: tempDir('hma-home-') } },
        (error, stdout, stderr) => {
          const code = error && typeof (error as { code?: unknown }).code === 'number' ? (error as { code: number }).code : error ? -1 : 0;
          resolve({ status: code, out: stdout, err: stderr });
        },
      );
    });
  }

  it('prints the robots.txt excerpt and the sitemap category with control bytes escaped', async () => {
    const r = await run(['wild', base, '--delay', '0']);
    expect(r.out, r.err).toContain('robots.txt: 200 [PAYLOAD FOUND]');
    expect(r.out).toContain('    hackmyagent FAKE \\e[2J\\e]0;owned\\x07 marker\n');
    expect(r.out).toContain('  inj\\e[31mred: 1 pages, 0 payloads\n');
    expect(r.out).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f]/);
  });
});
