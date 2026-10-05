/**
 * `attack` against a live endpoint describes an inconclusive result in terms
 * of the response the target sent, not a simulated one.
 *
 * Before: every inconclusive note read "no clear success or block indicators
 * matched the simulated response." Only an answered payload is counted as
 * inconclusive, and `--local` never answers one, so that sentence only ever
 * printed on a live run, where nothing was simulated.
 *
 * The target is a stub in its own process (an in-process server never
 * accepts while `spawnSync` blocks the event loop; see
 * verdict-requires-measurement.test.ts). Its reply matches neither a success
 * nor a block indicator, so every answered payload is inconclusive.
 *
 * RED-ON-BASE cells fail on the 647ef44c dist; PIN cells pass on both.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawn, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

const LIVE_WORDING = "indicators matched the target's response.";

interface Stub { url: string; stop(): Promise<void> }

async function startNeutralStub(): Promise<Stub> {
  const dir = tempDir('hma-inconclusive-stub-');
  const script = path.join(dir, 'stub.mjs');
  fs.writeFileSync(script, [
    "import http from 'node:http';",
    'const server = http.createServer((req, res) => {',
    "  req.resume();",
    "  req.on('end', () => {",
    "    res.writeHead(200, { 'Content-Type': 'application/json' });",
    "    res.end(JSON.stringify({ choices: [{ message: { content: 'The weather today is mild with light wind.' } }] }));",
    '  });',
    '});',
    "server.listen(0, '127.0.0.1', () => process.stdout.write('PORT ' + server.address().port + '\\n'));",
  ].join('\n'));

  const child = spawn(process.execPath, [script], { stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise<number>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('stub server did not report a port')), 15_000);
    let buf = '';
    child.stdout.on('data', (d) => {
      buf += String(d);
      const m = /PORT (\d+)/.exec(buf);
      if (m) { clearTimeout(timer); resolve(Number(m[1])); }
    });
    child.on('error', (e) => { clearTimeout(timer); reject(e); });
  });

  return {
    url: `http://127.0.0.1:${port}/v1/chat`,
    stop: () => new Promise<void>((resolve) => {
      child.once('exit', () => resolve());
      child.kill();
    }),
  };
}

function attack(args: string[]) {
  const r = spawnSync(process.execPath, [
    CLI, 'attack', ...args, '--category', 'prompt-injection', '--intensity', 'passive',
    '--delay', '0', '--timeout', '5000',
  ], {
    encoding: 'utf8',
    timeout: 180_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: tempDir('hma-home-') },
  });
  return { status: r.status, out: (r.stdout ?? '') + (r.stderr ?? '') };
}

describe('attack inconclusive note names the response that was tested', { timeout: 300_000 }, () => {
  it('RED-ON-BASE: a live run says the target\'s response, never a simulated one', async () => {
    const stub = await startNeutralStub();
    try {
      const { out } = attack([stub.url]);
      const counted = /(\d+) inconclusive/.exec(out);
      expect(counted, out).not.toBeNull();
      expect(Number(counted![1]), 'the stub reply produced no inconclusive result').toBeGreaterThan(0);
      expect(out).toContain(LIVE_WORDING);
      expect(out).not.toMatch(/simulated/i);
    } finally {
      await stub.stop();
    }
  });

  it('PIN: --local keeps its own wording and never claims a target responded', () => {
    const { status, out } = attack(['--local']);
    expect(status).toBe(2);
    expect(out).toContain('--local generates payloads and checks that they parse.');
    expect(out).not.toContain(LIVE_WORDING);
    expect(out).not.toMatch(/inconclusive -- /);
  });
});
