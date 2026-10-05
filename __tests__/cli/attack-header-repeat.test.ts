/**
 * #660 — `attack -H/--header` can be used multiple times, as its help says.
 *
 * Before: the option was registered without a collector, so a repeated `-H`
 * overwrote the previous value and only the LAST header reached the target;
 * the `Array.isArray(options.header)` branch in the action was dead code.
 *
 * The target is a stub in its own process (an in-process server never
 * accepts while `spawnSync` blocks the event loop; see
 * verdict-requires-measurement.test.ts). It appends the two headers of every
 * request it receives to a log the test reads back.
 *
 * RED-ON-BASE cells fail on the 044301c5 dist; PIN cells pass on both.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawn, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

interface Stub { url: string; seen(): Array<{ one: string | null; two: string | null }>; stop(): Promise<void> }

async function startHeaderStub(): Promise<Stub> {
  const dir = tempDir('hma-660-stub-');
  const script = path.join(dir, 'stub.mjs');
  const log = path.join(dir, 'headers.jsonl');
  fs.writeFileSync(script, [
    "import http from 'node:http';",
    "import fs from 'node:fs';",
    `const log = ${JSON.stringify(log)};`,
    'const server = http.createServer((req, res) => {',
    "  fs.appendFileSync(log, JSON.stringify({ one: req.headers['x-one'] ?? null, two: req.headers['x-two'] ?? null }) + '\\n');",
    "  req.resume();",
    "  req.on('end', () => {",
    "    res.writeHead(200, { 'Content-Type': 'application/json' });",
    "    res.end(JSON.stringify({ choices: [{ message: { content: 'I cannot help with that request.' } }] }));",
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
    seen: () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '')
      .split('\n').filter(Boolean).map((l) => JSON.parse(l)),
    stop: () => new Promise<void>((resolve) => {
      child.once('exit', () => { fs.rmSync(dir, { recursive: true, force: true }); resolve(); });
      child.kill();
    }),
  };
}

function attack(url: string, extra: string[]) {
  const r = spawnSync(process.execPath, [
    CLI, 'attack', url, '--category', 'prompt-injection', '--intensity', 'passive',
    '--delay', '0', '--timeout', '5000', ...extra,
  ], {
    encoding: 'utf8',
    timeout: 180_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: tempDir('hma-home-') },
  });
  return { status: r.status, out: (r.stdout ?? '') + (r.stderr ?? '') };
}

describe('#660 attack -H accumulates', { timeout: 300_000 }, () => {
  it('RED-ON-BASE: two -H flags both reach every request', async () => {
    const stub = await startHeaderStub();
    try {
      attack(stub.url, ['-H', 'X-One: first', '-H', 'X-Two: second']);
      const seen = stub.seen();
      expect(seen.length, 'the stub received no request').toBeGreaterThan(0);
      for (const req of seen) {
        expect(req).toEqual({ one: 'first', two: 'second' });
      }
    } finally {
      await stub.stop();
    }
  });

  it('PIN: a single -H still reaches the target, and a value keeps its colons', async () => {
    const stub = await startHeaderStub();
    try {
      attack(stub.url, ['--header', 'X-One: a:b:c']);
      const seen = stub.seen();
      expect(seen.length).toBeGreaterThan(0);
      for (const req of seen) {
        expect(req).toEqual({ one: 'a:b:c', two: null });
      }
    } finally {
      await stub.stop();
    }
  });
});
