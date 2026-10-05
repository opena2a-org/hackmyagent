/**
 * `ensureDaemon` must not wait for a daemon that never launched.
 *
 * On a machine without the NanoMind daemon, `spawn('nanomind-daemon')` does
 * not throw: it returns a ChildProcess and delivers ENOENT later as an 'error'
 * event. The launcher reported success at return time, so every scan then
 * polled the health endpoint for the whole startup window (3s, ~16 probes)
 * before giving up. Measured on a `secure` run of the kitchen-sink corpus:
 * 3.5s wall, 0.2s CPU, 3.0s of it in that loop. A spawn-heavy test file paid
 * it once per spawned scan, which is most of its wall time and none of its
 * work.
 *
 * Counted, not timed: the health endpoint is a local server on an ephemeral
 * port that tallies probes, so the assertion holds on a loaded machine and the
 * test never touches the daemon's real port. The launch candidates that live
 * on disk (monorepo sibling, PID file) are hidden from the module, and the
 * `@nanomind/daemon` package resolves only to a directory this test controls,
 * so whether a daemon is installed on the machine running the suite does not
 * matter.
 *
 * The daemon is started from a path found relative to the package, never from
 * a command name. PATH is pointed at a directory this test controls so the
 * case for a `nanomind-daemon` that exists only there can show it is left
 * alone.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** Where `@nanomind/daemon/package.json` resolves to; null means not installed. */
const installed = vi.hoisted(() => ({ manifest: null as string | null }));

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    existsSync: (p: Parameters<typeof actual.existsSync>[0]) =>
      String(p).includes('nanomind') ? false : actual.existsSync(p),
  };
});

vi.mock('node:module', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:module')>();
  return {
    ...actual,
    createRequire: (from: Parameters<typeof actual.createRequire>[0]) => {
      const real = actual.createRequire(from);
      return {
        resolve: (id: string) => {
          if (id !== '@nanomind/daemon/package.json') return real.resolve(id);
          if (!installed.manifest) throw new Error(`Cannot find module '${id}'`);
          return installed.manifest;
        },
      };
    },
  };
});

const { ensureDaemon } = await import('../../src/nanomind-core/daemon-lifecycle');

/** Health endpoint that answers from a script and counts every probe. */
function healthServer(statuses: number[]): Promise<{ server: Server; port: number; probes: () => number }> {
  let probes = 0;
  const server = createServer((req, res) => {
    if (req.url === '/health') {
      const status = statuses[Math.min(probes, statuses.length - 1)];
      probes += 1;
      res.writeHead(status).end();
      return;
    }
    res.writeHead(404).end();
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, port: (server.address() as AddressInfo).port, probes: () => probes });
    });
  });
}

describe('ensureDaemon and a daemon that cannot be launched', () => {
  let binDir: string;
  let savedPath: string | undefined;
  let server: Server | undefined;

  beforeEach(() => {
    binDir = mkdtempSync(join(tmpdir(), 'hma-daemon-bin-'));
    savedPath = process.env.PATH;
    process.env.PATH = binDir;
  });

  afterEach(async () => {
    installed.manifest = null;
    process.env.PATH = savedPath;
    rmSync(binDir, { recursive: true, force: true });
    if (server) await new Promise((r) => server!.close(r));
    server = undefined;
  });

  it('gives up after the first health check when the daemon is not installed', async () => {
    const h = await healthServer([503]);
    server = h.server;

    const available = await ensureDaemon(h.port);

    expect(available).toBe(false);
    // One probe to learn it is not running; none spent waiting on a process
    // that was never created.
    expect(h.probes()).toBe(1);
  });

  it('does not start a nanomind-daemon that is only on PATH', async () => {
    const started = join(binDir, 'started');
    const stub = join(binDir, 'nanomind-daemon');
    writeFileSync(stub, `#!/bin/sh\n: > '${started}'\n`);
    chmodSync(stub, 0o755);
    const h = await healthServer([503]);
    server = h.server;

    const available = await ensureDaemon(h.port);

    expect(available).toBe(false);
    expect(h.probes()).toBe(1);
    expect(existsSync(started)).toBe(false);
  });

  it('still waits for a daemon that did launch', async () => {
    // A CLI that launches and exits — the daemon itself is the health server
    // above, which comes up healthy on the second probe.
    const pkgDir = join(binDir, 'daemon');
    mkdirSync(pkgDir);
    writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({
      name: '@nanomind/daemon',
      bin: { 'nanomind-daemon': 'cli.js' },
    }));
    writeFileSync(join(pkgDir, 'cli.js'), 'process.exit(0);\n');
    installed.manifest = join(pkgDir, 'package.json');
    const h = await healthServer([503, 200]);
    server = h.server;

    const available = await ensureDaemon(h.port);

    expect(available).toBe(true);
    expect(h.probes()).toBe(2);
  });
});
