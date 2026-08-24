/**
 * #508 — a downloaded target that ships a member the run cannot read.
 *
 * The URL arm fetches an archive, extracts it, and runs the same scanner
 * `secure` runs, so the coverage ledger already records the read failure.
 * Before this change the derivation ignored that record (`total := examined`)
 * and the run exited 0 over an unreadable member; and the `SCAN-UNREAD-001`
 * remedy told the user to `chmod` a temp directory the run had already
 * deleted — a path that also leaked into `--json`.
 *
 * The archive is written here by a minimal ustar writer: a member's mode is
 * header metadata, so a mode-000 member can be produced without ever reading
 * an unreadable file (bsdtar cannot archive one as a non-root user, which is
 * how a first cut of this test skipped itself green on every build). The CLI's
 * own `tar xzf` restores mode 000 for a non-root user. Served from an
 * in-process HTTP server on a random port. Skips only when this process can
 * read a mode-000 file (root); every other precondition failure throws.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const EXIT_UNMEASURED = 2;

let root: string;
let server: http.Server | undefined;
let url = '';
let usable = false;
const restore: string[] = [];

function makeUnreadable(file: string): boolean {
  fs.chmodSync(file, 0o000);
  restore.push(file);
  try {
    fs.readFileSync(file);
    return false;
  } catch {
    return true;
  }
}

/** One ustar member: 512-byte header + content padded to 512. */
function ustar(name: string, content: string, mode: number): Buffer {
  const body = Buffer.from(content, 'utf-8');
  const header = Buffer.alloc(512, 0);
  header.write(name, 0, 100, 'utf-8');
  header.write(mode.toString(8).padStart(7, '0') + '\0', 100, 8, 'ascii');
  header.write('0000000\0', 108, 8, 'ascii'); // uid
  header.write('0000000\0', 116, 8, 'ascii'); // gid
  header.write(body.length.toString(8).padStart(11, '0') + '\0', 124, 12, 'ascii');
  header.write('00000000000\0', 136, 12, 'ascii'); // mtime
  header.write('        ', 148, 8, 'ascii'); // checksum placeholder
  header.write('0', 156, 1, 'ascii'); // regular file
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  let sum = 0;
  for (const byte of header) sum += byte;
  header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
  const padded = Buffer.alloc(Math.ceil(body.length / 512) * 512, 0);
  body.copy(padded);
  return Buffer.concat([header, padded]);
}

function tarball(members: Array<[string, string, number]>): Buffer {
  const parts = members.map(([n, c, m]) => ustar(n, c, m));
  parts.push(Buffer.alloc(1024, 0)); // end-of-archive
  return zlib.gzipSync(Buffer.concat(parts));
}

beforeAll(async () => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-508-url-'));
  // Prove unreadability is enforceable at all before serving anything.
  const probe = path.join(root, 'probe');
  fs.writeFileSync(probe, 'x');
  usable = makeUnreadable(probe);
  if (!usable) {
    console.warn('skipped: this process can read a mode-000 file (running as root?)');
    return;
  }
  const bytes = tarball([
    ['agent/package.json', '{ "name": "agent", "version": "1.0.0", "main": "src/util.js" }\n', 0o644],
    ['agent/.gitignore', 'node_modules/\n', 0o644],
    ['agent/src/util.js', 'export function greet(n){return "hi "+n}\n', 0o644],
    ['agent/src/secrets.js', 'module.exports = { note: "nothing to find here" };\n', 0o000],
  ]);
  // The writer must produce something the system tar can list, or the run
  // below fails for the wrong reason.
  const archive = path.join(root, 'agent.tar.gz');
  fs.writeFileSync(archive, bytes);
  const listed = spawnSync('tar', ['tzf', archive], { encoding: 'utf-8' });
  if (listed.status !== 0 || !listed.stdout.includes('agent/src/secrets.js')) {
    throw new Error(`the test's ustar writer produced an archive tar cannot list: ${listed.stderr}`);
  }
  server = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/gzip', 'content-length': bytes.length });
    res.end(bytes);
  });
  await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', () => resolve()));
  const address = server.address();
  if (address && typeof address === 'object') url = `http://127.0.0.1:${address.port}/agent.tar.gz`;
});

afterAll(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  for (const p of restore) {
    try { fs.chmodSync(p, 0o644); } catch { /* already gone */ }
  }
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
});

/**
 * Async on purpose: the archive is served from THIS process, and `spawnSync`
 * blocks the event loop, so the child's download would never be answered and
 * the child would hang to its kill timeout — on every build, which made a
 * first cut of this file fail identically on fixed and unfixed code.
 */
function run(args: string[]): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: {
        ...process.env,
        NO_COLOR: '1',
        OPENA2A_TELEMETRY: 'off',
        HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-')),
      },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    const killer = setTimeout(() => child.kill('SIGKILL'), 240_000);
    child.on('error', (e) => { clearTimeout(killer); reject(e); });
    child.on('close', (status) => { clearTimeout(killer); resolve({ status, stdout, stderr }); });
  });
}

describe('#508 check <url> over an archive with an unreadable member', () => {
  it('exits 2, puts the member on the denominator, and rewrites the remedy for a downloaded target', async () => {
    if (!usable) return;
    const res = await run(['check', url, '--no-registry', '--json']);
    expect(res.status, res.stderr.slice(0, 400)).toBe(EXIT_UNMEASURED);
    const body = JSON.parse(res.stdout.slice(res.stdout.indexOf('{')));
    expect(body.coverage.measured).toBe(true);
    expect(body.coverage.unreadableInputs.count).toBe(1);
    expect(body.coverage.total).toBe(body.coverage.examined + 1);

    const unread = (body.findings ?? []).filter((f: any) => f.checkId === 'SCAN-UNREAD-001');
    expect(unread).toHaveLength(1);
    expect(unread[0].file).toBe('src/secrets.js');
    // The remedy is about the archive, not about a directory on this machine.
    expect(unread[0].fix).not.toContain('chmod');
    expect(unread[0].fix).not.toContain(os.tmpdir());
    expect(unread[0].fix).not.toContain('/var/folders');
    expect(unread[0].fix).toContain('archive');
    expect(unread[0].fix).toContain('src/secrets.js');
    // Nowhere in the payload does the deleted extraction directory appear.
    expect(res.stdout).not.toContain('hma-check-url-');
  }, 300_000);
});
