/**
 * #455 — `check` read `.hmaignore` from the tree it had just downloaded, so a
 * published package could choose the scope of its own audit.
 *
 * `check <package>` exists to answer "is this safe to install?" about code the
 * user does not trust. Every remote arm (GitHub clone, PyPI archive, raw URL,
 * npm tarball) passed the extracted tree to `scan()` and to
 * `reapplyIgnoreFilters()`, both of which load `.hmaignore` from the target,
 * so a package shipping one line — the path of the file holding its planted
 * credential — had that file dropped from the report, the score and the exit
 * code. Measured on the build before the fix: 95/100, exit 0, the critical
 * finding gone, against 69/100 and exit 1 for the same package without it.
 *
 * The fix decides by provenance. A tree `check` fetched never has its
 * `.hmaignore` read; a local tree the operator points `check` at still does,
 * because there the operator and the author are the same person.
 *
 * The URL arm is the one with an offline trigger: the archives are written
 * here and served from this process. The other three arms fetch from fixed
 * hosts, so the source cells at the bottom hold their wiring.
 *
 * RED-ON-BASE: on ea751a6f the fetched run omits the `lib/config.js` finding
 * and `DEP-001`, and its score differs from the control's.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tarBytes, type TarMember } from '../helpers/archive-fixtures';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

// Synthetic, assembled at runtime so no whole credential literal sits in the tree.
const PLANTED = ['sk', 'proj', 'Q7vT2mX9kL4pR8sW1nB6yH3jD5fG0cZaE2uI7oK9wMxN4bV1'].join('-');

// One path rule (the scope channel) and one check-ID rule (the suppression
// channel): the package asks for both of its findings to disappear.
const SHIPPED_HMAIGNORE = 'lib/config.js\n!DEP-001\n';

const FILES: Array<[string, string]> = [
  ['package.json', '{ "name": "fx455", "version": "1.0.0", "main": "lib/index.js" }\n'],
  ['lib/index.js', 'module.exports = (n) => `hi ${n}`;\n'],
  ['lib/config.js', `const OPENAI_API_KEY = "${PLANTED}";\nmodule.exports = { OPENAI_API_KEY };\n`],
];

function archive(withIgnore: boolean): Buffer {
  const files = withIgnore ? [...FILES, ['.hmaignore', SHIPPED_HMAIGNORE] as [string, string]] : FILES;
  const members = files.map(([name, content]): TarMember => ({
    name: `package/${name}`,
    kind: 'file',
    data: Buffer.from(content, 'utf-8'),
  }));
  return zlib.gzipSync(tarBytes(members));
}

let root: string;
let localTree: string;
let server: http.Server | undefined;
let base = '';

beforeAll(async () => {
  root = tempDir('hma-455-');
  localTree = path.join(root, 'local');
  for (const [name, content] of [...FILES, ['.hmaignore', SHIPPED_HMAIGNORE] as [string, string]]) {
    fs.mkdirSync(path.dirname(path.join(localTree, name)), { recursive: true });
    fs.writeFileSync(path.join(localTree, name), content);
  }
  const served: Record<string, Buffer> = {
    '/shipped-ignore.tar.gz': archive(true),
    '/control.tar.gz': archive(false),
  };
  server = http.createServer((req, res) => {
    const bytes = served[req.url ?? ''];
    if (!bytes) { res.statusCode = 404; res.end(); return; }
    res.writeHead(200, { 'content-type': 'application/gzip', 'content-length': bytes.length });
    res.end(req.method === 'HEAD' ? undefined : bytes);
  });
  await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', () => resolve()));
  const address = server.address();
  if (address && typeof address === 'object') base = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
});

/**
 * Async on purpose: the archives are served from THIS process, and
 * `spawnSync` would block the event loop that answers the child's download.
 */
function check(target: string): Promise<{ status: number | null; body: any; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, 'check', target, '--no-registry', '--json'], {
      env: {
        ...process.env,
        NO_COLOR: '1',
        OPENA2A_TELEMETRY: 'off',
        HOME: tempDir('hma-home-'),
      },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    const killer = setTimeout(() => child.kill('SIGKILL'), 240_000);
    child.on('error', (e) => { clearTimeout(killer); reject(e); });
    child.on('close', (status) => {
      clearTimeout(killer);
      let body: any;
      try {
        body = JSON.parse(stdout.slice(stdout.indexOf('{')));
      } catch {
        reject(new Error(`no JSON from check ${target} (exit ${status}): ${stderr.slice(0, 400)}`));
        return;
      }
      resolve({ status, body, stderr });
    });
  });
}

const failed = (body: any) =>
  ((body.findings ?? []) as any[]).filter((f) => f.passed === false).map((f) => `${f.checkId} ${f.file ?? ''}`).sort();

describe('#455 an .hmaignore inside a fetched package does not narrow check', () => {
  it('RED-ON-BASE: reports what the shipped .hmaignore asks to hide, exactly as without it', async () => {
    const [fetched, control] = await Promise.all([
      check(`${base}/shipped-ignore.tar.gz`),
      check(`${base}/control.tar.gz`),
    ]);

    // Non-vacuous: without the file, the package has the credential finding
    // and DEP-001, so there is something for the shipped rules to hide.
    const controlFailed = failed(control.body);
    expect(controlFailed.some((k) => k.endsWith(' lib/config.js')), controlFailed.join('\n')).toBe(true);
    expect(controlFailed.some((k) => k.startsWith('DEP-001 ')), controlFailed.join('\n')).toBe(true);

    const fetchedFailed = failed(fetched.body);
    const credential = (fetched.body.findings as any[]).find(
      (f) => f.passed === false && f.file === 'lib/config.js' && f.severity === 'critical',
    );
    expect(credential, fetchedFailed.join('\n')).toBeDefined();
    expect(fetchedFailed.some((k) => k.startsWith('DEP-001 ')), fetchedFailed.join('\n')).toBe(true);

    // Scope, score and exit are the package's own, not the ones it asked for.
    expect(fetchedFailed).toEqual(controlFailed);
    expect(fetched.body.score).toBe(control.body.score);
    expect(fetched.status, fetched.stderr.slice(0, 400)).toBe(control.status);
  }, 300_000);

  it('a local tree the operator points check at still honours the same .hmaignore, and discloses it', async () => {
    const local = await check(localTree);
    // Local `check --json` carries counts, not a findings array.
    expect(local.body.critical, local.stderr.slice(0, 400)).toBe(0);
    const outOfScope = (local.body.outOfScope ?? []) as any[];
    expect(outOfScope.some((s) => s.severity === 'critical' && s.suppressedBy === 'hmaignore-path')).toBe(true);
    const excluded = ((local.body.hmaignore?.rules ?? []) as any[]).flatMap((r) => r.excluded ?? []);
    expect(excluded.some((e: any) => e.file === 'lib/config.js' && e.severity === 'critical')).toBe(true);
    expect(excluded.some((e: any) => e.checkId === 'DEP-001')).toBe(true);
  }, 300_000);
});

describe('#455 every remote check arm scans its fetched tree without reading .hmaignore', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'cli.ts'), 'utf8');

  function body(name: string): string {
    const start = src.indexOf(`async function ${name}(`);
    expect(start, `${name} not found in src/cli.ts`).toBeGreaterThan(-1);
    const next = src.indexOf('\nasync function ', start + 1);
    return src.slice(start, next === -1 ? undefined : next);
  }

  for (const arm of ['checkGitHubRepo', 'checkPyPiPackage', 'checkRawUrl', 'checkNpmPackage']) {
    it(`${arm}: every scan and every re-filter carries FETCHED_TREE`, () => {
      const fn = body(arm);
      const scans = fn.match(/scanner\.scan\(\{[^}]*\}\)/g) ?? [];
      expect(scans.length).toBeGreaterThan(0);
      for (const call of scans) expect(call).toContain('...FETCHED_TREE');
      const refilters = fn.match(/scanner\.reapplyIgnoreFilters\([^;]*\);/g) ?? [];
      expect(refilters.length).toBeGreaterThan(0);
      for (const call of refilters) expect(call).toMatch(/FETCHED_TREE\);$/);
    });
  }

  it('FETCHED_TREE turns the read off', () => {
    expect(src).toMatch(/const FETCHED_TREE = \{ readHmaIgnore: false \} as const;/);
  });
});
