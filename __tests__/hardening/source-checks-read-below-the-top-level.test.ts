/**
 * #1273 / #1207 — the 27 source checks select `.ts` and `.js` files across the
 * scanned tree, not only its top level.
 *
 * LOG-002 and the 26 checks from AUTH-003 to AUDIT-004 took their files from a
 * one-level listing of the scanned directory. Code under `src/` was never
 * read: with nothing at the top level each check recorded "not applicable",
 * and with one config file at the top level (`eslint.config.js`) it decided on
 * that file alone, so LOG-002 passed over a `console.log(password)` it never
 * opened and `secure` exited 0.
 *
 * The selection is now one walk of the tree per scan (`sourceCheckFiles`):
 * no symlink followed, `node_modules`, `.git` and hidden directories never
 * entered, every path under `dist/` or `build/` dropped, depth bound 10. A
 * site's `.json` files stay top-level only. The cells below are:
 *
 *   (a) `src/index.ts` logging `password`: LOG-002 fails at high on
 *       `src/index.ts`, and the CLI exits 1;
 *   (b) the same with a top-level `eslint.config.js`: still fails, exit 1;
 *   (c) the file at the top level: the record is byte-equal to the record
 *       the top-level listing produced;
 *   (d) the file only under `node_modules/x/`, `dist/`, `build/` and
 *       `.cache/`: not applicable, `includeDist` or not;
 *   (e) each of the 26 other checks fails on its failing file under `src/`
 *       exactly as it fails with that file at the top level;
 *   (f) a mode-000 directory under `src/`: the scan finishes, the readable
 *       file is still judged, and the unlistable directory is disclosed;
 *   (g) a top-level directory symlink to a tree outside the target is not
 *       followed;
 *
 * plus the selection's own contract: one walk per scan, per run (two
 * overlapping scans on one scanner each read their own tree, and a second
 * scan reads the tree as it is then), the walk's depth bound, and `.json`
 * read at the root only.
 */
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { ScanOptions } from '../../src/hardening/scanner';
import type { ScanResult, Severity } from '../../src/hardening/security-check';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

type Rec = NonNullable<ScanResult['allFindings']>[number];

/** The issue's fixture: a package with its code under `src/`. */
const PROBE_PACKAGE = '{"name":"probe","version":"1.0.0"}\n';
const LOGS_PASSWORD = 'export function login(password: string): void { console.log(password); }\n';

const SOURCE_SUBJECT = 'source files (.ts, .js)';
const NO_SOURCE_IN_TREE = 'No .ts or .js files in the scanned tree, so there is no source to inspect.';
const NO_SOURCE_OR_ROOT_CONFIG =
  'No .ts or .js files in the scanned tree and no .json files at the scanned root, so there is nothing to inspect.';

/** A new directory holding `files` (paths relative to it), removed when the test ends. */
function project(files: Record<string, string>, prefix = 'hma-1273-'): string {
  const dir = tempDir(prefix);
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

function scan(dir: string, options: Partial<ScanOptions> = {}): Promise<ScanResult> {
  return new HardeningScanner().scan({ targetDir: dir, ...options });
}

/** The one record a check left in `allFindings`, if any. */
function record(result: ScanResult, checkId: string): Rec | undefined {
  const hits = (result.allFindings ?? []).filter((f) => f.checkId === checkId);
  expect(hits.length, `${checkId} records`).toBeLessThanOrEqual(1);
  return hits[0];
}

const SOURCE_CHECK_IDS = [
  'LOG-002', 'AUTH-003', 'PROC-004', 'NET-003', 'NET-004', 'API-001', 'API-003', 'API-004', 'SEC-004',
  'IO-004', 'INJ-001', 'INJ-002', 'INJ-003', 'INJ-004', 'RATE-002', 'RATE-003', 'RATE-004', 'SESSION-001',
  'SESSION-002', 'SESSION-004', 'ENCRYPT-001', 'ENCRYPT-002', 'ENCRYPT-003', 'ENCRYPT-004', 'AUDIT-001',
  'AUDIT-002', 'AUDIT-004',
];

describe('(a) and (b) code under src/ is read, with or without a top-level config file', () => {
  it('(a) LOG-002 fails at high on src/index.ts', async () => {
    const dir = project({ 'package.json': PROBE_PACKAGE, 'src/index.ts': LOGS_PASSWORD });
    const log = record(await scan(dir), 'LOG-002');
    expect(log).toMatchObject({ passed: false, severity: 'high', file: path.join('src', 'index.ts'), line: 1 });
    expect(log?.notApplicable).toBeUndefined();
    expect(log?.details).toEqual({ files: [path.join('src', 'index.ts')] });
  });

  it('(b) a top-level eslint.config.js no longer stands in for the code under src/', async () => {
    const dir = project({
      'package.json': PROBE_PACKAGE,
      'eslint.config.js': 'module.exports = { root: true };\n',
      'src/index.ts': LOGS_PASSWORD,
    });
    const log = record(await scan(dir), 'LOG-002');
    expect(log).toMatchObject({ passed: false, severity: 'high', file: path.join('src', 'index.ts') });
    expect(log?.details).toEqual({ files: [path.join('src', 'index.ts')] });
  });
});

describe('(a) and (b) through the built CLI: the verdict reaches the exit code', () => {
  beforeAll(assertDistFresh);

  function secure(dir: string): { status: number | null; log: Rec | undefined } {
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: tempDir('hma-1273-home-') };
    delete env.ANTHROPIC_API_KEY;
    const run = spawnSync(
      process.execPath,
      [BUILT_CLI, 'secure', dir, '--ci', '--no-registry', '--no-contribute', '--static-only', '--json'],
      { encoding: 'utf-8', env, timeout: 180_000 },
    );
    const report = JSON.parse(run.stdout.slice(run.stdout.indexOf('{'))) as ScanResult;
    return { status: run.status, log: (report.allFindings ?? []).find((f) => f.checkId === 'LOG-002') };
  }

  it('(a) exits 1 with LOG-002 failing on src/index.ts', () => {
    const { status, log } = secure(project({ 'package.json': PROBE_PACKAGE, 'src/index.ts': LOGS_PASSWORD }));
    expect(log).toMatchObject({ passed: false, severity: 'high', file: path.join('src', 'index.ts') });
    expect(status).toBe(1);
  });

  it('(b) exits 1 with LOG-002 failing on src/index.ts beside a top-level eslint.config.js', () => {
    const { status, log } = secure(project({
      'package.json': PROBE_PACKAGE,
      'eslint.config.js': 'module.exports = { root: true };\n',
      'src/index.ts': LOGS_PASSWORD,
    }));
    expect(log).toMatchObject({ passed: false, severity: 'high', file: path.join('src', 'index.ts') });
    expect(status).toBe(1);
  });
});

describe('(c) the top-level layout keeps its record', () => {
  // The record the top-level listing produced for this tree, field for field
  // and in this order (measured on the scanner before the change).
  const TOP_LEVEL_RECORD = {
    checkId: 'LOG-002',
    name: 'Sensitive Data in Logs',
    description: 'Potential sensitive data being logged',
    category: 'logging',
    severity: 'high',
    passed: false,
    message: 'Code may be logging sensitive data - review console.log statements',
    file: 'index.ts',
    line: 1,
    details: { files: ['index.ts'] },
    fixable: false,
    guidance:
      'Passwords, API keys, and tokens logged to console or files persist in log aggregators and crash reports, where they can be harvested by anyone with log access.',
    attackClass: 'INTEGRITY-BYPASS',
    redactionStatus: 'clean',
    redactedShapes: [],
  };

  it('(c) index.ts at the top level gives a byte-equal LOG-002 record', async () => {
    const dir = project({ 'package.json': PROBE_PACKAGE, 'index.ts': LOGS_PASSWORD });
    expect(JSON.stringify(record(await scan(dir), 'LOG-002'))).toBe(JSON.stringify(TOP_LEVEL_RECORD));
  });
});

describe('(d) the selection leaves out dependencies, build output and hidden directories', () => {
  const OUTSIDE_THE_SELECTION = {
    'package.json': PROBE_PACKAGE,
    'node_modules/x/index.ts': LOGS_PASSWORD,
    'dist/index.ts': LOGS_PASSWORD,
    'build/index.ts': LOGS_PASSWORD,
    '.cache/index.ts': LOGS_PASSWORD,
    // A skipped directory below the top level is skipped too.
    'packages/a/dist/index.js': LOGS_PASSWORD,
    'src/build/index.ts': LOGS_PASSWORD,
  };

  it.each([false, true])('(d) LOG-002 is not applicable with the tree-wide reason, includeDist %s', async (includeDist) => {
    const log = record(await scan(project(OUTSIDE_THE_SELECTION), { includeDist }), 'LOG-002');
    expect(log?.notApplicable).toEqual({ subject: SOURCE_SUBJECT, reason: NO_SOURCE_IN_TREE });
    expect(log?.passed).toBeUndefined();
    expect(log?.file).toBeUndefined();
  });
});

/**
 * (e) One cell per check. None of these checks has a test with a failing
 * source fixture of its own, so each cell's file is built from the check's
 * own detection: a hazard check gets the pattern it matches, an absence check
 * a file without any of the markers it accepts as the mitigation.
 *
 * The project is typed `api` through `pyproject.toml`, a type every one of
 * these checks applies to (`CHECK_PROJECT_TYPES`), and holds no `.json` at its
 * root, so before the change each check recorded not applicable on the `src/`
 * layout, the six that also read `.json` included. Each record is pathless,
 * so the record under `src/` must equal the record at the top level.
 */
const API_PROJECT = { 'pyproject.toml': '[project]\nname = "probe-api"\ndependencies = ["fastapi"]\n' };

const NO_HTTPS = "export const endpoint = 'http://localhost:8080';\n";
const ROUTES_ONLY = "export const routes = ['/users'];\n";
const PLAIN_FETCH = 'export async function call(url: string): Promise<Response> { return fetch(url); }\n';
const PLAIN_COOKIE =
  "export function setSession(res: { cookie(name: string, value: string): void }, id: string): void { res.cookie('sid', id); }\n";
const PLAIN_LOG = 'export function log(line: string): void { process.stdout.write(line); }\n';
// Assembled here so this file carries no connection-string literal.
const CONNECTION_SCHEME = ['postgres', '://'].join('');

const CELLS: Array<{ checkId: string; severity: Severity; file: string; content: string }> = [
  { checkId: 'AUTH-003', severity: 'medium', file: 'session.ts', content: "export const sessionOptions = { name: 'sid' };\n" },
  { checkId: 'PROC-004', severity: 'medium', file: 'parse.ts', content: 'export function parse(input: string): unknown { return JSON.parse(input); }\n' },
  { checkId: 'NET-003', severity: 'high', file: 'client.ts', content: NO_HTTPS },
  { checkId: 'NET-004', severity: 'medium', file: 'routes.ts', content: "export const routes = ['/debug'];\n" },
  { checkId: 'API-001', severity: 'low', file: 'routes.ts', content: ROUTES_ONLY },
  {
    checkId: 'API-003',
    severity: 'high',
    file: 'upstream.ts',
    content: "export function upstream(req: { query: { k: string } }): string { return '/data?apiKey=' + req.query.k; }\n",
  },
  { checkId: 'API-004', severity: 'medium', file: 'routes.ts', content: ROUTES_ONLY },
  { checkId: 'SEC-004', severity: 'critical', file: 'db.ts', content: `export const databaseUrl = '${CONNECTION_SCHEME}localhost/app';\n` },
  {
    checkId: 'IO-004',
    severity: 'high',
    file: 'download.ts',
    content:
      "import { readFile } from 'node:fs/promises';\nexport async function download(req: { params: { name: string } }): Promise<Buffer> { return readFile(req.params.name); }\n",
  },
  { checkId: 'INJ-001', severity: 'high', file: 'handler.ts', content: 'export function handle(body: unknown): unknown { return body; }\n' },
  { checkId: 'INJ-002', severity: 'high', file: 'render.ts', content: "export function render(name: string): string { return '<p>' + name + '</p>'; }\n" },
  {
    checkId: 'INJ-003',
    severity: 'critical',
    file: 'find.ts',
    content:
      "export function find(db: { query(sql: string): unknown }, id: string): unknown { return db.query('SELECT * FROM users WHERE id = ' + id); }\n",
  },
  {
    checkId: 'INJ-004',
    severity: 'critical',
    file: 'list.ts',
    content: "import { exec } from 'node:child_process';\nexport function list(dir: string): void { exec(`ls ${dir}`); }\n",
  },
  { checkId: 'RATE-002', severity: 'low', file: 'call.ts', content: PLAIN_FETCH },
  { checkId: 'RATE-003', severity: 'medium', file: 'call.ts', content: PLAIN_FETCH },
  {
    checkId: 'RATE-004',
    severity: 'low',
    file: 'all.ts',
    content: 'export function all(urls: string[]): Promise<Response[]> { return Promise.all(urls.map((u) => fetch(u))); }\n',
  },
  { checkId: 'SESSION-001', severity: 'high', file: 'session.ts', content: PLAIN_COOKIE },
  { checkId: 'SESSION-002', severity: 'medium', file: 'session.ts', content: PLAIN_COOKIE },
  {
    checkId: 'SESSION-004',
    severity: 'medium',
    file: 'token.ts',
    content: "export function saveToken(token: string): void { localStorage.setItem('token', token); }\n",
  },
  {
    checkId: 'ENCRYPT-001',
    severity: 'high',
    file: 'store.ts',
    content: 'export function store(db: { insert(row: string): void }, row: string): void { db.insert(row); }\n',
  },
  {
    checkId: 'ENCRYPT-002',
    severity: 'critical',
    file: 'users.ts',
    content: 'export function savePassword(db: { insert(row: string): void }, password: string): void { db.insert(password); }\n',
  },
  {
    checkId: 'ENCRYPT-003',
    severity: 'high',
    file: 'digest.ts',
    content: "import { createHash } from 'node:crypto';\nexport const digest = (s: string): string => createHash('md5').update(s).digest('hex');\n",
  },
  { checkId: 'ENCRYPT-004', severity: 'high', file: 'client.ts', content: NO_HTTPS },
  {
    checkId: 'AUDIT-001',
    severity: 'medium',
    file: 'remove.ts',
    content: 'export function remove(db: { delete(id: string): void }, id: string): void { db.delete(id); }\n',
  },
  { checkId: 'AUDIT-002', severity: 'low', file: 'log.ts', content: PLAIN_LOG },
  { checkId: 'AUDIT-004', severity: 'high', file: 'log.ts', content: PLAIN_LOG },
];

describe('(e) each source check fails on its failing file under src/ as it does at the top level', () => {
  it('covers every source check but LOG-002, once', () => {
    expect(CELLS.map((c) => c.checkId).sort()).toEqual(SOURCE_CHECK_IDS.filter((id) => id !== 'LOG-002').sort());
  });

  it.each(CELLS)('(e) $checkId', async ({ checkId, severity, file, content }) => {
    const top = record(await scan(project({ ...API_PROJECT, [file]: content })), checkId);
    const below = record(await scan(project({ ...API_PROJECT, [path.join('src', file)]: content })), checkId);
    // The premise: the file fails this check where the check always looked.
    expect(top).toMatchObject({ passed: false, severity });
    expect(top?.file).toBeUndefined();
    expect(below?.notApplicable).toBeUndefined();
    expect(below).toEqual(top);
  });
});

describe('(f) a directory the walk cannot list', () => {
  it('(f) a mode-000 directory under src/: the scan finishes, src/index.ts is judged, the directory is disclosed', async (ctx) => {
    const dir = project({
      'package.json': PROBE_PACKAGE,
      'src/index.ts': LOGS_PASSWORD,
      'src/locked/inner.ts': LOGS_PASSWORD,
    });
    const locked = path.join(dir, 'src', 'locked');
    fs.chmodSync(locked, 0o000);
    try {
      let listable = true;
      try {
        fs.readdirSync(locked);
      } catch {
        listable = false;
      }
      if (listable) {
        console.warn('[source-checks] cannot deny listing to this process (root?): SKIPPING, not passing');
        ctx.skip();
      }
      const result = await scan(dir);
      expect(record(result, 'LOG-002')).toMatchObject({
        passed: false,
        severity: 'high',
        file: path.join('src', 'index.ts'),
        details: { files: [path.join('src', 'index.ts')] },
      });
      expect(result.coverage?.unreadableInputs?.directories).toBeGreaterThanOrEqual(1);
      expect(result.coverage?.unreadableInputs?.codes.EACCES).toBeGreaterThanOrEqual(1);
      const unread = result.findings.filter((f) => f.checkId === 'SCAN-UNREAD-001').map((f) => f.file);
      expect(unread).toContain('src/locked/');
    } finally {
      fs.chmodSync(locked, 0o755);
    }
  });
});

describe('(g) a symlinked directory', () => {
  it('(g) a top-level directory symlink pointing outside the tree is not followed', async () => {
    const outside = project({ 'index.ts': LOGS_PASSWORD }, 'hma-1273-outside-');
    const dir = project({ 'package.json': PROBE_PACKAGE, 'src/clean.ts': 'export const answer = 42;\n' });
    fs.symlinkSync(outside, path.join(dir, 'linked'), 'dir');
    const result = await scan(dir);
    // src/clean.ts was read, so the check has a verdict; the linked file was not.
    const log = record(result, 'LOG-002');
    expect(log).toMatchObject({ passed: true, severity: 'high' });
    expect(log?.file).toBeUndefined();
    const named = (result.allFindings ?? [])
      .filter((f) => SOURCE_CHECK_IDS.includes(f.checkId))
      .flatMap((f) => [f.file ?? '', ...(((f.details as { files?: string[] } | undefined)?.files) ?? [])]);
    expect(named.filter((p) => p.startsWith('linked'))).toEqual([]);
  });
});

describe('the selection: one walk per scan, per run', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('walks the tree for the source checks once per scan, whatever the number of checks that read it', async () => {
    const proto = HardeningScanner.prototype as unknown as { walkDirectory: (...args: unknown[]) => Promise<string[]> };
    const walk = vi.spyOn(proto, 'walkDirectory');
    const dir = project({ ...API_PROJECT, 'src/index.ts': LOGS_PASSWORD });
    await scan(dir);
    const selections = walk.mock.calls.filter(([, extensions, depth]) => depth === 0 && JSON.stringify(extensions) === '[".ts",".js"]');
    expect(selections).toHaveLength(1);
    expect(selections[0][0]).toBe(dir);
  });

  it('two overlapping scans on one scanner each read their own tree', async () => {
    const withSource = project({ 'package.json': PROBE_PACKAGE, 'src/index.ts': LOGS_PASSWORD });
    const withoutSource = project({ 'package.json': PROBE_PACKAGE, 'node_modules/x/index.ts': LOGS_PASSWORD });
    const scanner = new HardeningScanner();
    const [a, b] = await Promise.all([scanner.scan({ targetDir: withSource }), scanner.scan({ targetDir: withoutSource })]);
    expect(record(a, 'LOG-002')).toMatchObject({ passed: false, file: path.join('src', 'index.ts') });
    expect(record(b, 'LOG-002')?.notApplicable).toEqual({ subject: SOURCE_SUBJECT, reason: NO_SOURCE_IN_TREE });
  });

  it('reads a file ten directories below the root, and not one eleven below (the walk depth bound)', async () => {
    const ten = path.join('d1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'd10');
    const atTen = record(await scan(project({ 'package.json': PROBE_PACKAGE, [path.join(ten, 'index.ts')]: LOGS_PASSWORD })), 'LOG-002');
    expect(atTen).toMatchObject({ passed: false, file: path.join(ten, 'index.ts') });
    const eleven = path.join(ten, 'd11');
    const atEleven = record(await scan(project({ 'package.json': PROBE_PACKAGE, [path.join(eleven, 'index.ts')]: LOGS_PASSWORD })), 'LOG-002');
    expect(atEleven?.notApplicable).toEqual({ subject: SOURCE_SUBJECT, reason: NO_SOURCE_IN_TREE });
  });

  it('a second scan on the same scanner reads the tree as it is then', async () => {
    const dir = project({ 'package.json': PROBE_PACKAGE, 'src/clean.ts': 'export const answer = 42;\n' });
    const scanner = new HardeningScanner();
    expect(record(await scanner.scan({ targetDir: dir }), 'LOG-002')).toMatchObject({ passed: true });
    fs.writeFileSync(path.join(dir, 'src', 'index.ts'), LOGS_PASSWORD);
    expect(record(await scanner.scan({ targetDir: dir }), 'LOG-002')).toMatchObject({
      passed: false,
      file: path.join('src', 'index.ts'),
    });
  });
});

describe('a site that also reads .json reads it at the root only', () => {
  it('AUTH-003 still reads a .json file at the root', async () => {
    const dir = project({
      ...API_PROJECT,
      'session.json': '{"cookie": "httpOnly: true"}\n',
      'src/server.ts': "export const sessionOptions = { name: 'sid' };\n",
    });
    expect(record(await scan(dir), 'AUTH-003')).toMatchObject({ passed: true });
  });

  it('AUTH-003 does not read a .json file below the root, and judges the source it does read', async () => {
    const dir = project({
      ...API_PROJECT,
      'src/session.json': '{"cookie": "httpOnly: true"}\n',
      'src/server.ts': "export const sessionOptions = { name: 'sid' };\n",
    });
    expect(record(await scan(dir), 'AUTH-003')).toMatchObject({ passed: false, severity: 'medium' });
  });

  it('AUTH-003 is not applicable, with the tree-wide reason, when the only .json sits below the root', async () => {
    const dir = project({ ...API_PROJECT, 'src/session.json': '{"cookie": "httpOnly: true"}\n' });
    expect(record(await scan(dir), 'AUTH-003')?.notApplicable).toEqual({
      subject: 'source or config files (.ts, .js, .json)',
      reason: NO_SOURCE_OR_ROOT_CONFIG,
    });
  });
});
