/**
 * Out-of-tree link confinement, measured end to end on the built scanner.
 *
 * Measured on the pre-fix build (`f7f6076`), a plain `secure` over the
 * all-basenames fixture made link-following calls that reached an
 * out-of-tree real path from every fixed-name probe, the walkers' root
 * links, the structural layer and the citation re-reads; the out-of-tree
 * bytes reached findings, `--output`, and under `--deep` the Layer-3 request
 * body. The guard now sits once in the tracked `fs` namespace, so these
 * tests enumerate no sites: they instrument the REAL `fs` underneath the
 * namespace (`fs-reach-recorder.cjs`, preloaded before `dist` loads) and
 * assert that nothing got past it.
 *
 * Every assertion runs against `dist`, through `HardeningScanner.scan` in a
 * driver process and through the CLI entry (single-file mode included), so
 * the same suite is red on the base extract and green here.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { buildLinkFixture, CANARY, type LinkFixture } from '../helpers/out-of-tree-link-fixture';

const HELPERS = path.resolve(__dirname, '../helpers');
const RECORDER = path.join(HELPERS, 'fs-reach-recorder.cjs');
const DRIVER = path.join(HELPERS, 'scan-driver.cjs');
const SPAWN_TIMEOUT = 600_000;
const TEST_TIMEOUT = 900_000;

interface Reach { call: string; path: string; resolved: string; frame: string }
interface ReachReport { reaches: Reach[]; calls: number }
interface DriverOut {
  exit: number;
  score: number;
  failingCheckIds: string[];
  unread: number;
  withheldLinks: Array<{ rel: string; resolved: string; call: string; retarget: string }>;
  canaryInResult: number;
  canaryInLayer3Input: number;
  layer3Paths: string[];
}

let fx: LinkFixture;
let markers: string;
let markerSeq = 0;

function baseEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: '1', HMA_TEST_CANARY: CANARY };
  delete env.ANTHROPIC_API_KEY;
  return env;
}

function withRecorder(roots: string[]): { env: NodeJS.ProcessEnv; marker: string } {
  const marker = path.join(markers, `reach-${++markerSeq}.json`);
  return {
    env: { ...baseEnv(), HMA_TEST_CONFINE_ROOTS: roots.join(path.delimiter), HMA_TEST_REACH_MARKER: marker },
    marker,
  };
}

function readReach(marker: string): ReachReport {
  return JSON.parse(fs.readFileSync(marker, 'utf8')) as ReachReport;
}

function describeReaches(r: ReachReport): string {
  return [...new Set(r.reaches.map((x) => `${x.call} ${x.path} <- ${x.frame.replace(/\s\(.*$/, '')}`))].join('\n');
}

function runDriver(dir: string, roots: string[] = [dir]): { out: DriverOut; reach: ReachReport } {
  const { env, marker } = withRecorder(roots);
  const r = spawnSync(process.execPath, ['--require', RECORDER, DRIVER, dir, ...(roots.length > 1 ? roots : [])], {
    encoding: 'utf8', env, timeout: SPAWN_TIMEOUT, maxBuffer: 64 * 1024 * 1024,
  });
  const last = String(r.stdout ?? '').trim().split('\n').pop() ?? '';
  expect(r.status, `driver exit ${r.status}: ${String(r.stderr).slice(0, 500)}`).toBe(0);
  return { out: JSON.parse(last) as DriverOut, reach: readReach(marker) };
}

function runCli(args: string[], opts: { roots?: string[]; env?: NodeJS.ProcessEnv } = {}): { status: number | null; stdout: string; stderr: string; reach?: ReachReport } {
  const rec = opts.roots ? withRecorder(opts.roots) : undefined;
  const env = { ...(rec?.env ?? baseEnv()), ...(opts.env ?? {}) };
  const r = spawnSync(process.execPath, [...(rec ? ['--require', RECORDER] : []), BUILT_CLI, ...args], {
    encoding: 'utf8', env, timeout: SPAWN_TIMEOUT, maxBuffer: 64 * 1024 * 1024,
  });
  return {
    status: r.status,
    stdout: String(r.stdout ?? ''),
    stderr: String(r.stderr ?? ''),
    reach: rec ? readReach(rec.marker) : undefined,
  };
}

function count(s: string, needle = CANARY): number {
  return (s.match(new RegExp(needle, 'g')) ?? []).length;
}

beforeAll(() => {
  assertDistFresh();
  fx = buildLinkFixture();
  markers = path.join(fx.base, 'markers');
  fs.mkdirSync(markers);
});

afterAll(() => {
  fs.rmSync(fx.base, { recursive: true, force: true });
});

describe('AC1 — zero out-of-tree reaches, enumerating no sites', () => {
  it('HardeningScanner.scan over the all-basenames tree reaches nothing outside it, and neither does the Layer-3 input', () => {
    const { out, reach } = runDriver(fx.linked);
    expect(reach.calls, 'the recorder saw the scan (sanity)').toBeGreaterThan(100);
    expect(reach.reaches.length, describeReaches(reach)).toBe(0);
    expect(out.canaryInLayer3Input).toBe(0);
    expect(out.canaryInResult).toBe(0);
    expect(out.layer3Paths).not.toContain('.env');
    expect(out.layer3Paths).not.toContain('CLAUDE.md');
  }, TEST_TIMEOUT);

  it('a directory link at .claude is not entered', () => {
    const { out, reach } = runDriver(fx.linkedDir);
    expect(reach.reaches.length, describeReaches(reach)).toBe(0);
    expect(out.canaryInResult).toBe(0);
    expect(out.withheldLinks.map((w) => w.rel)).toContain('.claude');
  }, TEST_TIMEOUT);

  it('the CLI entry (directory mode) reaches nothing outside the tree', () => {
    const outFile = path.join(fx.base, 'cli-dir.json');
    const r = runCli(['secure', fx.linked, '--format', 'json', '--output', outFile], { roots: [fx.linked] });
    expect(r.reach!.calls).toBeGreaterThan(100);
    expect(r.reach!.reaches.length, describeReaches(r.reach!)).toBe(0);
    expect(fs.existsSync(outFile)).toBe(true);
  }, TEST_TIMEOUT);

  it('the CLI entry (single-file mode) does not copy or stat through an out-of-tree link', () => {
    const r = runCli(['secure', path.join(fx.linked, 'config.json')], { roots: [fx.linked] });
    expect(r.reach!.reaches.length, describeReaches(r.reach!)).toBe(0);
    const out = r.stdout + r.stderr;
    expect(out).toMatch(/1 link inside the scanned tree resolves outside it and was not read/);
    expect(out).toContain(`config.json -> ${path.join(fx.shared, 'config.json')}`);
    expect(out).toMatch(/point the scan at/);
    expect(count(out)).toBe(0);
  }, TEST_TIMEOUT);
});

describe('AC2 — parity with the retargeted twin, and complete disclosure', () => {
  it('the linked tree settles exactly as its twin and names every planted link', () => {
    const linked = runDriver(fx.linked).out;
    const twin = runDriver(fx.twin).out;
    expect(linked.exit).toBe(twin.exit);
    expect(linked.failingCheckIds).toEqual(twin.failingCheckIds);
    expect(linked.score).toBe(twin.score);
    expect(linked.unread).toBe(0);
    expect(twin.unread).toBe(0);
    expect(twin.withheldLinks).toEqual([]);
  }, TEST_TIMEOUT);

  it('the CLI JSON document names every planted link with its resolved target and the retarget instruction', () => {
    const outFile = path.join(fx.base, 'cli-parity.json');
    const r = runCli(['secure', fx.linked, '--format', 'json', '--output', outFile]);
    const doc = JSON.parse(fs.readFileSync(outFile, 'utf8')) as { exitCode: number; withheldLinks?: DriverOut['withheldLinks']; coverage?: { unreadableInputs?: { count: number } } };
    const twinFile = path.join(fx.base, 'cli-twin.json');
    runCli(['secure', fx.twin, '--format', 'json', '--output', twinFile]);
    const twin = JSON.parse(fs.readFileSync(twinFile, 'utf8')) as { exitCode: number; withheldLinks?: unknown[] };
    expect(r.status).toBe(twin.exitCode);
    expect(doc.exitCode).toBe(twin.exitCode);
    expect(twin.withheldLinks).toBeUndefined();
    expect(doc.coverage?.unreadableInputs?.count ?? 0).toBe(0);

    const byRel = new Map((doc.withheldLinks ?? []).map((w) => [w.rel, w]));
    for (const planted of fx.plantedLinks) {
      const rec = byRel.get(planted.rel);
      expect(rec, `withheldLinks names ${planted.rel}`).toBeDefined();
      expect(rec!.resolved).toBe(planted.resolved);
      expect(rec!.retarget).toMatch(/point the scan at/);
      expect(rec!.retarget).toContain(path.dirname(planted.resolved));
      expect(rec!.call.length).toBeGreaterThan(0);
    }
  }, TEST_TIMEOUT);

  it('detection is relocated, not destroyed: scanning the shared directory finds what the links pointed at', () => {
    const shared = runDriver(fx.shared).out;
    expect(shared.failingCheckIds.some((id) => /CRED/.test(id))).toBe(true);
  }, TEST_TIMEOUT);
});

describe('AC3 — zero canary on every channel', () => {
  it('serialized ScanResult and the --output artifact carry no out-of-tree bytes', () => {
    const { out } = runDriver(fx.linked);
    expect(out.canaryInResult).toBe(0);
    const outFile = path.join(fx.base, 'cli-canary.json');
    runCli(['secure', fx.linked, '--format', 'json', '--output', outFile]);
    expect(count(fs.readFileSync(outFile, 'utf8'))).toBe(0);
    const text = runCli(['secure', fx.linked]);
    expect(count(text.stdout + text.stderr)).toBe(0);
  }, TEST_TIMEOUT);

  it('the CLI entry in --deep TEXT mode (the simulation walk) reaches nothing outside the tree', () => {
    const fetchMarker = path.join(markers, 'fetch-bodies-text.ndjson');
    const r = runCli(['secure', fx.linked, '--deep'], {
      roots: [fx.linked],
      env: { ANTHROPIC_API_KEY: 'test-placeholder-not-a-key', HMA_TEST_FETCH_MARKER: fetchMarker },
    });
    expect(r.reach!.calls).toBeGreaterThan(100);
    expect(r.reach!.reaches.length, describeReaches(r.reach!)).toBe(0);
    expect(count(r.stdout + r.stderr)).toBe(0);
  }, TEST_TIMEOUT);

  it('intercepted Layer-3 request bodies under --deep carry no out-of-tree bytes', () => {
    const fetchMarker = path.join(markers, 'fetch-bodies.ndjson');
    const outFile = path.join(fx.base, 'cli-deep.json');
    const r = runCli(['secure', fx.linked, '--deep', '--format', 'json', '--output', outFile], {
      roots: [fx.linked],
      // A placeholder that unlocks the Layer-3 arm; the stubbed fetch never
      // sends it anywhere.
      env: { ANTHROPIC_API_KEY: 'test-placeholder-not-a-key', HMA_TEST_FETCH_MARKER: fetchMarker },
    });
    expect(r.reach!.reaches.length, describeReaches(r.reach!)).toBe(0);
    const bodies = fs.existsSync(fetchMarker) ? fs.readFileSync(fetchMarker, 'utf8') : '';
    const messages = bodies.split('\n').filter((l) => l.includes('/v1/messages'));
    expect(messages.length, 'Layer 3 attempted at least one request (else this assertion is vacuous)').toBeGreaterThan(0);
    expect(count(bodies)).toBe(0);
    expect(count(fs.readFileSync(outFile, 'utf8'))).toBe(0);
  }, TEST_TIMEOUT);
});

describe('AC4 — no false withhold', () => {
  it('an in-tree link is read and reported, nothing withheld', () => {
    const { out, reach } = runDriver(fx.intree);
    expect(reach.reaches.length).toBe(0);
    expect(out.withheldLinks).toEqual([]);
    expect(out.canaryInLayer3Input, 'the in-tree link IS read into the Layer-3 input').toBeGreaterThan(0);
    expect(out.failingCheckIds.some((id) => /CRED|PERM/.test(id))).toBe(true);
  }, TEST_TIMEOUT);

  it('a scan under a symlinked parent is indistinguishable from the real directory', () => {
    const via = runDriver(fx.linkToTwin).out;
    const twin = runDriver(fx.twin).out;
    expect(via.withheldLinks).toEqual([]);
    expect(via.exit).toBe(twin.exit);
    expect(via.failingCheckIds).toEqual(twin.failingCheckIds);
  }, TEST_TIMEOUT);

  it('a target spelled through the unresolved os.tmpdir() (/var -> /private/var) withholds nothing', () => {
    const unresolved = fx.twin.replace(fs.realpathSync(os.tmpdir()), os.tmpdir());
    const { out } = runDriver(unresolved, [unresolved]);
    expect(out.withheldLinks).toEqual([]);
    expect(out.failingCheckIds).toEqual(runDriver(fx.twin).out.failingCheckIds);
  }, TEST_TIMEOUT);

  it('secure --fix with backup, then rollback, on a tree with an in-tree link: nothing withheld, rollback complete', () => {
    const tree = path.join(fx.base, 'fixme');
    fs.cpSync(fx.intree, tree, { recursive: true, verbatimSymlinks: true });
    const fixOut = path.join(fx.base, 'fix.json');
    const fix = runCli(['secure', tree, '--fix', '--format', 'json', '--output', fixOut], { roots: [tree] });
    expect(fix.reach!.reaches.length, describeReaches(fix.reach!)).toBe(0);
    const doc = JSON.parse(fs.readFileSync(fixOut, 'utf8')) as { withheldLinks?: unknown[]; backupPath?: string };
    expect(doc.withheldLinks).toBeUndefined();
    expect(doc.backupPath, 'the fix run created a backup').toBeDefined();
    const back = runCli(['rollback', tree], { roots: [tree] });
    expect(back.reach!.reaches.length, describeReaches(back.reach!)).toBe(0);
    expect(back.status, back.stdout + back.stderr).toBe(0);
    expect(back.stdout + back.stderr).not.toMatch(/resolves? outside/);
  }, TEST_TIMEOUT);
});
