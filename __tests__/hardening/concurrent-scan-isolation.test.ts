/**
 * HMA-26.AC2 — concurrent scans with disjoint roots keep their own confinement.
 *
 * The filing measurement at the base (d6fade15): scanning one tree while
 * another root's ledger was active withheld only ['.env'] and made 28
 * out-of-tree reaches, where the sequential control withheld 6 with 0. The
 * global install meant `withholdOutOfTree` consulted whichever scan installed
 * last, whose roots do not cover the other scan's paths, so the other scan's
 * links passed straight through the guard to the real filesystem.
 *
 * This suite is the red-first proof: two concurrent `scan()` calls over two
 * disjoint all-basenames link fixtures, in one process (the defect is
 * per-process, so one-scan-per-process drivers cannot see it), under the
 * HMA-04 reach recorder (`fs-reach-recorder.cjs`, preloaded before `dist`
 * loads, confined to both roots). Each scan must withhold exactly what its
 * own sequential run withholds, resolve every withheld link into its OWN
 * shared directory, and make zero out-of-tree reaches.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import path from 'node:path';
import { assertDistFresh } from '../helpers/dist-freshness';
import { buildLinkFixture, type LinkFixture } from '../helpers/out-of-tree-link-fixture';

const HELPERS = path.resolve(__dirname, '../helpers');
const RECORDER = path.join(HELPERS, 'fs-reach-recorder.cjs');
const DRIVER = path.join(HELPERS, 'concurrent-scan-driver.cjs');
const SPAWN_TIMEOUT = 600_000;
const TEST_TIMEOUT = 900_000;

interface Reach { call: string; path: string; resolved: string; frame: string }
interface ReachReport { reaches: Reach[]; calls: number }
type Links = Array<{ rel: string; resolved: string }>;
interface DriverOut {
  concurrent: { a: Links; b: Links };
  sequential: { a: Links; b: Links };
}

let fxA: LinkFixture;
let fxB: LinkFixture;

beforeAll(() => {
  assertDistFresh();
  fxA = buildLinkFixture('hma26-a-');
  fxB = buildLinkFixture('hma26-b-');
});

afterAll(() => {
  fs.rmSync(fxA.base, { recursive: true, force: true });
  fs.rmSync(fxB.base, { recursive: true, force: true });
});

function describeReaches(r: ReachReport): string {
  return [...new Set(r.reaches.map((x) => `${x.call} ${x.path} <- ${x.frame.replace(/\s\(.*$/, '')}`))].join('\n');
}

describe('HMA-26.AC2 concurrent scan confinement isolation', () => {
  it('HMA-26.AC2 two concurrent scans with disjoint roots each withhold exactly their own out-of-tree links and make 0 out-of-tree reaches', () => {
    const marker = path.join(fxA.base, 'reach.json');
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      NO_COLOR: '1',
      HMA_TEST_CONFINE_ROOTS: [fxA.linked, fxB.linked].join(path.delimiter),
      HMA_TEST_REACH_MARKER: marker,
    };
    delete env.ANTHROPIC_API_KEY;

    const r = spawnSync(process.execPath, ['--require', RECORDER, DRIVER, fxA.linked, fxB.linked], {
      encoding: 'utf8', env, timeout: SPAWN_TIMEOUT, maxBuffer: 64 * 1024 * 1024,
    });
    expect(r.status, `driver exit ${r.status}: ${String(r.stderr).slice(0, 500)}`).toBe(0);
    const last = String(r.stdout ?? '').trim().split('\n').pop() ?? '';
    const out = JSON.parse(last) as DriverOut;
    const reach = JSON.parse(fs.readFileSync(marker, 'utf8')) as ReachReport;

    // Non-vacuity: the recorder saw the scans, and the fixtures' links were
    // really there to withhold — the sequential control names every planted
    // link of its own tree.
    expect(reach.calls, 'the recorder saw the scans (sanity)').toBeGreaterThan(100);
    for (const [seq, fx] of [[out.sequential.a, fxA], [out.sequential.b, fxB]] as const) {
      const rels = seq.map((w) => w.rel);
      for (const planted of fx.plantedLinks) expect(rels).toContain(planted.rel);
    }

    // The measured defect: each concurrent scan withholds what its own
    // sequential run withholds — not the ['.env']-only remnant the base
    // produced once the other scan's ledger was installed over its own.
    expect(out.concurrent.a).toEqual(out.sequential.a);
    expect(out.concurrent.b).toEqual(out.sequential.b);

    // And no scan's confinement was decided against the other's roots: every
    // withheld link resolves into its OWN fixture's out-of-tree directory.
    for (const w of [...out.concurrent.a, ...out.sequential.a]) {
      expect(w.resolved.startsWith(fxA.shared + path.sep), `${w.rel} resolves into fxA.shared`).toBe(true);
      expect(w.resolved.startsWith(fxB.base)).toBe(false);
    }
    for (const w of [...out.concurrent.b, ...out.sequential.b]) {
      expect(w.resolved.startsWith(fxB.shared + path.sep), `${w.rel} resolves into fxB.shared`).toBe(true);
      expect(w.resolved.startsWith(fxA.base)).toBe(false);
    }

    // 0 out-of-tree reaches: nothing in either scan got past the guard to the
    // real filesystem (28 did at the base while the wrong ledger was active).
    expect(reach.reaches.length, describeReaches(reach)).toBe(0);
  }, TEST_TIMEOUT);
});
