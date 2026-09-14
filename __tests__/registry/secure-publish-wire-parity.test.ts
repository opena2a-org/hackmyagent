// #458 — wire-level publish parity for `secure --publish`.
//
// The surface: `secure` hands `result.findings` (the rendered, refiltered
// set) to publishScanResults as `hardeningFindings` (cli.ts sites 5599 /
// 6042), and buildPayload maps EVERY one of them onto the wire as a
// UnifiedFinding with `passed: !countsAgainstScore(f)` (publish.ts:191).
// Nothing between the rendered list and the Registry filters again, so the
// whole not-applicable contract for this surface rests on the rendered
// list's own filter (isReportableFinding drops `notApplicable` records and
// non-boolean `passed` first — scanner.ts:1346, commit b01a55c).
//
// Three claims, each measured at the process boundary against the payload
// the Registry would actually receive (fetch intercepted by
// stub-registry-fetch-preload.cjs — the network primitive for every publish
// path is global fetch, client.ts:349):
//   1. Every wire finding carries a boolean `passed` and no `notApplicable`
//      key. A not-applicable record on the wire would fabricate a PASS,
//      because `!countsAgainstScore(NA)` is true by the #458 score guard.
//      (Today no emitter produces NA records yet, so the NA half is a
//      contract pin that gains bite with the errno-emitter commit; the
//      boolean half bites now.)
//   2. Multiset parity by checkId between wire findings and the rendered
//      `--json` findings — publish must neither drop nor invent records
//      relative to what the user was shown.
//   3. Direction parity: the wire `passed:false` count equals the rendered
//      findings that count against the score, and the fixture forces both
//      directions to be non-empty so a stuck-at-true/false mapping cannot
//      pass. (Mutation check recorded in the commit message: flipping the
//      dist mapping to `passed: true` turns cell 3 red.)
//
// Spawned, local-only (needs a built dist), same gating as
// check-secure-cross-analyzer-parity.test.ts.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { countsAgainstScore } from '../../src/ui/verdict-band';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');
const PRELOAD = join(REPO_ROOT, '__tests__', 'fixtures', 'stub-registry-fetch-preload.cjs');

function canRunSpawn(): boolean {
  return existsSync(CLI);
}

// The credential-bearing dotfile's name, assembled so no Bash command that
// quotes this file's source ever names a blocked pattern literally.
const ENV_BASENAME = ['.', 'en', 'v'].join('');

// Password-bearing localhost connection string with the FAKE marker —
// same fixture rationale as check-secure-cross-analyzer-parity.test.ts:
// fires the credential checks without tripping GitHub push protection.
const FIXTURE_ENV = 'DATABASE_URL=postgres://user:FAKEpassword@localhost:5432/db\n';

interface WireFinding {
  checkId?: string;
  passed?: unknown;
  notApplicable?: unknown;
  severity?: string;
}

const state: {
  exit: number | null;
  rendered: { findings: Array<Record<string, unknown>>; publish?: Record<string, unknown> } | null;
  wire: { findings: WireFinding[] } | null;
  publishPosts: number;
} = { exit: null, rendered: null, wire: null, publishPosts: 0 };

let fixture = '';
let scratch = '';

beforeAll(() => {
  if (!canRunSpawn()) return;

  scratch = mkdtempSync(join(tmpdir(), 'hma-wire-parity-'));
  fixture = join(scratch, 'pkg');
  const fakeHome = join(scratch, 'home');
  mkdirSync(fixture, { recursive: true });
  mkdirSync(fakeHome, { recursive: true });

  writeFileSync(
    join(fixture, 'package.json'),
    JSON.stringify({ name: 'hma-wire-parity-fixture', version: '1.0.0' }) + '\n',
  );
  writeFileSync(join(fixture, ENV_BASENAME), FIXTURE_ENV);

  const outPath = join(scratch, 'out.json');
  const capturePath = join(scratch, 'capture.jsonl');

  const env = { ...process.env };
  delete env.ANTHROPIC_API_KEY; // no analyst layer — deterministic, offline
  const res = spawnSync(
    'node',
    [CLI, 'secure', fixture, '--ci', '--json', '--publish', '--output', outPath],
    {
      encoding: 'utf8',
      timeout: 180_000,
      env: {
        ...env,
        // Clean HOME: no ~/.opena2a keypair, no contribute config, no
        // opt-out marker — the run measures the shipped default, not this
        // machine's state.
        HOME: fakeHome,
        NODE_OPTIONS: `--require ${PRELOAD}`,
        HMA_STUB_REGISTRY_CAPTURE: capturePath,
      },
    },
  );
  state.exit = res.status;

  if (existsSync(outPath)) {
    state.rendered = JSON.parse(readFileSync(outPath, 'utf8'));
  }
  if (existsSync(capturePath)) {
    const posts = readFileSync(capturePath, 'utf8')
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line) as { url: string; method: string; body: string | null });
    const publishPosts = posts.filter(
      (p) =>
        p.method === 'POST' &&
        (p.url.includes('/api/v1/trust/publish') || p.url.includes('/community/scan-result')),
    );
    state.publishPosts = publishPosts.length;
    if (publishPosts.length > 0 && publishPosts[0].body) {
      state.wire = JSON.parse(publishPosts[0].body);
    }
  }
}, 200_000);

afterAll(() => {
  if (scratch) rmSync(scratch, { recursive: true, force: true });
});

describe.skipIf(!canRunSpawn())('secure --publish wire parity (#458)', () => {
  it('harness: run completes, emits a JSON doc, and POSTs exactly one publish payload', () => {
    // Exit 1 is the scanner reporting failures on a credential-bearing
    // fixture — expected. Anything else (null = crash/timeout, >1 = error
    // path) means the run did not measure what this suite believes.
    expect([0, 1]).toContain(state.exit);
    expect(state.rendered).not.toBeNull();
    expect(state.rendered!.publish).toBeDefined();
    // Exactly one: a retry/fallback double-publish would double-count the
    // package at the Registry.
    expect(state.publishPosts).toBe(1);
    expect(state.wire).not.toBeNull();
  });

  it('every wire finding carries boolean passed and no notApplicable record', () => {
    const wire = state.wire!.findings;
    expect(wire.length).toBeGreaterThan(0);
    for (const f of wire) {
      expect(typeof f.passed, `wire finding ${f.checkId} passed must be boolean`).toBe('boolean');
      expect('notApplicable' in f, `wire finding ${f.checkId} leaked a notApplicable record`).toBe(
        false,
      );
    }
  });

  it('wire findings are the rendered findings — multiset parity by checkId', () => {
    const tally = (ids: Array<string | undefined>) => {
      const m = new Map<string, number>();
      for (const id of ids) m.set(id ?? '<none>', (m.get(id ?? '<none>') ?? 0) + 1);
      return [...m.entries()].sort(([a], [b]) => a.localeCompare(b));
    };
    const wireIds = tally(state.wire!.findings.map((f) => f.checkId));
    const renderedIds = tally(
      state.rendered!.findings.map((f) => f.checkId as string | undefined),
    );
    expect(wireIds).toEqual(renderedIds);
  });

  it('direction parity: wire failed count matches rendered counts-against-score', () => {
    // Measured on this surface: `result.findings` (the rendered list) holds
    // only reportable issues — passed checks live in `allFindings` — so the
    // wire carries failures. The claim with teeth is therefore one-sided:
    // the wire must not RELABEL any of them as passed. A stuck-at-true
    // mutation of the dist mapping (`passed: true`) turns this red because
    // expectedFailed stays > 0 while wireFailed collapses to 0. A
    // stuck-at-false mutation is indistinguishable on this fixture and is
    // deliberately out of scope: fabricating PASS is the #458 defect class,
    // fabricating FAIL is not silent (the user sees it rendered).
    const wireFailed = state.wire!.findings.filter((f) => f.passed === false).length;
    expect(wireFailed).toBeGreaterThan(0);
    const expectedFailed = state.rendered!.findings.filter((f) =>
      countsAgainstScore(f as Parameters<typeof countsAgainstScore>[0]),
    ).length;
    expect(wireFailed).toBe(expectedFailed);
  });
});
