/**
 * #350 (remainder) — spawn-level: endings that used to hard-exit now emit
 * their command event, refusals deliberately still do not, and the event
 * never carries argv.
 *
 * These are the live fixtures behind the exit-surface ratchet
 * (`__tests__/telemetry/exit-surface.test.ts` holds the STRUCTURAL claim;
 * this file holds the BEHAVIORAL one — #285's division). Events are observed
 * via `OPENA2A_TELEMETRY_DEBUG=print`, which echoes each payload to stderr
 * as `[opena2a:telemetry] {...}`. The endpoint is pinned to a dead local
 * port so no probe ever reaches the real Registry, and every send fails as
 * an instant connection refusal — which doubles as the latency cell's
 * condition: an unreachable endpoint must never hang the exit.
 *
 * Measured on this build (2026-08-26, darwin): detect exits 1 here because
 * the DEV machine has live AI assistants; CI machines may exit 0 or 2. The
 * claim is "one event on EVERY path", so the cells accept any settled code
 * and pin the event count and the success mapping for the code observed.
 *
 * RED-ON-BASE cells (detect, trust) fail on the b44baf9 build — bare
 * `process.exit` before the postAction hook meant zero events. PIN cells
 * pass on both builds and hold a chosen behavior against drift. The
 * converted npm-name-not-found ending (src/cli.ts, `check`'s unmeasured
 * arm) has no deterministic offline trigger, so it is held by the
 * structural ratchet plus the funnel mechanism these cells prove, not by
 * a spawn of its own.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

// Connection-refused instantly on every platform; nothing listens on the
// discard port. Same idiom as settled-outbound-claims.test.ts.
const DEAD_TELEMETRY = 'http://127.0.0.1:9';
const DEAD_REGISTRY = 'http://localhost:9';
// A string that appears ONLY in argv. If any event payload ever contains it,
// user input leaked into telemetry.
const ARGV_MARKER = 'xx-argv-canary-350-xx';

const cleanups: string[] = [];
afterAll(() => {
  for (const d of cleanups) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
});

function tmp(prefix: string): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanups.push(d);
  return d;
}

interface Run {
  status: number | null;
  events: Array<{ name: string; success: boolean } & Record<string, unknown>>;
  raw: string[];
  elapsedMs: number;
}

function run(args: string[], cwd: string): Run {
  const t0 = Date.now();
  const r = spawnSync(process.execPath, [CLI, ...args], {
    cwd,
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      NO_COLOR: '1',
      HOME: tmp('hma-350-home-'),
      OPENA2A_TELEMETRY_DEBUG: 'print',
      OPENA2A_TELEMETRY_URL: DEAD_TELEMETRY,
    },
  });
  const raw = (r.stderr ?? '')
    .split('\n')
    .filter((l) => l.includes('[opena2a:telemetry]'))
    .map((l) => l.slice(l.indexOf('{')));
  return { status: r.status, events: raw.map((l) => JSON.parse(l)), raw, elapsedMs: Date.now() - t0 };
}

describe('#350 endings emit their command event', { timeout: 300_000 }, () => {
  it('RED-ON-BASE: detect emits exactly one event on every path, and the code still reaches the shell', () => {
    // detect's final `process.exit(exitCode)` was the canonical dark ending:
    // every run ended before the postAction hook. Now every path settles
    // through the funnel. The machine decides the code (0 clean / 1 findings
    // / 2 nothing to examine); the EVENT is what must be unconditional.
    const r = run(['detect'], tmp('hma-350-detect-'));
    expect([0, 1, 2]).toContain(r.status);
    expect(r.events, r.raw.join('\n')).toHaveLength(1);
    expect(r.events[0].name).toBe('detect');
    // detect passes no reason on the findings path, so success follows the
    // security-tool convention: 0 and 1 did the job, 2 measured nothing.
    expect(r.events[0].success).toBe(r.status! <= 1);
  });

  it("RED-ON-BASE: a caught crash reports success:false where the convention would say true (trust, reason='error')", () => {
    // trust is NOT in EXIT1_IS_FAILURE, so its conventional exit-1 mapping is
    // success:true. A dead registry makes the action throw into its catch,
    // which settles with reason 'error' — the ONLY path to success:false at
    // exit 1 for this command. This is the reason-outranks-convention proof
    // end to end: without the reason the fleet metric counts this crashed
    // run as a successful one.
    const r = run(['trust', 'express', '--registry-url', DEAD_REGISTRY], tmp('hma-350-trust-'));
    expect(r.status).toBe(1);
    expect(r.events, r.raw.join('\n')).toHaveLength(1);
    expect(r.events[0].name).toBe('trust');
    expect(r.events[0].success).toBe(false);
  });

  it('PIN: an unmeasured check emits its event and keeps exit 2', () => {
    // A path-style target that does not exist measures nothing (#417's
    // division: never "high risk" about a name that was never fetched).
    // This path settled through `finishWithFindings` BEFORE this change —
    // the cell is a pin against drift, not a red-on-base proof (an
    // adversarial round caught the earlier label claiming otherwise).
    const r = run(['check', `./no-such-dir-${ARGV_MARKER}`, '--offline'], tmp('hma-350-check-'));
    expect(r.status).toBe(2);
    expect(r.events, r.raw.join('\n')).toHaveLength(1);
    expect(r.events[0].name).toBe('check');
    expect(r.events[0].success).toBe(false);
  });

  it('PIN: a UsageError refusal is dark — it never lands in the crash bucket', () => {
    // `check skill:###bad###` is refused by the identifier parser before any
    // work (deterministic, offline). An adversarial round measured the first
    // sweep routing this through the catch's `exitRecorded(1, 'error')` —
    // a refused run counted as a crashed one, polluting the exact metric
    // this change exists to fix, against the CHANGELOG's stated deferral.
    // The refusal branch is a registered unsettled site again; #525 flips
    // this cell to expect one event with the refusal reason.
    const r = run(['check', 'skill:###bad###', '--offline'], tmp('hma-350-usage-'));
    expect(r.status).toBe(1);
    expect(r.events, r.raw.join('\n')).toHaveLength(0);
    expect(r.elapsedMs).toBeLessThan(20_000);
  });

  it('PIN: a pre-work refusal stays dark until the schema reason field lands (#525)', () => {
    // `secure -b <unknown>` refuses before any work starts. Class R sites
    // are DELIBERATELY unconverted in this slice: an event that cannot say
    // "refused" would land in the same bucket as a crash and skew the fleet
    // error rate. The exit-surface baseline carries these as exit-unsettled
    // ids; slice 2 (#525) flips this cell to expect one event with the
    // refusal reason — this pin is the record that the residue is chosen,
    // not forgotten.
    const target = tmp('hma-350-refuse-');
    const r = run(['secure', target, '-b', 'totally-bogus-benchmark', '--no-machine-posture'], tmp('hma-350-refuse-cwd-'));
    expect(r.status).toBe(1);
    expect(r.events, r.raw.join('\n')).toHaveLength(0);
    // The refusal must stay instant: it does no work and now also waits on
    // no telemetry. The generous bound is for CI machines; the regression it
    // catches is a flush wait (or a hang) attached to the refusal path.
    expect(r.elapsedMs).toBeLessThan(20_000);
  });

  it('CONTROL: a clean run still emits exactly one event through the postAction hook', () => {
    // The pre-existing emission path. If this cell fails alongside the
    // RED-ON-BASE cells, the sweep broke emission wholesale rather than
    // adding it to the dark endings.
    const r = run(['check-metadata'], tmp('hma-350-meta-'));
    expect(r.status).toBe(0);
    expect(r.events, r.raw.join('\n')).toHaveLength(1);
    expect(r.events[0].name).toBe('check-metadata');
    expect(r.events[0].success).toBe(true);
  });

  it('an unreachable endpoint never hangs a settled exit', () => {
    // exitRecorded awaits the bounded post (TELEMETRY_FLUSH_MS = 750ms,
    // unref'd race) — a converted ending with a dead endpoint must exit
    // promptly, not wait out a network stack timeout. trust-dead is the
    // fastest converted path (<1s measured locally); the bound only has to
    // catch a hang, not a slow CI box.
    const r = run(['trust', 'express', '--registry-url', DEAD_REGISTRY], tmp('hma-350-latency-'));
    expect(r.status).toBe(1);
    expect(r.elapsedMs).toBeLessThan(20_000);
  });

  it('no event ever carries argv', () => {
    // The reason vocabulary is closed and static precisely so no event field
    // can carry user input (#350's design constraint). The canary rides argv
    // through two different settlement paths — a trust package name into the
    // caught-crash funnel, a check target into the unmeasured arm — and
    // every payload from BOTH runs is scanned (an adversarial round caught
    // the first version scanning only one).
    const runs = [
      run(['trust', ARGV_MARKER, '--registry-url', DEAD_REGISTRY], tmp('hma-350-argv-')),
      run(['check', `./no-such-dir-${ARGV_MARKER}`, '--offline'], tmp('hma-350-argv2-')),
    ];
    for (const r of runs) {
      expect(r.events.length).toBeGreaterThan(0);
      for (const line of r.raw) {
        expect(line).not.toContain(ARGV_MARKER);
        expect(line).not.toContain('--registry-url');
        expect(line).not.toContain(DEAD_REGISTRY);
      }
    }
  });
});
