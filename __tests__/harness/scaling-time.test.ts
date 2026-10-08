/**
 * The "each flood shape costs linear time" suites time each case with
 * `timeScaling` and judge it with `scalesLinearly`
 * (__tests__/helpers/scaling-time.ts): 64 KiB against 1 MiB, at most 64x, or
 * both runs under 50 ms.
 *
 * Those suites used to compare 512 KiB with 1 MiB, at most 2.5x, and to hold
 * each 1 MiB run under 500 ms. Timed once per size, 23 cases failed that on
 * the GitHub runners: 22 on the ratio, at 2.57x to 4.84x, and one at 623 ms.
 * Timed as the median of seven rounds, the tag strip over a flood of `>` still
 * failed it on ubuntu-latest, at 2.63x and 2.70x, and one other case at 2.51x.
 * One doubling leaves a linear scan a factor of 1.25 below that bound; sixteen
 * times the input leaves it a factor of 4 below this one, and a quadratic scan
 * a factor of 4 above it.
 *
 * The helper's rules run here against a scripted clock, so this file does not
 * itself depend on how fast the machine is. The last block is a static gate on
 * the four suites: each times its cases through the helper, and none reads a
 * clock of its own.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  timeScaling,
  scalesLinearly,
  ROUNDS,
  SMALL_BYTES,
  FULL_BYTES,
  MAX_RATIO,
  FLOOR_MS,
  RULE,
} from '../helpers/scaling-time';

const SMALL = 's';
const FULL = 'f';

/** Stands in for a suite's flood: a token for each of the two sizes, and no other size. */
const input = (bytes: number): string => {
  if (bytes === SMALL_BYTES) return SMALL;
  if (bytes === FULL_BYTES) return FULL;
  throw new Error(`asked for an input of ${bytes} bytes`);
};

type Size = 'small' | 'full';

/**
 * A clock that moves only when a scripted run or preparation advances it.
 * `cost` gives the ms of a run from its size and its index among all runs:
 * indices 0 (64 KiB) and 1 (1 MiB) are the untimed first runs, and round `i`
 * runs indices 3i+2 (64 KiB), 3i+3 (1 MiB) and 3i+4 (64 KiB).
 */
function scripted(cost: (size: Size, index: number) => number, prepareMs = 0) {
  let clock = 0;
  let prepared = 0;
  const sizes: Size[] = [];
  const prepare = () => {
    prepared++;
    clock += prepareMs;
    return (s: string): void => {
      const size: Size = s === SMALL ? 'small' : 'full';
      clock += cost(size, sizes.length);
      sizes.push(size);
    };
  };
  return { prepare, now: () => clock, sizes, prepared: () => prepared };
}

const time = (cost: (size: Size, index: number) => number) => {
  const clock = scripted(cost);
  return timeScaling(clock.prepare, input, clock.now);
};

/** Fewer than half of the rounds. */
const MINORITY = Math.floor((ROUNDS - 1) / 2);
/** Whether run `index` is timed and falls in one of the first MINORITY rounds. */
const inMinority = (index: number): boolean => index >= 2 && Math.floor((index - 2) / 3) < MINORITY;

describe('timeScaling and scalesLinearly', () => {
  it('compare 64 KiB with sixteen times that, against the midpoint of linear and quadratic', () => {
    expect([SMALL_BYTES, FULL_BYTES]).toEqual([64 * 1024, 1024 * 1024]);
    // A linear scan costs 16x, a quadratic one 256x; 64x is a factor of 4 from each.
    expect(MAX_RATIO).toBe(Math.sqrt(16 * 256));
    expect(RULE).toBe('64 KiB -> 1 MiB at most 64x, or both under 50 ms');
  });

  it('runs each size once untimed, then times 64 KiB, 1 MiB and 64 KiB in each round', () => {
    const clock = scripted(() => 1);
    timeScaling(clock.prepare, input, clock.now);
    expect(ROUNDS).toBeGreaterThanOrEqual(3);
    expect(clock.sizes).toEqual([
      'small',
      'full',
      ...Array.from({ length: ROUNDS }, () => ['small', 'full', 'small'] as const).flat(),
    ]);
  });

  it('returns the fastest timed run of each size and the median ratio of the rounds', () => {
    // The untimed runs are the fastest of all and are left out; round 1 has a faster
    // first 64 KiB run (ratio 1600 / 95) and round 2 a faster 1 MiB run (ratio 15).
    const result = time((size, index) => {
      if (index < 2) return 1;
      if (size === 'small') return index === 5 ? 90 : 100;
      return index === 9 ? 1_500 : 1_600;
    });
    expect(result).toEqual({ tSmall: 90, tFull: 1_500, ratio: 16 });
  });

  it('prepares a fresh run before every run, outside the time it reports', () => {
    const clock = scripted((size) => (size === 'small' ? 100 : 1_600), 1_000);
    expect(timeScaling(clock.prepare, input, clock.now)).toEqual({ tSmall: 100, tFull: 1_600, ratio: 16 });
    expect(clock.prepared()).toBe(2 + 3 * ROUNDS);
  });

  it('gives a linear scan 16x on a machine that slows with every run', () => {
    // Each run costs half as much again as its base cost for every run before it.
    const result = time((size, index) => (size === 'small' ? 100 : 1_600) * (1 + 0.5 * index));
    expect(result.ratio).toBeCloseTo(16, 10);
    expect(scalesLinearly(result)).toBe(true);
  });

  it('passes a linear scan whose 1 MiB run is delayed in fewer than half of the rounds', () => {
    const result = time((size, index) => (size === 'small' ? 100 : 1_600 + (inMinority(index) ? 20_000 : 0)));
    expect(result).toEqual({ tSmall: 100, tFull: 1_600, ratio: 16 });
    expect(scalesLinearly(result)).toBe(true);
  });

  it('passes the tag strip over a flood of ">" as ubuntu-latest timed it, which one doubling measured at 2.64x', () => {
    // 23.2 ms at 512 KiB and 61.3 ms at 1 MiB in its fastest runs there. If its cost is
    // linear up to 512 KiB, its 64 KiB run takes an eighth of the 512 KiB one.
    const result = time((size) => (size === 'small' ? 23.2 / 8 : 61.3));
    expect(61.3 / 23.2).toBeGreaterThan(2.5);
    expect(result.ratio).toBeCloseTo(61.3 / 2.9, 10);
    expect(scalesLinearly(result)).toBe(true);
  });

  it('still fails a quadratic scan whose 64 KiB runs are delayed in fewer than half of the rounds', () => {
    // 100 ms at 64 KiB and 25,600 ms at 1 MiB; a delayed round measures 2.8x.
    const result = time((size, index) => (size === 'full' ? 25_600 : 100 + (inMinority(index) ? 9_000 : 0)));
    expect(result).toEqual({ tSmall: 100, tFull: 25_600, ratio: 256 });
    expect(scalesLinearly(result)).toBe(false);
  });

  it('fails a scan whose cost triples with every doubling of its input', () => {
    const result = time((size) => (size === 'small' ? 100 : 100 * 3 ** 4));
    expect(result.ratio).toBe(81);
    expect(scalesLinearly(result)).toBe(false);
  });

  it(`passes a case whose fastest runs of both sizes stay under ${FLOOR_MS} ms, whatever its ratio`, () => {
    const result = time((size) => (size === 'small' ? 0.125 : FLOOR_MS - 1));
    expect(result.ratio).toBeGreaterThan(MAX_RATIO);
    expect(scalesLinearly(result)).toBe(true);
  });

  it(`holds a case to the ratio once its fastest 1 MiB run takes ${FLOOR_MS} ms`, () => {
    // 0.125 ms keeps the scripted clock exact, so the 1 MiB run measures 50 ms and not a hair under.
    const result = time((size) => (size === 'small' ? 0.125 : FLOOR_MS));
    expect(result.ratio).toBeGreaterThan(MAX_RATIO);
    expect(scalesLinearly(result)).toBe(false);
  });
});

const SUITES = [
  'lazy-regex-chain-alternations.test.ts',
  'lazy-regex-head-tail.test.ts',
  'lazy-regex-sibling-sites.test.ts',
  'lazy-regex-word-chains.test.ts',
];

describe('each flood timing suite times its cases through the helper', () => {
  for (const file of SUITES) {
    const source = (): string => fs.readFileSync(path.join(__dirname, '..', file), 'utf8');

    it(`${file} times its "each flood shape costs linear time" block with timeScaling and judges it with scalesLinearly`, () => {
      const text = source();
      const start = text.indexOf("describe('each flood shape costs linear time'");
      expect(start, `${file} has no "each flood shape costs linear time" block`).toBeGreaterThanOrEqual(0);
      const block = text.slice(start, text.indexOf('\n});\n', start));
      expect(block).toContain('timeScaling(');
      expect(block).toContain('scalesLinearly(');
    });

    it(`${file} reads no clock of its own, so none of its cases is held to a time on the clock`, () => {
      expect(source()).not.toMatch(/performance\.now|Date\.now|process\.hrtime|elapsedMs\(/);
    });
  }
});
