/**
 * The "each flood shape costs linear time" suites time each case with
 * `timeDoubling` (__tests__/helpers/doubling-time.ts).
 *
 * Each of those suites timed one run of a 512 KiB input and one run of a
 * 1 MiB input, and failed when the second took more than 2.5 times the first
 * or more than 500 ms. On the GitHub runners, 14 such cases failed on
 * ubuntu-latest and 9 on macos-latest, at 2.6x to 4.8x, and one took 623 ms.
 * The same cases scale by 1.7x to 2.2x on an idle machine: what decided each
 * result was the load beside the run, not the scan.
 *
 * The helper's rules run here against a scripted clock, so this file does not
 * itself depend on how fast the machine is. The last block is a static gate on
 * the four suites, because a single timed run put back there passes every run
 * on an idle machine.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { timeDoubling, ROUNDS } from '../helpers/doubling-time';

const HALF = 'h'.repeat(512);
const FULL = 'f'.repeat(1024);

type Size = 'half' | 'full';

/**
 * A clock that moves only when a scripted run or preparation advances it.
 * `cost` gives the ms of a run from its size and its index among all runs:
 * index 0 is the untimed first run, and round `i` runs indices 3i+1 (512 KiB),
 * 3i+2 (1 MiB) and 3i+3 (512 KiB).
 */
function scripted(cost: (size: Size, index: number) => number, prepareMs = 0) {
  let clock = 0;
  let prepared = 0;
  const sizes: Size[] = [];
  const prepare = () => {
    prepared++;
    clock += prepareMs;
    return (input: string): void => {
      const size: Size = input === HALF ? 'half' : 'full';
      clock += cost(size, sizes.length);
      sizes.push(size);
    };
  };
  return { prepare, now: () => clock, sizes, prepared: () => prepared };
}

const time = (cost: (size: Size, index: number) => number) => {
  const clock = scripted(cost);
  return timeDoubling(clock.prepare, HALF, FULL, clock.now);
};

/** The bounds each suite asserts, on the values it is given. */
const withinBounds = (tHalf: number, tFull: number, ratio: number): boolean =>
  tFull < 500 && ((tHalf < 50 && tFull < 50) || ratio <= 2.5);

/** Fewer than half of the rounds. */
const MINORITY = Math.floor((ROUNDS - 1) / 2);
const roundOf = (index: number): number => Math.floor((index - 1) / 3);

describe('timeDoubling', () => {
  it('runs the smaller input once untimed, then times 512 KiB, 1 MiB and 512 KiB in each round', () => {
    const clock = scripted(() => 1);
    timeDoubling(clock.prepare, HALF, FULL, clock.now);
    expect(ROUNDS).toBeGreaterThanOrEqual(3);
    expect(clock.sizes).toEqual([
      'half',
      ...Array.from({ length: ROUNDS }, () => ['half', 'full', 'half'] as const).flat(),
    ]);
  });

  it('returns the fastest timed run of each size and the median ratio of the rounds', () => {
    // The untimed run is the fastest of all and is left out; round 1 has a faster
    // first 512 KiB run (ratio 200 / 95) and round 2 a faster 1 MiB run (ratio 1.8).
    const result = time((size, index) => {
      if (index === 0) return 1;
      if (size === 'half') return index === 4 ? 90 : 100;
      return index === 8 ? 180 : 200;
    });
    expect(result).toEqual({ tHalf: 90, tFull: 180, ratio: 2 });
  });

  it('prepares a fresh run before every run, outside the time it reports', () => {
    const clock = scripted((size) => (size === 'half' ? 100 : 200), 1_000);
    expect(timeDoubling(clock.prepare, HALF, FULL, clock.now)).toEqual({ tHalf: 100, tFull: 200, ratio: 2 });
    expect(clock.prepared()).toBe(1 + 3 * ROUNDS);
  });

  it('gives a linear scan 2x on a machine that slows with every run, where the fastest run of each size gives 2.67x', () => {
    // Each run costs half as much again as its base cost for every run before it.
    const cost = (size: Size, index: number): number => (size === 'half' ? 100 : 200) * (1 + 0.5 * index);
    const { tHalf, tFull, ratio } = time(cost);
    expect(ratio).toBeCloseTo(2, 10);
    expect(withinBounds(tHalf, tFull, ratio)).toBe(true);
    // The first timed run of each size (indices 1 and 2) is also the fastest of each size.
    expect([tHalf, tFull]).toEqual([cost('half', 1), cost('full', 2)]);
    expect(tFull / tHalf).toBeCloseTo(400 / 150, 10);
    expect(withinBounds(tHalf, tFull, tFull / tHalf)).toBe(false);
  });

  it('passes a linear scan whose 1 MiB run is delayed in fewer than half of the rounds, which one run of each size failed', () => {
    const cost = (size: Size, index: number): number =>
      size === 'half' ? 100 : 200 + (roundOf(index) < MINORITY ? 300 : 0);
    const { tHalf, tFull, ratio } = time(cost);
    expect({ tHalf, tFull, ratio }).toEqual({ tHalf: 100, tFull: 200, ratio: 2 });
    expect(withinBounds(tHalf, tFull, ratio)).toBe(true);
    // One run of each size, as the suites timed before: 100 ms and 500 ms.
    expect(withinBounds(cost('half', 1), cost('full', 2), cost('full', 2) / cost('half', 1))).toBe(false);
  });

  it('still fails a quadratic scan whose 512 KiB runs are delayed in fewer than half of the rounds', () => {
    // 100 ms at 512 KiB and 400 ms at 1 MiB; a delayed round measures 1x.
    const cost = (size: Size, index: number): number =>
      size === 'full' ? 400 : 100 + (index > 0 && roundOf(index) < MINORITY ? 300 : 0);
    const { tHalf, tFull, ratio } = time(cost);
    expect({ tHalf, tFull, ratio }).toEqual({ tHalf: 100, tFull: 400, ratio: 4 });
    expect(withinBounds(tHalf, tFull, ratio)).toBe(false);
  });
});

const SUITES = [
  'lazy-regex-chain-alternations.test.ts',
  'lazy-regex-head-tail.test.ts',
  'lazy-regex-sibling-sites.test.ts',
  'lazy-regex-word-chains.test.ts',
];

describe('each flood timing suite times its cases with timeDoubling', () => {
  for (const file of SUITES) {
    it(`${file} times its "each flood shape costs linear time" block with timeDoubling`, () => {
      const text = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
      const start = text.indexOf("describe('each flood shape costs linear time'");
      expect(start, `${file} has no "each flood shape costs linear time" block`).toBeGreaterThanOrEqual(0);
      const block = text.slice(start, text.indexOf('\n});\n', start));
      expect(block).toContain('timeDoubling(');
      expect(block).not.toMatch(/performance\.now|elapsedMs\(/);
    });
  }
});
