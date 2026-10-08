/**
 * Times a scan of a 64 KiB input against a scan of a 1 MiB input, and judges
 * the result, for the "each flood shape costs linear time" suites.
 *
 * Sixteen times the input costs a linear scan about 16 times as much and a
 * quadratic one about 256 times. A case passes when its ratio is at most
 * MAX_RATIO, 64, the geometric midpoint of the two: a factor of 4 from each.
 *
 * The suites used to compare 512 KiB with 1 MiB against a bound of 2.5x. One
 * doubling apart, a linear scan sits only 1.25 times below that bound, and the
 * GitHub runners used up the difference. Timed once per size, cases that scale
 * by 1.7x to 2.2x on an idle machine measured 2.6x to 4.8x there. Timed as the
 * median of seven rounds, the tag strip over a flood of `>` still measured
 * 2.63x and 2.70x on ubuntu-latest. It runs one regex match per `>`: the 512K
 * matches at 512 KiB took 23 to 25 ms there and the 1M matches at 1 MiB 61 to
 * 62 ms, while the 512K matches of a 1 MiB flood of `<>` took 26 to 29 ms. A
 * cost per match that rises once, past some size, moves a ratio taken over
 * sixteen times the input by the same factor as one taken over a doubling,
 * and the factor of 4 leaves room for it.
 *
 * Each of the ROUNDS rounds times a 64 KiB run, a 1 MiB run and a second
 * 64 KiB run back to back, and divides the 1 MiB time by the mean of the two
 * 64 KiB times. Both sides of that ratio cover the same stretch of time:
 * steady load slows both alike, and so does a machine that speeds up or slows
 * down at an even rate during the round. The ratio returned is the median over
 * the rounds, so load confined to fewer than half of them cannot carry it
 * outside the range of the other rounds. To fail a scan that measures 16x,
 * load has to add three times the 1 MiB run's own time to that run, in most
 * rounds.
 *
 * A case whose fastest runs of both sizes stay under FLOOR_MS passes without
 * the ratio, because a run that short times the machine more than the scan.
 * The floor only ever passes a case. There is no limit on the 1 MiB time
 * itself: such a limit measures the runner, and one linear scan took 623 ms
 * there against a limit of 500 ms.
 *
 * One untimed run of each size comes first, to compile the code paths.
 * `prepare` is called before every run, outside the timed span, and returns
 * the function to time, so a suite can give each run fresh matchers and no run
 * can reuse what an earlier one cached.
 */
import { performance } from 'node:perf_hooks';

const KiB = 1024;

/** The smaller input, in bytes. */
export const SMALL_BYTES = 64 * KiB;

/** The larger input, in bytes: sixteen times the smaller one. */
export const FULL_BYTES = 16 * SMALL_BYTES;

/** How many rounds are timed; each times 64 KiB, 1 MiB and 64 KiB again. */
export const ROUNDS = 7;

/** The highest median ratio a case may show: between 16 (linear) and 256 (quadratic). */
export const MAX_RATIO = 64;

/** A case whose fastest runs of both sizes are under this many ms passes without the ratio. */
export const FLOOR_MS = 50;

/** The rule `scalesLinearly` applies, as the suites name their cases. */
export const RULE = `64 KiB -> 1 MiB at most ${MAX_RATIO}x, or both under ${FLOOR_MS} ms`;

export interface ScalingTime {
  /** The fastest timed run on the smaller input, in ms. */
  tSmall: number;
  /** The fastest timed run on the larger input, in ms. */
  tFull: number;
  /** The median over the rounds of the larger run's time over the mean of the round's two smaller runs. */
  ratio: number;
}

/** Times `prepare()`'s function on `input(SMALL_BYTES)` and `input(FULL_BYTES)`. */
export function timeScaling(
  prepare: () => (input: string) => void,
  input: (bytes: number) => string,
  now: () => number = () => performance.now(),
): ScalingTime {
  const small = input(SMALL_BYTES);
  const full = input(FULL_BYTES);
  prepare()(small);
  prepare()(full);
  let tSmall = Infinity;
  let tFull = Infinity;
  const ratios: number[] = [];
  for (let i = 0; i < ROUNDS; i++) {
    const before = timed(prepare(), small, now);
    const middle = timed(prepare(), full, now);
    const after = timed(prepare(), small, now);
    tSmall = Math.min(tSmall, before, after);
    tFull = Math.min(tFull, middle);
    ratios.push(middle / Math.max((before + after) / 2, 0.001));
  }
  ratios.sort((a, b) => a - b);
  return { tSmall, tFull, ratio: ratios[Math.floor(ratios.length / 2)] };
}

/** Whether a timed case passes `RULE`. */
export function scalesLinearly(t: ScalingTime): boolean {
  return (t.tSmall < FLOOR_MS && t.tFull < FLOOR_MS) || t.ratio <= MAX_RATIO;
}

/** The figures a suite logs for a case, and reports when it fails. */
export function describeScaling(t: ScalingTime): string {
  return `fastest 64KiB=${t.tSmall.toFixed(1)} ms, fastest 1MiB=${t.tFull.toFixed(1)} ms, median ratio=${t.ratio.toFixed(1)}x`;
}

function timed(run: (input: string) => void, input: string, now: () => number): number {
  const t0 = now();
  run(input);
  return now() - t0;
}
