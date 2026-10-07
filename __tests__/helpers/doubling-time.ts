/**
 * Times a scan of a 512 KiB input against a scan of a 1 MiB input, for the
 * "each flood shape costs linear time" suites.
 *
 * Those suites require the 1 MiB scan to finish in under 500 ms and to cost
 * at most 2.5 times the 512 KiB scan: a linear scan doubles, a quadratic one
 * quadruples. Timed once each, the two runs also measure the machine. On the
 * GitHub runners, whose few cores the rest of the suite shares, cases that
 * scale by 1.7x to 2.2x on an idle machine failed at 2.6x to 4.8x, and one
 * 1 MiB scan took 623 ms.
 *
 * The fastest of several runs of each size does not fix that. When the load
 * never lets up, a 512 KiB run finds a quiet stretch more often than a 1 MiB
 * run, which takes twice as long, so the fastest runs still overstate the
 * ratio: with four suites on four slow cores, the fastest of five runs failed
 * 10 to 18 of the 401 cases per run, where a single run failed 9 to 11.
 *
 * So each of the ROUNDS rounds times a 512 KiB run, a 1 MiB run and a second
 * 512 KiB run back to back, and divides the 1 MiB time by the mean of the two
 * 512 KiB times. Both sides of that ratio cover the same number of bytes over
 * the same stretch of time: steady load slows both alike, and so does a
 * machine that speeds up or slows down at an even rate during the round. The
 * ratio returned is the median over the rounds, so load confined to fewer
 * than half of them cannot carry it outside the range of the other rounds.
 * The fastest run of each size is returned for the 500 ms bound and the 50 ms
 * floor, because time lost to other work only ever adds to a run.
 *
 * One untimed run on the smaller input comes first, to compile the code
 * paths. `prepare` is called before every run, outside the timed span, and
 * returns the function to time, so a suite can give each run fresh matchers
 * and no run can reuse what an earlier one cached. A scan whose cost grows
 * with the square of its input measures about 4x in every round that load
 * leaves alone, so its median stays near 4x unless load reaches most rounds,
 * and the suites still fail it.
 */
import { performance } from 'node:perf_hooks';

/** How many rounds are timed; each times 512 KiB, 1 MiB and 512 KiB again. */
export const ROUNDS = 7;

export interface DoublingTime {
  /** The fastest timed run on the smaller input, in ms. */
  tHalf: number;
  /** The fastest timed run on the larger input, in ms. */
  tFull: number;
  /** The median over the rounds of the larger run's time over the mean of the round's two smaller runs. */
  ratio: number;
}

export function timeDoubling(
  prepare: () => (input: string) => void,
  half: string,
  full: string,
  now: () => number = () => performance.now(),
): DoublingTime {
  prepare()(half);
  let tHalf = Infinity;
  let tFull = Infinity;
  const ratios: number[] = [];
  for (let i = 0; i < ROUNDS; i++) {
    const before = timed(prepare(), half, now);
    const middle = timed(prepare(), full, now);
    const after = timed(prepare(), half, now);
    tHalf = Math.min(tHalf, before, after);
    tFull = Math.min(tFull, middle);
    ratios.push(middle / Math.max((before + after) / 2, 0.001));
  }
  ratios.sort((a, b) => a - b);
  return { tHalf, tFull, ratio: ratios[Math.floor(ratios.length / 2)] };
}

function timed(run: (input: string) => void, input: string, now: () => number): number {
  const t0 = now();
  run(input);
  return now() - t0;
}
