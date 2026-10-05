/**
 * A wall-clock budget for spawn tests that is measured, not assumed (#581).
 *
 * A suite that spawns the built CLI needs a budget so a hung command ends the
 * run instead of holding it open. Written as a constant, that budget is a
 * statement about one machine on one day: `secure` on a three-file tree
 * returns in seconds on a quiet machine, and the same spawn was measured past
 * its 240s constant while a second suite ran beside it. The tests that failed
 * that way changed from run to run and none of them was about the change under
 * test.
 *
 * So the budget here is relative to what the file itself has measured. Each
 * spawn may take `scale` times the slowest spawn the file has completed, and
 * never less than `floorMs`. A machine that is slow for every spawn raises its
 * own budget; a spawn far outside the file's baseline is still stopped.
 *
 * Two things follow from making the budget generous:
 *
 * - A hang must not cost one budget per test. The first spawn to exhaust its
 *   budget trips the breaker, and every later call throws without spawning,
 *   so a hung command costs the file one budget in total.
 * - The failure has to say what happened. A spawn stopped by a timeout used to
 *   surface as `expected null to be 2`. It now throws an error that carries the
 *   budget, the baseline it was derived from and the load average, so the
 *   reader can tell a loaded machine from a wrong verdict.
 *
 * `spawnSync` blocks the event loop, so the test runner cannot interrupt a
 * spawn: its own per-test timeout only relabels a test that has already
 * finished. A file that uses this helper sets that timeout to 0 and lets the
 * budget be the one bound.
 */
import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import * as os from 'node:os';

/** Budget for a spawn while nothing slower than `floorMs / scale` was seen. */
export const DEFAULT_FLOOR_MS = 900_000;
/** How many times the slowest completed spawn the next one may take. */
export const DEFAULT_SCALE = 8;

export interface SpawnBudgetOptions {
  floorMs?: number;
  scale?: number;
  /** Seams for this helper's own tests. */
  spawn?: typeof spawnSync;
  now?: () => number;
}

export interface SpawnBudget {
  /** Spawn `command` inside the current budget. Throws when it is exceeded. */
  run(command: string, args: string[], options?: { env?: NodeJS.ProcessEnv; cwd?: string }): SpawnSyncReturns<string>;
  /** The timeout the next spawn would be given, in milliseconds. */
  nextMs(): number;
}

/** A spawn was stopped at its budget, or was not started because one was. */
export class SpawnBudgetExceeded extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SpawnBudgetExceeded';
  }
}

export function createSpawnBudget(opts: SpawnBudgetOptions = {}): SpawnBudget {
  const floorMs = opts.floorMs ?? DEFAULT_FLOOR_MS;
  const scale = opts.scale ?? DEFAULT_SCALE;
  const spawn = opts.spawn ?? spawnSync;
  const now = opts.now ?? (() => performance.now());

  let slowestMs = 0;
  let tripped: string | null = null;

  const nextMs = (): number => Math.max(floorMs, Math.ceil(slowestMs * scale));

  function run(command: string, args: string[], options: { env?: NodeJS.ProcessEnv; cwd?: string } = {}) {
    if (tripped !== null) {
      throw new SpawnBudgetExceeded(`not spawned, because an earlier spawn in this file was stopped at its budget: ${tripped}`);
    }
    const budgetMs = nextMs();
    const started = now();
    const res = spawn(command, args, { ...options, encoding: 'utf-8', timeout: budgetMs });
    const elapsedMs = now() - started;

    if ((res.error as NodeJS.ErrnoException | undefined)?.code === 'ETIMEDOUT') {
      const baseline = slowestMs > 0
        ? `${scale}x the slowest spawn this file completed (${Math.round(slowestMs)} ms), floor ${floorMs} ms`
        : `the ${floorMs} ms floor, no spawn having completed yet`;
      tripped = `\`${[command, ...args].join(' ')}\` did not exit within ${budgetMs} ms (${baseline}). `
        + `1-minute load average ${os.loadavg()[0].toFixed(1)} on ${os.cpus().length} cores. `
        + 'Either the command hung or the machine is too loaded to run it: run this file on its own to tell which.';
      throw new SpawnBudgetExceeded(tripped);
    }

    // Only a spawn that finished is a measurement of how slow the machine is.
    slowestMs = Math.max(slowestMs, elapsedMs);
    return res;
  }

  return { run, nextMs };
}
