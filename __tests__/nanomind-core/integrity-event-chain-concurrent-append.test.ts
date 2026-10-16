/**
 * #1123: processes that append to one integrity event log at the same time
 * keep its chain valid.
 *
 * `EventChain.append` reads the last event, links the next one to it and
 * appends. With nothing held between the read and the write, two processes
 * that started together read the same last event and wrote two events with
 * the same `seq` and `prevHash`, and `verify()` reported the log as broken
 * although no event was edited, inserted or removed. An append now holds
 * `<log>.lock` from the read to the write.
 *
 * Each writer is its own process, started by tsx on the TypeScript source,
 * and all of them wait for one start file, so their appends overlap.
 */
import { describe, it, expect } from 'vitest';
import { spawn } from 'node:child_process';
import { existsSync, utimesSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { EventChain } from '../../src/nanomind-core/security/integrity-verifier';
import { tempDir } from '../helpers/temp-dir';

const TSX = path.resolve(__dirname, '../../node_modules/.bin/tsx');
const VERIFIER = path.resolve(__dirname, '../../src/nanomind-core/security/integrity-verifier.ts').split(path.sep).join('/');

const WRITERS = 6;
const EVENTS_PER_WRITER = 40;

/** Writes the runner each writer process executes. */
function writeRunner(dir: string): string {
  const runner = path.join(dir, 'append-runner.ts');
  writeFileSync(
    runner,
    [
      "import { existsSync, writeFileSync } from 'node:fs';",
      `import { EventChain } from '${VERIFIER}';`,
      'const [chainPath, readyPath, goPath, writer, count] = process.argv.slice(2);',
      "writeFileSync(readyPath, '');",
      'const pause = new Int32Array(new SharedArrayBuffer(4));',
      'while (!existsSync(goPath)) Atomics.wait(pause, 0, 0, 1);',
      'const chain = new EventChain(chainPath);',
      "for (let i = 0; i < Number(count); i++) chain.append('startup', `writer ${writer} event ${i}`);",
    ].join('\n'),
  );
  return runner;
}

function exitOf(child: ReturnType<typeof spawn>): Promise<{ code: number | null; stderr: string }> {
  let stderr = '';
  child.stderr?.on('data', (d) => { stderr += String(d); });
  return new Promise((resolve) => child.on('close', (code) => resolve({ code, stderr })));
}

async function waitFor(paths: string[], timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!paths.every((p) => existsSync(p))) {
    if (Date.now() > deadline) throw new Error(`writers did not start: ${paths.filter((p) => !existsSync(p)).join(', ')}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}

describe('#1123 concurrent appends to the integrity event log', () => {
  it(`${WRITERS} processes appending ${EVENTS_PER_WRITER} events each leave one valid chain`, async () => {
    const dir = tempDir('hma-1123-chain-');
    const chainPath = path.join(dir, 'log', 'integrity-events.jsonl');
    const goPath = path.join(dir, 'go');
    const runner = writeRunner(dir);
    const ready: string[] = [];
    const exits: Array<Promise<{ code: number | null; stderr: string }>> = [];
    for (let w = 0; w < WRITERS; w++) {
      const readyPath = path.join(dir, `ready-${w}`);
      ready.push(readyPath);
      const child = spawn(TSX, [runner, chainPath, readyPath, goPath, String(w), String(EVENTS_PER_WRITER)], {
        stdio: ['ignore', 'ignore', 'pipe'],
      });
      exits.push(exitOf(child));
    }
    await waitFor(ready, 60_000);
    writeFileSync(goPath, '');
    for (const { code, stderr } of await Promise.all(exits)) expect(code, stderr).toBe(0);

    const chain = new EventChain(chainPath);
    const events = chain.readAll();
    expect(events).toHaveLength(WRITERS * EVENTS_PER_WRITER);
    expect(events.map((e) => e.seq)).toEqual(events.map((_, i) => i));
    expect(chain.verify()).toEqual({ valid: true, brokenAt: -1 });
    // Each writer's events are in the order it appended them.
    for (let w = 0; w < WRITERS; w++) {
      const mine = events.filter((e) => e.detail.startsWith(`writer ${w} `)).map((e) => e.detail);
      expect(mine).toEqual(Array.from({ length: EVENTS_PER_WRITER }, (_, i) => `writer ${w} event ${i}`));
    }
    expect(existsSync(chain.lockPath), 'the last append released its lock').toBe(false);
  }, 120_000);

  it('removes a lock left by a process that ended mid-append, and appends', () => {
    const dir = tempDir('hma-1123-stale-lock-');
    const chain = new EventChain(path.join(dir, 'integrity-events.jsonl'));
    chain.append('startup', 'first');
    writeFileSync(chain.lockPath, '');
    const old = new Date(Date.now() - 60_000);
    utimesSync(chain.lockPath, old, old);

    const event = chain.append('startup', 'second');
    expect(event.seq).toBe(1);
    expect(chain.verify()).toEqual({ valid: true, brokenAt: -1 });
    expect(existsSync(chain.lockPath)).toBe(false);
  });

  it('appends without the lock when another holder keeps it past the wait, and leaves that lock alone', () => {
    const dir = tempDir('hma-1123-held-lock-');
    const chain = new EventChain(path.join(dir, 'integrity-events.jsonl'));
    // A fresh lock file stands for a live holder that does not release it:
    // too new to remove as stale, so the append waits out its limit and then
    // appends, because a log write must not fail the check it records.
    writeFileSync(chain.lockPath, '');
    const started = Date.now();
    const event = chain.append('startup', 'first');
    const waited = Date.now() - started;
    expect(event.seq).toBe(0);
    expect(waited).toBeGreaterThanOrEqual(1_900);
    expect(waited).toBeLessThan(5_000);
    expect(chain.verify()).toEqual({ valid: true, brokenAt: -1 });
    expect(existsSync(chain.lockPath), 'the other holder\'s lock is not removed').toBe(true);
  });
});
