/**
 * #581 — a spawn test's time budget follows what the file measured.
 *
 * `secure-unread-input-gate.test.ts` gave every spawn 240s and every test a
 * 240s or 300s cap. Both were constants calibrated on a quiet machine. With a
 * second suite running beside it the file failed on timeouts, a different
 * handful of cases each run, and vetoed pushes whose change it did not touch.
 * Reproduced without load by delaying each spawn 50s: the five-spawn
 * determinism case reported `Test timed out in 240000ms` with no spawn near
 * its own budget.
 *
 * Two layers are pinned here. The budget's rules run against a scripted clock,
 * so this file does not itself depend on how fast the machine is; the two
 * real-spawn cases use a child that either returns at once or cannot return in
 * time, so their outcome does not depend on it either. The last block is a
 * static gate on the suite the issue is about, because a constant put back
 * there passes every run on a quiet machine.
 */
import { describe, it, expect } from 'vitest';
import type { SpawnSyncReturns } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import ts from 'typescript';
import { createSpawnBudget, SpawnBudgetExceeded, DEFAULT_FLOOR_MS } from '../helpers/spawn-budget';

/** A stand-in `spawnSync` whose spawns take the scripted number of ms. */
function scripted(durations: (number | 'timeout')[]) {
  let clock = 0;
  const timeouts: number[] = [];
  const spawn = ((_cmd: string, _args: string[], options: { timeout: number }) => {
    const next = durations.shift();
    if (next === undefined) throw new Error('more spawns than the script allows');
    timeouts.push(options.timeout);
    if (next === 'timeout' || next > options.timeout) {
      clock += options.timeout;
      return { status: null, stdout: '', stderr: '', error: Object.assign(new Error('spawnSync ETIMEDOUT'), { code: 'ETIMEDOUT' }) };
    }
    clock += next;
    return { status: 0, stdout: 'ok', stderr: '' };
  }) as unknown as typeof import('node:child_process').spawnSync;
  return { spawn, now: () => clock, timeouts };
}

describe('#581 the spawn budget is scaled from measured spawns', () => {
  it('is the floor while nothing has been measured', () => {
    expect(createSpawnBudget({ floorMs: 1000, scale: 8 }).nextMs()).toBe(1000);
    expect(createSpawnBudget().nextMs()).toBe(DEFAULT_FLOOR_MS);
  });

  it('a spawn slower than the floor completes once the file has measured a slow machine', () => {
    // The shape of the defect. Under a constant budget the third spawn is
    // stopped at 1000 ms; here the 400 ms spawn before it raised the budget to
    // 3200 ms, so a machine that is slow for every spawn is not failed for it.
    const s = scripted([100, 400, 2500]);
    const budget = createSpawnBudget({ floorMs: 1000, scale: 8, spawn: s.spawn, now: s.now });
    for (let i = 0; i < 3; i++) expect(budget.run('cli', []).status).toBe(0);
    expect(s.timeouts).toEqual([1000, 1000, 3200]);
  });

  it('follows the SLOWEST completed spawn, so one fast spawn does not shrink it', () => {
    const s = scripted([500, 10]);
    const budget = createSpawnBudget({ floorMs: 1000, scale: 8, spawn: s.spawn, now: s.now });
    budget.run('cli', []);
    budget.run('cli', []);
    expect(budget.nextMs()).toBe(4000);
  });

  it('still stops a spawn far outside the baseline, and says what the budget was', () => {
    // Without this the helper could pass every case above by never timing out.
    const s = scripted([200, 'timeout']);
    const budget = createSpawnBudget({ floorMs: 1000, scale: 8, spawn: s.spawn, now: s.now });
    budget.run('cli', ['secure', 'tree']);
    let thrown: unknown;
    try { budget.run('cli', ['secure', 'tree']); } catch (e) { thrown = e; }
    expect(thrown).toBeInstanceOf(SpawnBudgetExceeded);
    const message = (thrown as Error).message;
    expect(message).toContain('`cli secure tree` did not exit within 1600 ms');
    expect(message).toContain('8x the slowest spawn this file completed (200 ms)');
    expect(message).toMatch(/1-minute load average \d+\.\d on \d+ cores/);
  });

  it('a hang costs the file one budget: after a timeout nothing else is spawned', () => {
    const s = scripted(['timeout']);
    const budget = createSpawnBudget({ floorMs: 1000, scale: 8, spawn: s.spawn, now: s.now });
    expect(() => budget.run('cli', [])).toThrow(SpawnBudgetExceeded);
    // The script holds no second spawn: reaching `spawn` again would throw a
    // different error than the one asserted.
    expect(() => budget.run('cli', [])).toThrow(/not spawned, because an earlier spawn in this file was stopped/);
    expect(s.timeouts).toEqual([1000]);
  });

  it('a spawn that timed out is not a measurement', () => {
    const s = scripted(['timeout']);
    const budget = createSpawnBudget({ floorMs: 1000, scale: 8, spawn: s.spawn, now: s.now });
    expect(() => budget.run('cli', [])).toThrow(SpawnBudgetExceeded);
    expect(budget.nextMs()).toBe(1000);
  });
});

describe('#581 the budget holds against a real child process', () => {
  it('returns the result of a spawn that exits inside the budget', () => {
    const res: SpawnSyncReturns<string> = createSpawnBudget().run(process.execPath, ['-e', "process.stdout.write('ok')"]);
    expect(res.status).toBe(0);
    expect(res.stdout).toBe('ok');
  });

  it('stops a child that outlasts the budget, and does not start the next one', () => {
    // The child sleeps far longer than the budget, so it times out on a machine
    // of any speed. The second command would leave a file behind if it ran.
    const marker = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hma-581-')), 'second-spawn-ran');
    const budget = createSpawnBudget({ floorMs: 300 });
    expect(() => budget.run(process.execPath, ['-e', 'setTimeout(() => {}, 600000)'])).toThrow(SpawnBudgetExceeded);
    expect(() => budget.run(process.execPath, ['-e', `require('fs').writeFileSync(${JSON.stringify(marker)}, '')`]))
      .toThrow(SpawnBudgetExceeded);
    expect(fs.existsSync(marker)).toBe(false);
    fs.rmSync(path.dirname(marker), { recursive: true, force: true });
  });
});

describe('#581 secure-unread-input-gate carries no wall-clock constant', () => {
  const FILE = path.resolve(__dirname, '..', 'cli', 'secure-unread-input-gate.test.ts');
  const text = fs.readFileSync(FILE, 'utf-8');
  const source = ts.createSourceFile(FILE, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);

  /** Every node in the file, comments excluded by construction. */
  function nodes(): ts.Node[] {
    const out: ts.Node[] = [];
    const visit = (n: ts.Node): void => { out.push(n); n.forEachChild(visit); };
    visit(source);
    return out;
  }

  /** `it`, `it.each(...)`, `describe` and their modifiers, by leftmost name. */
  function runnerCall(call: ts.CallExpression): string | null {
    let callee: ts.Expression = call.expression;
    while (ts.isPropertyAccessExpression(callee) || ts.isCallExpression(callee)) callee = callee.expression;
    return ts.isIdentifier(callee) && ['it', 'test', 'describe'].includes(callee.text) ? callee.text : null;
  }

  it('spawns through the measured budget, never through spawnSync with its own timeout', () => {
    const calls = nodes().filter(ts.isCallExpression).map((c) => c.expression.getText(source));
    expect(calls).toContain('createSpawnBudget');
    expect(calls).toContain('budget.run');
    expect(calls.filter((c) => /\bspawnSync$|\bexecFileSync$|\bexecSync$/.test(c))).toEqual([]);
  });

  it('every `timeout` it sets is 0, so the runner cap cannot fail a test for the time its spawns took', () => {
    const timeouts = nodes()
      .filter(ts.isPropertyAssignment)
      .filter((p) => p.name.getText(source) === 'timeout')
      .map((p) => p.initializer.getText(source));
    // Non-vacuity: the file does switch the cap off. With no `timeout` at all
    // the config's 180s default would apply to every case.
    expect(timeouts.length).toBeGreaterThan(0);
    expect(timeouts.filter((t) => t !== '0')).toEqual([]);
  });

  it('every describe switches the runner cap off, and no case passes a number as its own cap', () => {
    const calls = nodes().filter(ts.isCallExpression).filter((c) => runnerCall(c) !== null);
    const describes = calls.filter((c) => runnerCall(c) === 'describe');
    expect(describes.length).toBeGreaterThan(0);
    for (const d of describes) {
      const title = d.arguments[0].getText(source);
      expect(d.arguments[1]?.getText(source), `${title} does not switch the runner cap off`).toBe('NO_RUNNER_CAP');
    }
    const numericCaps = calls
      .filter((c) => c.arguments.length > 0 && ts.isNumericLiteral(c.arguments[c.arguments.length - 1]))
      .map((c) => `${c.arguments[0].getText(source)} -> ${c.arguments[c.arguments.length - 1].getText(source)}`);
    expect(numericCaps).toEqual([]);
  });
});
