import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

/**
 * #454 — the `--ci` contract.
 *
 * `main()` strips `--ci` from `process.argv` before Commander parses it, so a
 * command's own `options.ci` never populated. Every bare `options.ci` read was
 * therefore dead. Four of them existed: two in `secure` (contribute-disable,
 * and the flag passed into `orchestrateNanoMind`) and two in `scan-soul`
 * (contribute-disable, and deep-progress display).
 *
 * `[CHIEF-CPO]` ruled the contract (COUNCIL_LEDGER.md, 2026-08-11): `--ci` is an
 * OUTPUT-MODE flag. It suppresses prompts and turns contribution off. It never
 * changes the exit code. The unreachable any-finding gate in `secure` was
 * DELETED rather than made reachable, matching the #390 precedent in `scan-soul`.
 *
 * Measured on `main` @ be4a1da, persisted opt-in, isolated HOME:
 *   secure --ci      -> 2 events queued (scan_result, scan_ping), exit 0
 *   scan-soul --ci   -> 2 events queued, exit 1
 * and after the fix, 0 and 0 with both exit codes unmoved.
 */

const CLI = join(__dirname, '..', '..', 'dist', 'cli.js');

/** A tree whose only finding is LOW (missing .gitignore). Scores 98/100, exits 0. */
function makeLowOnlyFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'hma-454-low-'));
  writeFileSync(join(dir, 'package.json'), '{"name":"fx-low","version":"1.0.0"}\n');
  writeFileSync(join(dir, 'index.js'), 'console.log("hello");\n');
  return dir;
}

function makeSoulFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'hma-454-soul-'));
  writeFileSync(
    join(dir, 'SOUL.md'),
    '# Agent Soul\n\n## Identity\nName: fx-agent\n\n## Safety\nNever exfiltrate credentials.\n\n## Boundaries\nStay in the working directory.\n',
  );
  return dir;
}

/**
 * A HOME carrying a prior contribution opt-in.
 *
 * REGISTRY_URL must be `http://localhost:*`, not `http://127.0.0.1:*` —
 * `validateRegistryUrl` accepts only https and localhost, and an invalid value
 * aborts the run before it scans, which would make every cell below read exit 1.
 */
function makeOptedInHome(): string {
  const home = mkdtempSync(join(tmpdir(), 'hma-454-home-'));
  mkdirSync(join(home, '.opena2a'), { recursive: true });
  writeFileSync(join(home, '.opena2a', 'config.json'), '{"contribute":{"enabled":true}}\n');
  return home;
}

/**
 * The queue file is an object `{"events":[…]}`, NOT a bare array. A counter
 * written as `Array.isArray(q) ? q.length : 0` returns 0 for every run and
 * reads as a permanent pass. That inversion silently produced a clean baseline
 * during this fix before it was caught.
 */
function countQueued(home: string): number {
  const f = join(home, '.opena2a', 'contribute-queue.json');
  if (!existsSync(f)) return 0;
  const q = JSON.parse(readFileSync(f, 'utf8'));
  const events = Array.isArray(q) ? q : (q.events ?? []);
  return events.length;
}

function run(args: string[], home?: string): { code: number; home: string } {
  const h = home ?? makeOptedInHome();
  const r = spawnSync(process.execPath, [CLI, ...args], {
    env: { ...process.env, HOME: h, REGISTRY_URL: 'http://localhost:9' },
    encoding: 'utf8',
  });
  return { code: r.status ?? -1, home: h };
}

describe('#454 — --ci is an output-mode flag', () => {
  beforeAll(() => {
    assertDistFreshIfPresent();
  });

  describe('contribution', () => {
    /**
     * NON-VACUITY GUARD. If the fixture never queues anything, "--ci queues 0"
     * is trivially true and the pin below is worthless. This asserts the
     * no-flag run DOES queue through the identical harness, so the assertion
     * that follows is measuring the flag and not an inert fixture.
     */
    it('queues events without --ci, so the --ci assertion is not vacuous', () => {
      const dir = makeLowOnlyFixture();
      const { home, code } = run(['secure', dir]);
      expect(code).toBe(0);
      expect(countQueued(home)).toBeGreaterThan(0);
    });

    it('secure --ci queues nothing despite a persisted opt-in', () => {
      const dir = makeLowOnlyFixture();
      const { home } = run(['secure', dir, '--ci']);
      expect(countQueued(home)).toBe(0);
    });

    it('scan-soul --ci queues nothing despite a persisted opt-in', () => {
      const dir = makeSoulFixture();
      const noFlag = run(['scan-soul', dir]);
      expect(countQueued(noFlag.home)).toBeGreaterThan(0); // non-vacuity

      const { home } = run(['scan-soul', dir, '--ci']);
      expect(countQueued(home)).toBe(0);
    });

    it('an explicit --contribute still wins over --ci', () => {
      const dir = makeLowOnlyFixture();
      const { home } = run(['secure', dir, '--ci', '--contribute']);
      expect(countQueued(home)).toBeGreaterThan(0);
    });
  });

  describe('exit codes are unmoved by --ci', () => {
    /**
     * This pin passes on pre-fix `main` too — there it passes because the flag
     * was dead. It is not a red-proof of the fix; it is the guard against the
     * HALF fix. Wiring the reads through isCiMode() WITHOUT deleting the
     * any-finding gate at the old cli.ts:5631 flips this LOW-only tree from
     * exit 0 to exit 1, and this assertion is what catches that.
     */
    it('a LOW-only tree exits 0 with and without --ci', () => {
      const dir = makeLowOnlyFixture();
      expect(run(['secure', dir]).code).toBe(0);
      expect(run(['secure', dir, '--ci']).code).toBe(0);
    });

    it('--fail-below still gates independently of --ci', () => {
      const dir = makeLowOnlyFixture();
      expect(run(['secure', dir, '--fail-below', '100']).code).toBe(1);
      expect(run(['secure', dir, '--ci', '--fail-below', '100']).code).toBe(1);
    });

    it('scan-soul exit code is identical with and without --ci', () => {
      const dir = makeSoulFixture();
      expect(run(['scan-soul', dir, '--ci']).code).toBe(run(['scan-soul', dir]).code);
    });
  });

  describe('the argv strip still shields the commands that do not declare --ci', () => {
    /**
     * Only `secure` and `scan-soul` declare `--ci`; the other 23 commands would
     * have Commander reject it as an unknown option. The strip is what lets
     * them tolerate it, so it stays — the fix is to the READS, not the strip.
     * "Unknown option" surfaces as exit 1 with a usage error, so this asserts
     * parity against the same command run without the flag.
     */
    it('detect tolerates --ci', () => {
      const dir = makeLowOnlyFixture();
      expect(run(['detect', dir, '--ci']).code).toBe(run(['detect', dir]).code);
    });

    it('check-metadata tolerates --ci', () => {
      const dir = makeLowOnlyFixture();
      expect(run(['check-metadata', dir, '--ci']).code).toBe(run(['check-metadata', dir]).code);
    });
  });

  describe('help text does not promise an exit-code effect', () => {
    it('neither command claims "exit non-zero on findings" for --ci', () => {
      for (const cmd of ['secure', 'scan-soul']) {
        const r = spawnSync(process.execPath, [CLI, cmd, '--help'], { encoding: 'utf8' });
        const help = `${r.stdout}${r.stderr}`;
        const ciLine = help.split('\n').find((l) => l.includes('--ci'));
        expect(ciLine, `${cmd} --help has no --ci line`).toBeDefined();
        expect(ciLine!).not.toMatch(/exit non-zero/i);
      }
    });
  });
});
