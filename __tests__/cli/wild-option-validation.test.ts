/**
 * #480 — `wild --tier` was not validated. `parseInt` read `--tier 99999` and
 * `--tier -5` as a filter no page matches: nothing was scanned, the empty set
 * scored 100/100 and the run exited 0, so a typo turned a failing gate green.
 * `--tier abc` parsed to NaN, which applied no filter and ran every tier
 * without saying so. `--timeout` / `--delay` fell back to their defaults on a
 * non-number the same way.
 *
 * Every cell here runs against a local path, so no request leaves the machine:
 * the option cells are refused before any fetch, and the zero-match cell's
 * three file-level fetches fail on the non-URL target. RED-ON-BASE: on
 * 044301c5 every refusal cell exits 0 and prints a Wild Resilience Score.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFresh } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { parseWildTier, parseWildTimeout, parseWildDelay, WILD_MAX_TIER } from '../../src/wild';

const CLI = path.join(__dirname, '..', '..', 'dist', 'cli.js');

function run(args: string[]) {
  const res = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 60_000,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: tempDir('hma-home-') },
  });
  return { status: res.status, out: res.stdout ?? '', err: res.stderr ?? '' };
}

describe('#480 wild integer options are parsed strictly', () => {
  it('accepts every published tier and nothing outside it', () => {
    expect(WILD_MAX_TIER).toBe(10);
    expect(parseWildTier(undefined)).toBeUndefined();
    expect(parseWildTier('1')).toBe(1);
    expect(parseWildTier('10')).toBe(10);
    expect(parseWildTier(' 5 ')).toBe(5);
    for (const bad of ['0', '11', '99999', '-5', 'abc', '', '5.5', '1e1', '0x5', '5abc']) {
      expect(() => parseWildTier(bad), `--tier '${bad}'`).toThrow(/--tier must be a whole number between 1 and 10/);
    }
  });

  it('refuses a timeout that would abort every fetch and a delay that is not a number', () => {
    expect(parseWildTimeout('15000')).toBe(15000);
    expect(parseWildDelay('0')).toBe(0);
    for (const bad of ['0', '-1', 'abc', '']) {
      expect(() => parseWildTimeout(bad), `--timeout '${bad}'`).toThrow(/--timeout must be a whole number/);
    }
    for (const bad of ['-1', 'abc', '']) {
      expect(() => parseWildDelay(bad), `--delay '${bad}'`).toThrow(/--delay must be a whole number/);
    }
  });
});

describe('#480 wild refuses a gate parameter that would scan nothing', { timeout: 120_000 }, () => {
  let target: string;
  beforeAll(() => {
    // A checkout that has not built fails here, naming the command to run; the
    // parser cases above read only the source and still report on their own.
    assertDistFresh();
    target = path.join(tempDir('hma-480-'), 'no-such-site');
  });

  for (const tier of ['99999', '-5', 'abc', '0', '']) {
    it(`--tier '${tier}' exits 1 before any request, with no score`, () => {
      for (const json of [false, true]) {
        const r = run(['wild', target, '--tier', tier, '--delay', '0', ...(json ? ['--json'] : [])]);
        expect(r.status, r.out + r.err).toBe(1);
        expect(r.err).toContain('--tier must be a whole number between 1 and 10');
        expect(r.out).not.toMatch(/Wild Resilience Score|Target:|"wildResilienceScore"/);
      }
    });
  }

  it('--timeout abc and --delay -1 are refused, not replaced by the default', () => {
    const t = run(['wild', target, '--timeout', 'abc']);
    expect(t.status).toBe(1);
    expect(t.err).toContain('--timeout must be a whole number');
    const d = run(['wild', target, '--delay', '-1']);
    expect(d.status).toBe(1);
    expect(d.err).toContain('--delay must be a whole number');
  });

  it('an in-range filter that selects no page exits 1 instead of scoring the empty set', () => {
    // jailbreak publishes tiers 1-5, so tier 7 is valid on its own and matches nothing here.
    for (const json of [false, true]) {
      const r = run(['wild', target, '--category', 'jailbreak', '--tier', '7', '--delay', '0', ...(json ? ['--json'] : [])]);
      expect(r.status, r.out + r.err).toBe(1);
      expect(r.out + r.err).toContain('No attack page matches --category jailbreak --tier 7');
      expect(r.out).not.toMatch(/Wild Resilience Score|"wildResilienceScore"/);
    }
  });

  it('help states the accepted tier range', () => {
    const r = run(['wild', '--help']);
    expect(r.out).toContain('Filter by specific difficulty tier (1-10)');
  });
});
