/**
 * HMA-21.AC3 — per-rule disclosure and the (checkId, channel) fold.
 *
 * `secure --json` and `check --json` carry a top-level `hmaignore` key iff a
 * `.hmaignore` exists at the target, with the CA's literal shape;
 * `rules[].checkId` upper-cased, `rules[].rule` as written, `expires` only on
 * active rules; attribution first-matching-rule WITHIN the winning tier
 * (whole-path, then `<path>:<CHECK>`, then `!<CHECK>`), the absorbed narrow
 * rule carrying `redundantTo` and `matched: 0`; Σ matched per (checkId,
 * channel) equals the Row count; `summarizeSuppressed` folds by
 * `checkId + '\0' + suppressedBy`; and a document from a tree without the
 * file is identical to one from a tree whose file adds nothing — the
 * `hmaignore` key is the only delta the file's presence introduces.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { summarizeSuppressed } from '../../src/ui/verdict-band';
import { matchesCheckPattern } from '../../src/hardening/scanner';

beforeAll(assertDistFreshIfPresent);

let fixture: string;
let home: string;

beforeAll(() => {
  fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'hma21-disc-'));
  fs.writeFileSync(path.join(fixture, 'danger.py'), 'eval(user_input)\n');
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'hma21-disc-home-'));
});

afterAll(() => {
  for (const d of [fixture, home]) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function run(command: 'secure' | 'check', hmaignore?: string): { status: number | null; json: any } {
  if (hmaignore === undefined) {
    fs.rmSync(path.join(fixture, '.hmaignore'), { force: true });
  } else {
    fs.writeFileSync(path.join(fixture, '.hmaignore'), hmaignore);
  }
  const args = command === 'secure' ? [CLI, 'secure', '--ci', '--json', '.'] : [CLI, 'check', '--json', '.'];
  const r = spawnSync(process.execPath, args, {
    cwd: fixture,
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home },
  });
  const out = r.stdout ?? '';
  return { status: r.status, json: JSON.parse(out.slice(out.indexOf('{'))) };
}

describe('HMA-21.AC3 — the hmaignore disclosure', { timeout: 900_000 }, () => {
  it('HMA-21.AC3 presence rule: the key exists iff the file exists, and is the only NEW top-level key its presence introduces', () => {
    const without = run('secure').json;
    expect('hmaignore' in without).toBe(false);

    // a comment-only file: present, empty rules, empty errors
    const withEmpty = run('secure', '# scope notes only\n').json;
    expect(withEmpty.hmaignore).toEqual({ file: '.hmaignore', rules: [], errors: [] });

    // `hmaignore` is the only key the file's presence adds. (The VALUES of
    // the coverage keys legitimately move — the scan read one more file —
    // which is why the byte-identical claim is stated for a tree WITHOUT the
    // file against the base build, and verified there with `diff`.)
    const withoutKeys = Object.keys(without).sort();
    const withKeys = Object.keys(withEmpty).filter((k) => k !== 'hmaignore').sort();
    expect(withKeys).toEqual(withoutKeys);
  });

  it('HMA-21.AC3 check --json carries the same key under the same presence rule', () => {
    const without = run('check').json;
    expect('hmaignore' in without).toBe(false);
    const withFile = run('check', '# scope notes only\n').json;
    expect(withFile.hmaignore).toEqual({ file: '.hmaignore', rules: [], errors: [] });
  });

  it('HMA-21.AC3 shape and Σ-matched cross-check: rule as written, checkId upper-cased, expires only on active rules, matched counts the removed findings', () => {
    const { json } = run('secure', [
      'danger.py:nemo-009 # fp on fixture',
      '!git-001 EXPIRES:2099-12-31',
      '!ZZZ-999 # typo shows as matched: 0',
      '',
    ].join('\n'));
    const h = json.hmaignore;
    expect(h.file).toBe('.hmaignore');
    expect(h.errors).toEqual([]);
    expect(h.rules).toEqual([
      {
        line: 1,
        rule: 'danger.py:nemo-009 # fp on fixture',
        channel: 'hmaignore-path-check',
        path: 'danger.py',
        checkId: 'NEMO-009',
        reason: 'fp on fixture',
        matched: 1,
      },
      {
        line: 2,
        rule: '!git-001 EXPIRES:2099-12-31',
        channel: 'hmaignore-check',
        checkId: 'GIT-001',
        expires: '2099-12-31',
        matched: 1,
      },
      {
        line: 3,
        rule: '!ZZZ-999 # typo shows as matched: 0',
        channel: 'hmaignore-check',
        checkId: 'ZZZ-999',
        reason: 'typo shows as matched: 0',
        matched: 0,
      },
    ]);

    // the cross-check: for each (checkId, channel) Row, Σ matched over the
    // rules of that channel whose pattern covers the checkId equals count
    const rows = [...(json.suppressed ?? []), ...(json.outOfScope ?? [])];
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      const sum = h.rules
        .filter((r: any) => r.channel === row.suppressedBy && matchesCheckPattern(row.checkId, r.checkId))
        .reduce((n: number, r: any) => n + r.matched, 0);
      expect(sum, `${row.checkId} / ${row.suppressedBy}`).toBe(row.count);
    }
  });

  it('HMA-21.AC3 tiers: the whole-path rule wins, the absorbed narrow rule carries redundantTo and matched: 0', () => {
    const { json } = run('secure', [
      '!NEMO-009',
      'danger.py:NEMO-009 # narrow',
      'danger.py # whole',
      '',
    ].join('\n'));
    const h = json.hmaignore;
    const byLine = new Map(h.rules.map((r: any) => [r.line, r]));
    // tier 1 wins the finding
    expect((byLine.get(3) as any).matched).toBe(1);
    expect((json.outOfScope ?? []).find((r: any) => r.checkId === 'NEMO-009')?.suppressedBy).toBe('hmaignore-path');
    // the narrow rule is reported redundant, never silently swallowed
    expect(byLine.get(2)).toMatchObject({ channel: 'hmaignore-path-check', matched: 0, redundantTo: 3 });
    // the global !NEMO-009 loses the tier and matched nothing here
    expect(byLine.get(1)).toMatchObject({ channel: 'hmaignore-check', matched: 0 });
    expect((byLine.get(1) as any).redundantTo).toBeUndefined();
  });

  it('HMA-21.AC3 summarizeSuppressed folds by checkId + NUL + suppressedBy: one check scoped by two channels shows two rows', () => {
    const base = { name: 'Unsafe deserialization', category: 'nemo', severity: 'critical', passed: false, suppressed: true };
    const rows = summarizeSuppressed([
      { ...base, checkId: 'NEMO-009', suppressedBy: 'hmaignore-path' },
      { ...base, checkId: 'NEMO-009', suppressedBy: 'hmaignore-path-check' },
      { ...base, checkId: 'NEMO-009', suppressedBy: 'hmaignore-path' },
    ]);
    expect(rows).toEqual([
      { checkId: 'NEMO-009', name: 'Unsafe deserialization', category: 'nemo', severity: 'critical', count: 2, suppressedBy: 'hmaignore-path' },
      { checkId: 'NEMO-009', name: 'Unsafe deserialization', category: 'nemo', severity: 'critical', count: 1, suppressedBy: 'hmaignore-path-check' },
    ]);
  });
});
