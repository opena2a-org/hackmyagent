/**
 * #293, second pass — `detect`'s fix citations must name the scanned tree.
 *
 * `detect` builds its remediation strings itself, hardcoded to a bare `.`, so
 * scanning one directory from another printed:
 *
 *   Fix: hackmyagent harden-soul .
 *   Claude Code   ungoverned  ->  hackmyagent harden-soul .
 *
 * Pasting either one generates a SOUL.md in the CURRENT directory rather than
 * the one that was scanned — writing to the wrong tree and then reporting
 * success, which is the harm #293 was filed over. The same output's Next
 * Steps block named the full path, so the two halves of one screen disagreed.
 *
 * The central rewriter added in #293 could not reach this: it completes
 * *targetless* citations and deliberately leaves an explicit `.` alone,
 * because for every other command a written-out `.` really does mean the
 * scanned tree. Only `detect` used `.` as a placeholder for something else.
 *
 * Found by the Phase 6 per-finding review during the pre-push gate for the
 * 0.25.2 stack, on the same stack that fixed #293 for `secure`.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';

/** A verb that takes a target, followed by a bare `.`, EOL, or a flag. */
const PATHLESS = /\b(?:hackmyagent|opena2a-cli|opena2a)\s+(?:secure|harden-soul|scan-soul|protect|detect)(?:\s+\.(?:\s|$)|\s*$|\s+--)/;

let target: string;
let elsewhere: string;

function detectFrom(cwd: string, arg: string): string {
  try {
    return execFileSync(process.execPath, [BUILT_CLI, 'detect', arg], {
      encoding: 'utf8', timeout: 180_000, cwd, env: { ...process.env, NO_COLOR: '1' },
    });
  } catch (e: unknown) {
    return String((e as { stdout?: string }).stdout ?? '');
  }
}

beforeAll(() => {
  assertDistFresh();
  target = mkdtempSync(path.join(tmpdir(), 'hma-293b-target-'));
  writeFileSync(path.join(target, 'package.json'), '{"name":"a","version":"1.0.0"}\n');
  writeFileSync(path.join(target, 'SOUL.md'), '# SOUL.md\n\nSome prose about the agent.\n');
  elsewhere = mkdtempSync(path.join(tmpdir(), 'hma-293b-cwd-'));
}, 120_000);

afterAll(() => {
  for (const d of [target, elsewhere]) if (d) rmSync(d, { recursive: true, force: true });
});

describe('#293 detect fix citations name the scanned target', () => {
  it('emits no pathless citation when the target is not the cwd', () => {
    const out = detectFrom(elsewhere, target);

    // Sanity: the fixture must actually produce citations, or this is vacuous.
    expect(out.length, 'no output captured').toBeGreaterThan(0);
    expect(out, 'fixture produced no fix citations to check').toMatch(/harden-soul/);

    const offenders = out.split('\n').filter((l) => PATHLESS.test(l) && !l.includes('--help'));
    expect(
      offenders,
      `these citations act on the cwd, not the scanned tree:\n${offenders.join('\n')}`,
    ).toEqual([]);
  });

  it('names the actual directory in the per-finding Fix line', () => {
    const out = detectFrom(elsewhere, target);
    const fixLine = out.split('\n').find((l) => l.includes('Fix:') && l.includes('harden-soul'));
    expect(fixLine, 'no harden-soul Fix line found').toBeTruthy();
    expect(
      fixLine,
      'the Fix line does not name the scanned tree, so pasting it writes to the wrong directory',
    ).toContain(target);
  });

  it('names the actual directory in the running-agent rows, if any', () => {
    const out = detectFrom(elsewhere, target);
    const rows = out.split('\n').filter((l) => l.includes('ungoverned') && l.includes('harden-soul'));
    for (const row of rows) {
      expect(row, `agent row cites the cwd:\n${row}`).toContain(target);
    }
  });

  it('stays pathless when the scan target IS the cwd', () => {
    // #293's discipline: a cwd scan should not churn every citation into an
    // absolute path. `.` is correct there and must be preserved.
    const out = detectFrom(target, '.');
    expect(out.length).toBeGreaterThan(0);
    const fixLine = out.split('\n').find((l) => l.includes('Fix:') && l.includes('harden-soul'));
    expect(fixLine, 'no harden-soul Fix line found').toBeTruthy();
    expect(
      fixLine,
      'a cwd scan should keep the concise `.` form rather than an absolute path',
    ).toMatch(/harden-soul \.\s*$/);
  });
});
