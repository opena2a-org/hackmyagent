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
 *
 * ---
 *
 * HERMETICITY (added when PR #366 first ran this suite on a clean machine).
 *
 * The `Fix:` line these cases read is a finding's `remediation`, and the only
 * findings carrying a `harden-soul` one are raised from `result.agents` —
 * which `detect` fills from `scanProcesses()`, which shells out to `ps aux`.
 * So the rows came from the AI agents running on the DEVELOPER'S OWN MACHINE,
 * not from the fixture. Two cases here passed on maintainer laptops for a
 * reason unrelated to what they claim to measure, and failed on both CI
 * runners and for every new contributor — `no harden-soul Fix line found`.
 *
 * Same class as the `$HOME/.openclaw` scope escape #356 fixed for `secure`:
 * a test whose subject is the host is a test of the host.
 *
 * The fixture now plants its own agent, by putting a `ps` on the child's PATH
 * that reports one. That fixes the failure in both directions — the row exists
 * on a clean machine, and the host's real agents can no longer supply it. The
 * `names no host agent` case below is what holds the second half: it fails on
 * a maintainer laptop the moment the planted `ps` stops being used.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';

/** A verb that takes a target, followed by a bare `.`, EOL, or a flag. */
const PATHLESS = /\b(?:hackmyagent|opena2a-cli|opena2a)\s+(?:secure|harden-soul|scan-soul|protect|detect)(?:\s+\.(?:\s|$)|\s*$|\s+--)/;

/**
 * The one agent the fixture reports, chosen so it cannot be confused with a
 * real one: `Aider` matches on `/\baider\b/` alone, and no other entry in
 * `AGENT_PATTERNS` matches the planted line. `Claude Code`'s pattern is the
 * loose `/\bclaude\s+/i`, so the line deliberately contains no `claude`.
 */
const PLANTED_AGENT = 'Aider';
/** An agent that is NOT planted, and IS running on maintainer laptops. */
const HOST_AGENT = 'Claude Code';

let target: string;
let elsewhere: string;
/** Holds the `ps` the scanned child sees instead of the real one. */
let fakeBin: string;

function detectFrom(cwd: string, arg: string): string {
  try {
    return execFileSync(process.execPath, [BUILT_CLI, 'detect', arg], {
      encoding: 'utf8',
      timeout: 180_000,
      cwd,
      // `scanProcesses` runs `ps aux` through a shell, so a `ps` earlier on
      // PATH is the one it reads. Everything else about the environment is
      // left alone: this shadows one command, not the whole environment.
      env: { ...process.env, NO_COLOR: '1', PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ''}` },
    });
  } catch (e: unknown) {
    return String((e as { stdout?: string }).stdout ?? '');
  }
}

beforeAll(() => {
  assertDistFresh();
  target = mkdtempSync(path.join(tmpdir(), 'hma-293b-target-'));
  writeFileSync(path.join(target, 'package.json'), '{"name":"a","version":"1.0.0"}\n');
  // No controls in it, deliberately: `governanceEstablished` is false, so the
  // planted agent stays `no governance` and the finding that carries the
  // `harden-soul` citation is the one raised.
  writeFileSync(path.join(target, 'SOUL.md'), '# SOUL.md\n\nSome prose about the agent.\n');
  elsewhere = mkdtempSync(path.join(tmpdir(), 'hma-293b-cwd-'));

  // Its own directory, NOT inside `target`: `detect` scans the target, and a
  // stray executable in there would be part of what is being measured.
  fakeBin = mkdtempSync(path.join(tmpdir(), 'hma-293b-bin-'));
  const ps = path.join(fakeBin, 'ps');
  writeFileSync(
    ps,
    '#!/bin/sh\n'
    + '# Stands in for `ps aux` so the agent row comes from this fixture rather\n'
    + '# than from whatever the developer happens to be running.\n'
    + "printf '%s\\n' 'USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND'\n"
    + "printf '%s\\n' 'fixture 4242 0.0 0.0 4200 900 ?? S 1:00AM 0:00.10 /usr/local/bin/aider --yes'\n",
  );
  chmodSync(ps, 0o755);
}, 120_000);

afterAll(() => {
  for (const d of [target, elsewhere, fakeBin]) if (d) rmSync(d, { recursive: true, force: true });
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

  /**
   * Was `…, if any`, and the `if any` was doing real damage: on a clean
   * machine `rows` is empty and a `for` loop over nothing passes. So the one
   * case here that reads the agent rows reported success precisely where the
   * rows did not exist. The fixture plants an agent now, so the row is
   * guaranteed and its absence is a failure.
   */
  it('names the actual directory in the running-agent rows', () => {
    const out = detectFrom(elsewhere, target);
    // Filtering on `harden-soul` made this loop silently empty the moment the
    // row started citing a different command — a change to the citation VERB
    // would have turned the assertion off rather than failing it. Anchor on
    // what the row is, then assert the command inside it. (#303 changed the
    // verb for subverted documents, which is how this was caught.)
    const rows = out.split('\n').filter((l) => l.includes('ungoverned'));
    expect(
      rows.length,
      'no ungoverned agent row was rendered, so this case measures nothing',
    ).toBeGreaterThan(0);
    for (const row of rows) {
      expect(row, `agent row cites no fix command at all:\n${row}`).toMatch(/harden-soul|scan-soul/);
      expect(row, `agent row cites the cwd:\n${row}`).toContain(target);
    }
  });

  /**
   * The other half of the hermeticity fix, and the half that can fail.
   *
   * Planting an agent makes the suite pass on a clean machine. It does NOT by
   * itself stop the host's own agents from being what the other cases read —
   * and that was the original defect. This case fails on any machine where
   * `detect` is still reading the real `ps`, which on a maintainer laptop is
   * every machine this suite was ever green on.
   */
  it('reads the planted agent and not the host', () => {
    const out = detectFrom(elsewhere, target);
    expect(
      out,
      'the planted agent is missing, so `ps` is not being read from the fixture',
    ).toContain(PLANTED_AGENT);
    expect(
      out,
      `${HOST_AGENT} came from the host, not the fixture: this suite is measuring `
      + 'the developer\'s machine',
    ).not.toContain(HOST_AGENT);
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
