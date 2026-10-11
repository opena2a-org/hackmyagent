/**
 * #973 — the `detect --help` exit-code table says what the command does.
 *
 * The table promised `2  NOT MEASURED — no AI agent, MCP server, AI config or
 * governance file was found to examine`, but `detect` deliberately reports
 * "examined, found nothing" as a measured result (src/scanner/detect.ts): on a
 * machine and directory with nothing to report it exits 0. The only paths to
 * exit 2 are a target it cannot open and a `--depth` that is not a whole
 * number. A CI author reading the help would have written a gate on exit 2
 * that never fires.
 *
 * This suite renders the real help, splits the table into its rows, and runs
 * each case the rows describe, so the table and the behavior cannot drift
 * apart again.
 *
 * HERMETICITY: `detect` shells out to `ps aux` and reads machine-wide tool
 * configs under the home directory, so a planted `ps` that lists no process
 * and an empty HOME make the "nothing found" run the same on every host.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

let base: string;
let emptyDir: string;
let fakeBin: string;

function run(args: string[]): { status: number | null; out: string } {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    NO_COLOR: '1',
    OPENA2A_TELEMETRY: 'off',
    HOME: fakeBin,
    PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ''}`,
  };
  delete env.APPDATA;
  delete env.HMA_CLI_PREFIX;
  const r = spawnSync(process.execPath, [BUILT_CLI, ...args], {
    encoding: 'utf8',
    timeout: 120_000,
    cwd: base,
    env,
  });
  return { status: r.status, out: `${r.stdout}${r.stderr}` };
}

/** The exit-code table of `detect --help`, one entry per code, rows joined. */
function exitRows(): Map<string, string> {
  const help = run(['detect', '--help']).out;
  const start = help.indexOf('Exit codes:');
  expect(start, help).toBeGreaterThanOrEqual(0);
  const block = help.slice(start).split('\n\n')[0].split('\n').slice(1);
  const rows = new Map<string, string>();
  let current = '';
  for (const line of block) {
    const m = /^ {2}(\d)\s+(.*)$/.exec(line);
    if (m) {
      current = m[1];
      rows.set(current, m[2]);
    } else if (current) {
      rows.set(current, `${rows.get(current)} ${line.trim()}`);
    }
  }
  return rows;
}

beforeAll(() => {
  assertDistFresh();
  // Removed when this file finishes, by the afterAll vitest.setup.ts registers.
  base = tempDir('hma-973-');
  emptyDir = path.join(base, 'empty');
  mkdirSync(emptyDir);
  fakeBin = path.join(base, 'bin');
  mkdirSync(fakeBin);
  const ps = path.join(fakeBin, 'ps');
  writeFileSync(
    ps,
    "#!/bin/sh\nprintf '%s\\n' 'USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND'\n",
  );
  chmodSync(ps, 0o755);
}, 120_000);

describe('detect --help exit codes match what detect does (#973)', () => {
  it('a run that finds nothing exits 0, and the help puts that case under 0, not 2', () => {
    const r = run(['detect', emptyDir]);
    expect(r.out).toMatch(/No AI agents, MCP servers, or AI configs detected/);
    expect(r.status, r.out).toBe(0);

    const rows = exitRows();
    expect(rows.get('0')).toMatch(/no AI agent, MCP server, AI config or governance file/i);
    expect(rows.get('2')).not.toMatch(/no AI agent/i);
  }, 180_000);

  it('a directory that does not exist exits 2, and the help names it under 2', () => {
    const r = run(['detect', path.join(base, 'missing')]);
    expect(r.status, r.out).toBe(2);
    expect(exitRows().get('2')).toMatch(/does not exist or could not be read/);
  }, 180_000);

  it('a --depth that is not a whole number exits 2, and the help names it under 2', () => {
    const r = run(['detect', emptyDir, '--depth', 'two']);
    expect(r.status, r.out).toBe(2);
    expect(exitRows().get('2')).toMatch(/--depth was not a whole number/);
  }, 180_000);
});
