/**
 * #524 — SUPPLY-001's fix cited `hackmyagent check SKILL.md`, relative to the
 * scan target, so `secure ./skill-out` run from the parent printed a command
 * that failed on paste with "Invalid skill identifier". The text channel now
 * rebases a citation of the finding's own file onto the scan root, the same
 * join the `Verify:` line uses (#286).
 *
 * RED-ON-BASE: on 044301c5 the printed line is `hackmyagent check SKILL.md`,
 * and running it from the parent directory exits 1 with that error.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const cleanups: string[] = [];
afterAll(() => {
  for (const d of cleanups) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
});

function run(args: string[], cwd: string) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-524-home-'));
  cleanups.push(home);
  const r = spawnSync(process.execPath, [CLI, ...args], {
    cwd,
    encoding: 'utf8',
    timeout: 120_000,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

describe('#524 an own-file fix citation runs from where the reader is standing', { timeout: 300_000 }, () => {
  it('RED-ON-BASE: secure ./skill-out from the parent cites a check command that runs there', () => {
    const parent = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hma-524-')));
    cleanups.push(parent);
    fs.mkdirSync(path.join(parent, 'skill-out'));
    fs.writeFileSync(
      path.join(parent, 'skill-out', 'SKILL.md'),
      '---\nname: helper\ndescription: formats text\n---\n# Helper\n\nFormats text the user gives it.\n',
    );

    const scan = run(['secure', './skill-out', '--verbose', '--no-machine-posture'], parent);
    const cited = scan.stdout
      .split('\n')
      .map((l) => l.match(/hackmyagent check (\S*SKILL\.md)\b/)?.[1])
      .find((m): m is string => !!m);
    expect(cited, scan.stdout).toBeDefined();
    expect(cited).toBe(path.join(parent, 'skill-out', 'SKILL.md'));

    const follow = run(['check', cited!, '--offline'], parent);
    expect(follow.stderr).not.toMatch(/Invalid skill identifier/);
    expect([0, 1, 2]).toContain(follow.status);
  });
});
