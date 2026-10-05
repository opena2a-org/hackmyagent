/**
 * #460 — `secure-openclaw` and `secure-nemoclaw`: an `.hmaignore` check rule
 * takes a finding off the list and leaves it in the risk level and the exit
 * code, and both reports name what was suppressed, in text and in `--json`.
 * That is the contract `secure` and `check` already keep (#450).
 *
 * Measured before the fix on `test-fixtures/insecure-openclaw` with every
 * critical/high check ID suppressed: `Risk Level: Critical`, exit 1 became
 * `Risk Level: Moderate`, exit 0, and nothing in either report mentioned a
 * suppression.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { appendFileSync, cpSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

const FIXTURE = path.resolve(__dirname, '../../test-fixtures/insecure-openclaw');

type Command = 'secure-openclaw' | 'secure-nemoclaw';

interface Row { checkId: string; severity: string; count: number }
interface Report {
  riskLevel: string | null;
  findings: Array<{ checkId: string; severity?: string; passed?: boolean }>;
  suppressed?: Row[];
  outOfScope?: Row[];
}

function copyFixture(): string {
  const dir = tempDir('hma-460-');
  cpSync(FIXTURE, dir, { recursive: true });
  return dir;
}

function run(command: Command, dir: string, extra: string[] = []) {
  const home = tempDir('hma-460-home-');
  const r = spawnSync(process.execPath, [CLI, command, dir, ...extra], {
    encoding: 'utf8',
    timeout: 120_000,
    env: {
      ...process.env,
      HOME: home,
      OPENA2A_HOME: path.join(home, '.opena2a'),
      OPENA2A_TELEMETRY: 'off',
      NO_COLOR: '1',
      FORCE_COLOR: '0',
    },
  });
  // eslint-disable-next-line no-control-regex
  const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, '');
  return { status: r.status, stdout: strip(r.stdout ?? ''), stderr: strip(r.stderr ?? '') };
}

function runJson(command: Command, dir: string): { status: number | null; report: Report } {
  const r = run(command, dir, ['--json']);
  return { status: r.status, report: JSON.parse(r.stdout) as Report };
}

function criticalOrHighIds(report: Report): string[] {
  return [...new Set(
    report.findings
      .filter((f) => !f.passed && (f.severity === 'critical' || f.severity === 'high'))
      .map((f) => f.checkId),
  )];
}

/**
 * Write a `!CHECK` rule for every critical/high finding the report lists,
 * repeating until none is left: the semantic pass can surface a finding only
 * once the static one it would have merged into is suppressed.
 */
function suppressEveryCriticalAndHigh(command: Command, dir: string): string[] {
  const suppressed: string[] = [];
  for (let round = 0; round < 5; round++) {
    const ids = criticalOrHighIds(runJson(command, dir).report).filter((id) => !suppressed.includes(id));
    if (ids.length === 0) return suppressed;
    appendFileSync(path.join(dir, '.hmaignore'), ids.map((id) => `!${id}\n`).join(''));
    suppressed.push(...ids);
  }
  throw new Error(`critical/high findings still listed after five rounds of ${command}`);
}

describe.each<Command>(['secure-openclaw', 'secure-nemoclaw'])(
  '#460 %s: an .hmaignore check rule keeps the verdict and is disclosed',
  (command) => {
    let baseline: { status: number | null; report: Report };
    let dir: string;
    let ids: string[];

    beforeAll(() => {
      baseline = runJson(command, copyFixture());
      dir = copyFixture();
      ids = suppressEveryCriticalAndHigh(command, dir);
    }, 600_000);

    it('the fixture is a critical, exit-1 target with critical/high findings to suppress', () => {
      expect(baseline.report.riskLevel).toBe('Critical');
      expect(baseline.status).toBe(1);
      expect(ids.length).toBeGreaterThan(0);
    });

    it('--json: same risk level and exit code, suppressed rows carried, list narrowed', () => {
      const { status, report } = runJson(command, dir);
      expect(report.riskLevel).toBe(baseline.report.riskLevel);
      expect(status).toBe(baseline.status);
      expect(criticalOrHighIds(report)).toEqual([]);
      const rows = report.suppressed ?? [];
      const named = new Set(rows.map((r) => r.checkId));
      for (const id of ids) expect(named, id).toContain(id);
      // Identity rows only: what was withheld is named, its evidence is not.
      for (const row of rows) expect(Object.keys(row).sort()).toEqual(['category', 'checkId', 'count', 'name', 'severity', 'suppressedBy']);
    }, 180_000);

    it('text: same risk level and exit code, and a Suppressed line names every suppressed check', () => {
      const r = run(command, dir);
      expect(r.status, r.stdout + r.stderr).toBe(baseline.status);
      expect(r.stdout).toContain(`Risk Level: ${baseline.report.riskLevel}`);
      const line = r.stdout.split('\n').find((l) => l.startsWith('Suppressed: '));
      expect(line, r.stdout).toBeDefined();
      for (const id of ids) expect(line).toContain(`${id} (`);
      expect(r.stdout).toContain('Still in the risk level and the exit code');
    }, 180_000);
  },
);

describe('#460 secure-openclaw: an .hmaignore path rule is disclosed as scope', () => {
  it('text and --json name the excluded findings and do not count them', () => {
    const dir = copyFixture();
    writeFileSync(path.join(dir, '.hmaignore'), 'skills/\n');
    const { status, report } = runJson('secure-openclaw', dir);
    const scoped = report.outOfScope ?? [];
    expect(scoped.length, JSON.stringify(report.outOfScope)).toBeGreaterThan(0);
    expect(report.suppressed).toBeUndefined();
    const text = run('secure-openclaw', dir);
    expect(text.status).toBe(status);
    const total = scoped.reduce((n, r) => n + r.count, 0);
    expect(text.stdout).toMatch(new RegExp(`^Scope: ${total} findings? excluded by \\.hmaignore path rules`, 'm'));
    expect(text.stdout).toContain('Out of scope, so not in the risk level and not in the exit code.');
  }, 180_000);
});
