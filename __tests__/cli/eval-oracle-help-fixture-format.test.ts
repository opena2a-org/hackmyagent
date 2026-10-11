/**
 * #990 — `eval oracle --help` documents the fixture format and the release
 * gate itself.
 *
 * Before: the description ended `See: hackmyagent-redteam-oracle/METHODOLOGY.md
 * for fixture format and release-gate thresholds.` That file is not in this
 * repository and not in the published package (`files`: dist, README.md,
 * LICENSE), so the one pointer a user had led nowhere, and nothing they could
 * read named a label.json field or a threshold.
 *
 * Now the help prints both after the options, built from the values the
 * evaluation uses.
 *
 * RED-ON-BASE cells fail on the help text before the fix; PIN cells hold the
 * behaviour the new text describes and pass on both.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { GATE_F1, GATE_PRECISION, GATE_RECALL, ORACLE_LABELS, REPORTED_SURFACES } from '../../src/eval/oracle';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SRC_CLI = path.join(REPO_ROOT, 'src', 'cli.ts');
const SRC_ORACLE = path.join(REPO_ROOT, 'src', 'eval', 'oracle.ts');
const TSX = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');

beforeAll(assertDistFreshIfPresent);

/** The built CLI when present, `tsx` over `src/` otherwise — never a skip. */
function cliCommand(args: string[]): { bin: string; argv: string[] } {
  if (fs.existsSync(BUILT_CLI)) return { bin: process.execPath, argv: [BUILT_CLI, ...args] };
  if (!fs.existsSync(TSX)) {
    throw new Error('Neither dist/cli.js nor node_modules/.bin/tsx is present; run `npm ci` before this suite.');
  }
  return { bin: TSX, argv: [SRC_CLI, ...args] };
}

function cliEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: tempDir('hma-990-home-') };
  delete env.HMA_CLI_PREFIX;
  return env;
}

function help(args: string[]): string {
  const { bin, argv } = cliCommand([...args, '--help']);
  // eslint-disable-next-line no-control-regex
  return execFileSync(bin, argv, { env: cliEnv(), encoding: 'utf8', cwd: REPO_ROOT }).replace(/\x1b\[[0-9;]*m/g, '');
}

/** The rows of one indented block of the help: `    name   text`, continuation lines joined. */
function blockRows(text: string, heading: string): Map<string, string> {
  const lines = text.split('\n');
  const start = lines.findIndex((l) => l.trim() === heading);
  expect(start, `eval oracle --help has a "${heading}" block`).toBeGreaterThanOrEqual(0);
  const rows = new Map<string, string>();
  let current: string | undefined;
  for (let i = start + 1; i < lines.length && lines[i].trim() !== ''; i++) {
    const row = /^ {4}(\S+(?: \S+)*) {2,}(\S.*)$/.exec(lines[i]);
    if (row) {
      current = row[1];
      rows.set(current, row[2]);
    } else if (current !== undefined) {
      rows.set(current, `${rows.get(current)} ${lines[i].trim()}`);
    }
  }
  return rows;
}

/** The label.json fields `runOracleEval` reads, taken from its source. */
function fieldsTheEvaluationReads(): string[] {
  const src = fs.readFileSync(SRC_ORACLE, 'utf8');
  const from = src.indexOf('export async function runOracleEval');
  const to = src.indexOf('\n}\n', from);
  expect(from, 'runOracleEval is found in src/eval/oracle.ts').toBeGreaterThanOrEqual(0);
  const read = new Set<string>();
  // `label.json` is the file name inside a path string, not a field read.
  for (const m of src.slice(from, to).matchAll(/\blabel\.(\w+)/g)) if (m[1] !== 'json') read.add(m[1]);
  return [...read].sort();
}

describe('#990 eval oracle --help documents the fixture format and the release gate', { timeout: 120_000 }, () => {
  let oracleHelp = '';
  let evalHelp = '';

  beforeAll(() => {
    oracleHelp = help(['eval', 'oracle']);
    evalHelp = help(['eval']);
  });

  it('RED-ON-BASE: neither help names a markdown file the package does not ship', () => {
    const published = (JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8')) as { files: string[] }).files;
    for (const text of [oracleHelp, evalHelp]) {
      const cited = text.match(/[\w./-]+\.md\b/g) ?? [];
      expect(cited.filter((file) => !published.includes(file))).toEqual([]);
    }
  });

  it('RED-ON-BASE: the help lists exactly the label.json fields the evaluation reads', () => {
    const read = fieldsTheEvaluationReads();
    // Non-vacuity: an empty read set means the source walk broke, not that the
    // evaluation stopped reading labels.
    expect(read).toContain('surface');
    expect(read).toContain('expectedChecks');
    expect([...blockRows(oracleHelp, 'label.json fields:').keys()].sort()).toEqual(read);
  });

  it('RED-ON-BASE: the help names every surface, label and severity a label.json can carry', () => {
    const rows = blockRows(oracleHelp, 'label.json fields:');
    for (const surface of REPORTED_SURFACES) expect(rows.get('surface')).toContain(surface);
    for (const label of ORACLE_LABELS) expect(rows.get('expectedLabel')).toMatch(new RegExp(`\\b${label}\\b`));
    for (const severity of ['critical', 'high', 'medium', 'low', 'info', 'none']) {
      expect(rows.get('expectedSeverity')).toMatch(new RegExp(`\\b${severity}\\b`));
    }
  });

  it('RED-ON-BASE: the help states the thresholds the release gate applies', () => {
    const pct = (n: number) => `${(n * 100).toFixed(1)}%`;
    const gate = oracleHelp.slice(oracleHelp.indexOf('Release gate:'));
    expect(oracleHelp).toContain('Release gate:');
    expect(gate).toMatch(new RegExp(`recall\\s+is ${pct(GATE_RECALL).replace('.', '\\.')} or higher, overall and on each surface`));
    expect(gate).toMatch(new RegExp(`precision\\s+is ${pct(GATE_PRECISION).replace('.', '\\.')} or higher, overall and on each surface`));
    expect(gate).toMatch(new RegExp(`F1\\s+is ${pct(GATE_F1).replace('.', '\\.')} or higher, overall`));
    expect(gate).toContain('--fail-on-gate exits 1 when the gate fails');
  });

  it('PIN: no help line is wider than 80 columns', () => {
    expect(oracleHelp.split('\n').filter((line) => line.length > 80)).toEqual([]);
  });

  it('PIN: a fixture set laid out as the help describes is found and evaluated', () => {
    const root = tempDir('hma-990-');
    const label = { surface: 'arp-input', expectedLabel: 'benign', expectedSeverity: 'none', attackFamily: 'pin', expectedChecks: [] };
    const fixture = (rel: string, extra: Record<string, unknown> = {}): string => {
      const dir = path.join(root, rel);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'label.json'), JSON.stringify({ ...label, ...extra }));
      return dir;
    };
    // One fixture a directory down with its input.txt, one two directories
    // down without it, and one retired.
    const withInput = fixture(path.join('group', 'with-input'));
    fs.writeFileSync(path.join(withInput, 'input.txt'), 'What time is the standup tomorrow?\n');
    const withoutInput = fixture(path.join('group', 'deeper', 'without-input'));
    fixture('retired', { retired: true });

    const { bin, argv } = cliCommand(['eval', 'oracle', '--oracle-dir', root, '--format', 'json']);
    const r = spawnSync(bin, argv, { env: cliEnv(), encoding: 'utf8', cwd: REPO_ROOT, timeout: 110_000 });
    expect(r.status).toBe(0);
    const report = JSON.parse(r.stdout.slice(r.stdout.indexOf('{'))) as {
      totalFixtures: number;
      retired: number;
      all: Array<{ fixturePath: string; surface: string; scanError?: string }>;
    };
    expect(report.totalFixtures).toBe(2);
    expect(report.retired).toBe(1);
    const byPath = new Map(report.all.map((result) => [fs.realpathSync(result.fixturePath), result]));
    expect(byPath.get(fs.realpathSync(withInput))).toMatchObject({ surface: 'arp-input' });
    expect(byPath.get(fs.realpathSync(withInput))?.scanError).toBeUndefined();
    expect(byPath.get(fs.realpathSync(withoutInput))?.scanError).toBe('input.txt not found');
  });
});
