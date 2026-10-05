/**
 * #465 — the report FILES disclose what `--ignore` / `.hmaignore` withheld,
 * and the `.hmaignore` disclosure says which rule excluded which finding.
 *
 * Measured on `044301c5` with `.hmaignore` = `vendor/` + `!DEP-001` over a tree
 * whose only critical is in `vendor/`: `-f sarif` carried no `run.properties`,
 * `-f html` no suppression text, `-f asff` nothing at all, and `--json`'s
 * per-rule record said `matched: 1` with no way to tell which finding that was.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { disclosureSentences, hasDisclosure, sarifRunProperties } from '../../src/output/suppression-disclosure';

beforeAll(assertDistFreshIfPresent);

let root: string;

beforeAll(() => {
  root = tempDir('hma-465-');
  fs.mkdirSync(path.join(root, 'vendor'));
  fs.mkdirSync(path.join(root, 'lib'));
  const evalSource = 'module.exports = (r) => eval(r.body);\n';
  fs.writeFileSync(path.join(root, 'vendor', 'a.js'), evalSource);
  fs.writeFileSync(path.join(root, 'lib', 'b.js'), evalSource);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'hma-465', version: '1.0.0' }));
  fs.writeFileSync(path.join(root, '.hmaignore'), 'vendor/  # third-party copy\n!DEP-001\n');
});

afterAll(() => {
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
});

function run(args: string[]): { stdout: string; stderr: string; status: number | null } {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    cwd: root,
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: tempDir('hma-home-'),
    },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status };
}

const jsonOf = (s: string) => JSON.parse(s.slice(s.search(/[[{]/)));

describe('#465 report files disclose suppression and scope', () => {
  it('SARIF carries both records in run.properties and does not list the suppressed check', () => {
    const doc = jsonOf(run(['secure', '.', '-f', 'sarif']).stdout);
    const props = doc.runs[0].properties;
    expect(props, 'run.properties missing').toBeDefined();
    expect(props.suppressed.map((r: { checkId: string }) => r.checkId)).toEqual(['DEP-001']);
    expect(props.outOfScope).toEqual([
      expect.objectContaining({ checkId: 'NEMO-009', severity: 'critical', count: 1, suppressedBy: 'hmaignore-path' }),
    ]);
    const ruleIds = doc.runs[0].results.map((r: { ruleId: string }) => r.ruleId);
    expect(ruleIds).not.toContain('DEP-001');
    // Identity only: no file, message or evidence on a disclosure row.
    for (const row of [...props.suppressed, ...props.outOfScope]) {
      expect(Object.keys(row).sort()).toEqual(['category', 'checkId', 'count', 'name', 'severity', 'suppressedBy']);
    }
  });

  it('HTML names both records', () => {
    const html = run(['secure', '.', '-f', 'html']).stdout;
    expect(html).toContain('<h2>Suppressed and out of scope</h2>');
    expect(html).toContain('1 finding excluded by .hmaignore path rules (1 critical)');
    expect(html).toContain('<code>DEP-001</code>');
    expect(html).toContain('<code>NEMO-009</code>');
  });

  it('ASFF stays an importable array on stdout and discloses on stderr', () => {
    const r = run(['secure', '.', '-f', 'asff']);
    const findings = jsonOf(r.stdout);
    expect(Array.isArray(findings)).toBe(true);
    expect(r.stderr).toContain('1 finding excluded by .hmaignore path rules (1 critical)');
    expect(r.stderr).toContain('suppressed by the caller: DEP-001 (medium)');
    expect(r.stderr).toContain('Not in this ASFF document.');
  });

  it('--json names, per .hmaignore rule, the findings it excluded', () => {
    const doc = jsonOf(run(['secure', '.', '--json']).stdout);
    const rules = doc.hmaignore.rules as Array<{ rule: string; matched: number; excluded?: unknown[] }>;
    const vendorRule = rules.find((r) => r.rule.startsWith('vendor/'));
    const depRule = rules.find((r) => r.rule === '!DEP-001');
    expect(vendorRule?.excluded).toEqual([{ checkId: 'NEMO-009', severity: 'critical', file: 'vendor/a.js' }]);
    expect(depRule?.excluded).toEqual([expect.objectContaining({ checkId: 'DEP-001', severity: 'medium' })]);
    for (const r of rules) expect(r.excluded?.length ?? 0, `rule ${r.rule}`).toBe(r.matched);
    // The live copy outside vendor/ is still reported.
    expect(JSON.stringify(doc.findings ?? doc.allFindings)).toContain('lib/b.js');
  });
});

describe('suppression-disclosure helpers', () => {
  const row = { checkId: 'X-1', name: 'X', category: 'c', severity: 'high', count: 2, suppressedBy: 'ignore-flag' };

  it('discloses nothing when nothing was withheld', () => {
    expect(hasDisclosure({})).toBe(false);
    expect(sarifRunProperties({ suppressed: [], outOfScope: [] })).toBeUndefined();
    expect(disclosureSentences({})).toEqual([]);
  });

  it('counts rows by their count, not their number', () => {
    expect(disclosureSentences({ suppressed: [row] })).toEqual([
      '2 findings suppressed by the caller: X-1 (high x2). Withheld from this report at your request; '
      + 'still scored, still in the verdict, still in the exit code.',
    ]);
    expect(sarifRunProperties({ outOfScope: [row] })).toEqual({ outOfScope: [row] });
  });
});
