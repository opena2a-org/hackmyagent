/**
 * #872 — the benchmark report discloses what `.hmaignore` check rules withheld.
 *
 * Measured with `!MCP-001`, `!TOOL-001`, `!TOOL-002`, `!GIT-001` over
 * `test-fixtures/insecure-mcp`: `secure -b oasb-1 --json` read controls 2.3 and
 * 4.1 as unverified and carried no `suppressed` or `hmaignore` key, and
 * `-f sarif` had no `runs[0].properties`, while `secure --json` and the scan
 * SARIF (#465) on the same tree carried both.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const FIXTURE = path.resolve(__dirname, '../../test-fixtures/insecure-mcp');

let withRules: string;
let withoutRules: string;

beforeAll(() => {
  withRules = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-872-'));
  withoutRules = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-872-ctl-'));
  fs.cpSync(FIXTURE, withRules, { recursive: true });
  fs.cpSync(FIXTURE, withoutRules, { recursive: true });
  fs.writeFileSync(path.join(withRules, '.hmaignore'), '!MCP-001\n!TOOL-001\n!TOOL-002\n!GIT-001\n');
});

afterAll(() => {
  for (const dir of [withRules, withoutRules]) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function run(cwd: string, args: string[]): { stdout: string; stderr: string; status: number | null } {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    cwd,
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-')),
    },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status };
}

const jsonOf = (s: string) => JSON.parse(s.slice(s.search(/[[{]/)));
const IDENTITY_KEYS = ['category', 'checkId', 'count', 'name', 'severity', 'suppressedBy'];

describe('#872 benchmark output discloses .hmaignore check rules', () => {
  it('--json carries the suppressed rows and the per-rule .hmaignore record', () => {
    const doc = jsonOf(run(withRules, ['secure', '.', '-b', 'oasb-1', '--json']).stdout);
    expect(doc.benchmark).toBeDefined();
    expect(doc.suppressed, 'suppressed missing').toBeDefined();
    expect(doc.suppressed.map((r: { checkId: string }) => r.checkId).sort()).toEqual(['GIT-001', 'MCP-001', 'TOOL-002']);
    for (const row of doc.suppressed) {
      expect(Object.keys(row).sort()).toEqual(IDENTITY_KEYS);
      expect(row.suppressedBy).toBe('hmaignore-check');
    }
    // Check rules only: nothing was put out of scope.
    expect(doc).not.toHaveProperty('outOfScope');
    const rules = doc.hmaignore?.rules as Array<{ rule: string; matched: number }> | undefined;
    expect(rules?.map((r) => r.rule)).toEqual(['!MCP-001', '!TOOL-001', '!TOOL-002', '!GIT-001']);
    expect(rules?.find((r) => r.rule === '!TOOL-001')?.matched).toBe(0);
  });

  it('SARIF carries the suppressed rows in runs[0].properties', () => {
    const doc = jsonOf(run(withRules, ['secure', '.', '-b', 'oasb-1', '-f', 'sarif']).stdout);
    const props = doc.runs[0].properties;
    expect(props, 'runs[0].properties missing').toBeDefined();
    expect(props.suppressed.map((r: { checkId: string }) => r.checkId).sort()).toEqual(['GIT-001', 'MCP-001', 'TOOL-002']);
    for (const row of props.suppressed) expect(Object.keys(row).sort()).toEqual(IDENTITY_KEYS);
    expect(props).not.toHaveProperty('outOfScope');
  });

  it('CONTROL: with nothing withheld neither channel adds a disclosure', () => {
    const doc = jsonOf(run(withoutRules, ['secure', '.', '-b', 'oasb-1', '--json']).stdout);
    expect(doc.benchmark).toBeDefined();
    expect(doc).not.toHaveProperty('suppressed');
    expect(doc).not.toHaveProperty('outOfScope');
    expect(doc).not.toHaveProperty('hmaignore');
    const sarif = jsonOf(run(withoutRules, ['secure', '.', '-b', 'oasb-1', '-f', 'sarif']).stdout);
    expect(sarif.runs[0]).not.toHaveProperty('properties');
  });
});
