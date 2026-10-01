/**
 * #670 — `secure --benchmark --format sarif` emits one result per record the
 * control cited, joined by exact evidence line against the record set the
 * assessor read.
 *
 * Before: the SARIF writer re-derived a control's records from
 * `result.findings` by checkId (a substring match until #749, a prefix match
 * after it). The assessor reads `allFindings`, so a failing record the plain
 * scan does not list (an MCP config's TOOL-001, TOOL-002 and MCP-006 below)
 * failed its control in the JSON report while SARIF printed one location-less
 * result for it; a passed or fixed record of a cited checkId was attached as
 * an `error` result.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import {
  controlEvidenceLine,
  failingRecordsForControl,
} from '../../src/benchmarks/benchmark-report';
import type { SecurityFinding } from '../../src/hardening/security-check';

function rec(over: Partial<SecurityFinding>): SecurityFinding {
  return {
    checkId: 'CRED-001',
    name: 'n',
    category: 'credentials',
    severity: 'high',
    passed: false,
    message: 'm',
    description: 'API key found in plaintext',
    fixable: false,
    ...over,
  } as SecurityFinding;
}

describe('failingRecordsForControl (#670)', () => {
  it('joins by exact evidence line, not by checkId substring', () => {
    const cred = rec({ checkId: 'CRED-001', file: 'a.env', line: 1 });
    const sem = rec({ checkId: 'SEM-CRED-001', file: 'b.md', line: 2 });
    const evidence = [controlEvidenceLine(sem)];
    expect(failingRecordsForControl(evidence, [cred, sem])).toEqual([sem]);
  });

  it('skips passed, fixed and not-applicable records of a cited checkId', () => {
    const failing = rec({ checkId: 'TOOL-001', file: 'mcp.json' });
    const passed = { ...failing, passed: true };
    const fixed = { ...failing, passed: true, fixed: true };
    const na = { ...failing, passed: undefined, notApplicable: { subject: 'mcp.json' } } as unknown as SecurityFinding;
    const evidence = [controlEvidenceLine(failing)];
    expect(failingRecordsForControl(evidence, [passed, fixed, na, failing])).toEqual([failing]);
  });

  it('cites a failing record of the same checkId in another file only when its own line is cited', () => {
    const inA = rec({ checkId: 'TOOL-001', file: 'mcp.json' });
    const inB = rec({ checkId: 'TOOL-001', file: '.mcp.json' });
    expect(failingRecordsForControl([controlEvidenceLine(inA)], [inA, inB])).toEqual([inA]);
  });

  it('keeps a pathless failing record the control cited', () => {
    const pathless = rec({ checkId: 'DEP-003', file: undefined });
    expect(failingRecordsForControl([controlEvidenceLine(pathless)], [pathless])).toEqual([pathless]);
  });
});

beforeAll(assertDistFreshIfPresent);

const FLAGS = ['--ci', '-b', 'oasb-1', '--no-machine-posture'];

let tree: string;
let home: string;

beforeAll(() => {
  tree = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-670-'));
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-'));
  // No whitelist, no resource constraints, no timeout: TOOL-001, TOOL-002 and
  // MCP-006 fail on mcp.json and fail OASB-1 2.3, 4.1 and 5.2, but the plain
  // scan's `findings` does not carry them.
  fs.writeFileSync(
    path.join(tree, 'mcp.json'),
    JSON.stringify({ servers: { fs: { command: 'node', args: ['server.js'] } } }) + '\n',
  );
});

afterAll(() => {
  for (const d of [tree, home]) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function run(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, 'secure', tree, ...args], {
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

interface SarifResult {
  ruleId: string;
  message: { text: string };
  locations?: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
}

describe('secure --benchmark --format sarif cites the assessor\'s records (#670)', () => {
  let failed: Array<{ controlId: string; findings: string[] }>;
  let results: SarifResult[];

  beforeAll(() => {
    const json = run([...FLAGS, '--format', 'json']);
    const report = JSON.parse(json.stdout) as {
      categories: Array<{ controls: Array<{ controlId: string; status: string; findings: string[] }> }>;
    };
    failed = report.categories.flatMap((c) => c.controls).filter((c) => c.status === 'failed');
    const sarif = run([...FLAGS, '--format', 'sarif']);
    results = (JSON.parse(sarif.stdout) as { runs: Array<{ results: SarifResult[] }> }).runs[0].results;
  }, 600_000);

  it('the fixture fails controls on records the plain scan does not list', () => {
    const ids = failed.map((c) => c.controlId);
    expect(ids).toEqual(expect.arrayContaining(['2.3', '4.1', '5.2']));
  });

  it('every failed control has one SARIF result per evidence line, each located in the cited file', () => {
    for (const ctrl of failed) {
      const mine = results.filter((r) => r.ruleId === `OASB-1/${ctrl.controlId}`);
      expect(mine.length, `OASB-1/${ctrl.controlId}`).toBe(ctrl.findings.length);
      for (const r of mine) {
        expect(r.locations?.[0]?.physicalLocation.artifactLocation.uri, `OASB-1/${ctrl.controlId}`).toBe('mcp.json');
      }
    }
  });

  it('2.3 carries the TOOL-001 and TOOL-002 descriptions, not a joined control summary', () => {
    const texts = results.filter((r) => r.ruleId === 'OASB-1/2.3').map((r) => r.message.text).sort();
    expect(texts).toEqual([
      'MCP servers should have explicit tool whitelists',
      'MCP tools should have resource constraints',
    ]);
  });
});
