/**
 * #637 — the deterministic MCP checks read every root config spelling.
 *
 * Measured on efc862a with the issue's fixture: the same live servers scored
 * compliance 33 (2.3, 4.1, 5.2 failed) as `mcp.json` and 36 (2.3, 4.1, 5.2
 * not-applicable) as `.mcp.json` — Claude Code's project-scope file — because
 * every root read site spelled the file by hand. Renaming the config raised
 * the rating while the servers stayed live.
 *
 * Contract under test (CPO ruling 2026-08-27, ledger):
 *   - parity: both spellings score identically, and a record names the file
 *     it came from;
 *   - both present: EVERY existing config is evaluated (a first-found read
 *     would let a clean `mcp.json` shadow a live `.mcp.json`), so a checkId
 *     can appear once per file, and the control fails if any file fails;
 *   - neither present: one not-applicable record per check naming the SET,
 *     `mcp.json or .mcp.json`, so the reader is not told to create the wrong
 *     file.
 *
 * Spawned through the built CLI (`dist/cli.js`), the surface a user runs; the
 * parity cell is the issue's Verify block.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

const SCAN_TIMEOUT = 120_000;
const SUBJECT = 'mcp.json or .mcp.json';
const ROOT_MCP_CHECK = /^(MCP-00[1-9]|MCP-010|TOOL-00[1-3]|NET-00[12])$/;
const NA_CHECKS = ['TOOL-001', 'TOOL-002', 'TOOL-003', 'MCP-006', 'MCP-007', 'MCP-008', 'MCP-009'];
const MCP_CONTROLS = ['2.3', '4.1', '5.2'];

// An MCP-typed tree: the checks run, and an absent config is a measured
// absence rather than a non-MCP project.
const PACKAGE_JSON = JSON.stringify({ name: 't', version: '1.0.0', dependencies: { '@modelcontextprotocol/sdk': '^1.0.0' } });
// A config every MCP-scoped L1 control fails on: no allowedTools (TOOL-001:
// controls 2.3, 4.1), no timeout (MCP-006) and a sensitive server name
// (MCP-009): control 5.2.
const FAILING = JSON.stringify({ servers: { shell: { command: 'shell-server', args: ['--stdio'] } } });
// A config the same controls pass on.
const CLEAN = JSON.stringify({
  timeout: 30000,
  retries: 3,
  servers: { files: { command: 'files-server', args: ['./data'], allowedTools: ['read_file'], maxTokens: 1000 } },
});

interface Record_ { checkId: string; file?: string; passed?: boolean; notApplicable?: { subject: string; reason: string } }
interface Control { controlId: string; status: string; notApplicableSubjects?: string[] }

function tree(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'hma-637-'));
  writeFileSync(join(dir, 'package.json'), PACKAGE_JSON);
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(dir, name), content);
  }
  return dir;
}

function scan(dir: string, extra: string[]): any {
  const r = spawnSync(process.execPath, [CLI, 'secure', dir, '--no-machine-posture', '--format', 'json', ...extra], {
    encoding: 'utf-8',
    timeout: SCAN_TIMEOUT,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: mkdtempSync(join(tmpdir(), 'hma-637-home-')) },
  });
  expect(r.stdout, r.stderr).toBeTruthy();
  return JSON.parse(r.stdout);
}

/** The root-config records of a plain scan. */
function records(dir: string): Record_[] {
  const out = scan(dir, []);
  return (out.allFindings as Record_[]).filter((f) => ROOT_MCP_CHECK.test(f.checkId));
}

/** compliance + the MCP-scoped L1 control statuses of an OASB-1 scan. */
function benchmark(dir: string): { compliance: number | null; controls: Map<string, Control> } {
  const out = scan(dir, ['-b', 'oasb-1', '-l', 'L1']);
  const controls = new Map<string, Control>();
  for (const category of out.categories) {
    for (const control of category.controls as Control[]) {
      controls.set(control.controlId, control);
    }
  }
  return { compliance: out.compliance, controls };
}

function statuses(b: ReturnType<typeof benchmark>): Record<string, string> {
  return Object.fromEntries([...b.controls.values()].map((c) => [c.controlId, c.status]));
}

describe('root MCP config discovery (#637)', () => {
  beforeAll(assertDistFreshIfPresent);

  it('parity: the same servers score identically as mcp.json and as .mcp.json, and every record names its file', () => {
    const plain = benchmark(tree({ 'mcp.json': FAILING }));
    const dot = benchmark(tree({ '.mcp.json': FAILING }));

    // The issue's measurement, inverted: identical figure, identical statuses.
    expect(dot.compliance).toBe(plain.compliance);
    expect(statuses(dot)).toEqual(statuses(plain));
    // And the figure is a MEASURED one: the live servers fail the controls
    // under both spellings — not-applicable under neither.
    for (const id of MCP_CONTROLS) {
      expect(dot.controls.get(id)?.status, id).toBe('failed');
    }

    const dotRecords = records(tree({ '.mcp.json': FAILING }));
    expect(dotRecords.length).toBeGreaterThan(0);
    for (const r of dotRecords) {
      expect(r.notApplicable, r.checkId).toBeUndefined();
      // MCP-010 is the one informational record over every file read.
      if (r.checkId !== 'MCP-010') {
        expect(r.file, r.checkId).toBe('.mcp.json');
      }
    }
  }, SCAN_TIMEOUT * 4);

  it('both spellings present, clean mcp.json beside a failing .mcp.json: every live config is evaluated', () => {
    const dir = tree({ 'mcp.json': CLEAN, '.mcp.json': FAILING });
    const found = records(dir);
    for (const checkId of ['TOOL-001', 'MCP-006', 'MCP-009']) {
      const files = found.filter((r) => r.checkId === checkId).map((r) => r.file).sort();
      expect(files, checkId).toEqual(['.mcp.json', 'mcp.json']);
      expect(found.find((r) => r.checkId === checkId && r.file === '.mcp.json')?.passed, checkId).toBe(false);
    }
    // The evaluator folds every record per checkId: one failing file fails
    // the control. A last-record-wins map would pass 2.3 here on the clean
    // mcp.json record emitted first.
    const b = benchmark(dir);
    for (const id of MCP_CONTROLS) {
      expect(b.controls.get(id)?.status, id).toBe('failed');
    }
  }, SCAN_TIMEOUT * 2);

  it('both spellings present, the reverse: a clean .mcp.json cannot launder a failing mcp.json', () => {
    const dir = tree({ 'mcp.json': FAILING, '.mcp.json': CLEAN });
    const found = records(dir);
    expect(found.find((r) => r.checkId === 'TOOL-001' && r.file === 'mcp.json')?.passed).toBe(false);
    expect(found.find((r) => r.checkId === 'TOOL-001' && r.file === '.mcp.json')?.passed).toBe(true);
    const b = benchmark(dir);
    for (const id of MCP_CONTROLS) {
      expect(b.controls.get(id)?.status, id).toBe('failed');
    }
  }, SCAN_TIMEOUT * 2);

  it('neither spelling present on an MCP-typed tree: one not-applicable per check, naming the set', () => {
    const dir = tree({});
    const found = records(dir);
    for (const checkId of NA_CHECKS) {
      const na = found.filter((r) => r.checkId === checkId);
      expect(na.length, checkId).toBe(1);
      expect(na[0].notApplicable?.subject, checkId).toBe(SUBJECT);
      expect(na[0].notApplicable?.reason, checkId).not.toContain('outside its scope');
    }
    const b = benchmark(dir);
    for (const id of MCP_CONTROLS) {
      expect(b.controls.get(id)?.status, id).toBe('not-applicable');
      expect(b.controls.get(id)?.notApplicableSubjects, id).toContain(SUBJECT);
    }
  }, SCAN_TIMEOUT * 2);

  it('an env reference in .mcp.json is not a hardcoded secret', () => {
    // The widened CONFIG_CANDIDATE_NAMES puts .mcp.json in front of CRED-001
    // too; the env-reference exemption must hold there as it does for mcp.json.
    const dir = tree({ '.mcp.json': JSON.stringify({ servers: { api: { command: 'api-server', env: { API_TOKEN: '${API_TOKEN}' } } } }) });
    const out = scan(dir, []);
    const failed = (out.allFindings as Record_[]).filter((f) => f.passed === false && /^(MCP-003|CRED-001)$/.test(f.checkId));
    expect(failed.map((f) => `${f.checkId} ${f.file}`)).toEqual([]);
  }, SCAN_TIMEOUT);
});
