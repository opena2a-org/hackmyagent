/**
 * #639 — spawn-level: a wildcard MCP grant now moves the OASB-1 benchmark.
 *
 * Fixture: an `mcp.json` whose one server grants `allowedTools: ["*"]`
 * (SEM-MCP-004, control 2.1's own audit step). Before: 2.1 read
 * `unverified`, the tree beside a lockfile rated `Certified 100% (11/11)`
 * at exit 0 and `--fail-below 100` exited 0. Now: `[-] 2.1`, `Passing`,
 * `11/12`, `--fail-below 100` exits 1, SARIF carries `OASB-1/2.1`, and the
 * same tree without the lockfile moves 56% (5/9) -> 50% (5/10).
 *
 * RED-ON-BASE cells fail on the 2a39b72 dist; PIN cells pass on both.
 *
 * #637 moved the whole-report figures the cells pin (never the #639 story):
 * the MCP checks' records gained `file:`, so the noise floor stopped
 * dropping their failing records on these non-MCP-typed fixtures — 2.3, 4.1
 * and 5.2 became measured. wild: 50% (5/10) -> 33% (4/12); wildLock:
 * `Passing 92% (11/12)` exit 0 -> `Needs Improvement 71% (10/14)` exit 1.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const MCP = '{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","./data"],"allowedTools":["*"]}}}\n';
const FLAGS = ['-b', 'oasb-1', '-l', 'L1', '--no-machine-posture'];

let wild: string;
let wildLock: string;
let empty: string;

beforeAll(() => {
  wild = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-639-wild-'));
  fs.writeFileSync(path.join(wild, 'mcp.json'), MCP);
  wildLock = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-639-lock-'));
  fs.writeFileSync(path.join(wildLock, 'mcp.json'), MCP);
  fs.writeFileSync(path.join(wildLock, 'package.json'), '{"name":"fx","version":"1.0.0","private":true,"dependencies":{}}\n');
  fs.writeFileSync(path.join(wildLock, 'package-lock.json'), '{"name":"fx","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"fx","version":"1.0.0"}}}\n');
  empty = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-639-empty-'));
});

afterAll(() => {
  for (const d of [wild, wildLock, empty]) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
});

function run(dir: string, args: string[]) {
  const r = spawnSync(process.execPath, [CLI, 'secure', dir, ...FLAGS, ...args], {
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-')) },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

function json(stdout: string): any {
  return JSON.parse(stdout.slice(stdout.indexOf('{')));
}

describe('#639 a wildcard MCP grant fails OASB-1 control 2.1', { timeout: 300_000 }, () => {
  it('fixture guard: the scan itself records the wildcard as SEM-MCP-004', () => {
    const r = spawnSync(process.execPath, [CLI, 'secure', wild, '--no-machine-posture', '--format', 'json'], {
      encoding: 'utf8', timeout: 240_000, maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-')) },
    });
    const body = json(r.stdout ?? '');
    const recs = (body.allFindings ?? body.findings).filter((f: any) => f.checkId === 'SEM-MCP-004');
    expect(recs.length).toBeGreaterThan(0);
  });

  // #637 — the wild/wildLock figures below moved when the MCP checks' records
  // gained `file:`: neither fixture's package.json types it as an MCP project,
  // so the noise floor had been dropping the checks' failing pathless records
  // (2.3/4.1 read unverified, 5.2 passed on the surviving MCP-009 record).
  // With file attribution 2.3, 4.1 and 5.2 are measured and fail on the
  // config's real gaps. The #639 story these cells pin is unchanged: the
  // wildcard grant fails 2.1 and the tree is never Certified.
  it('RED-ON-BASE text: [-] 2.1, the category shows 1/3, compliance 33% (4/12)', () => {
    const r = run(wild, ['--verbose']);
    expect(r.stdout).toMatch(/\[-\] 2\.1: Explicit Capability Grants/);
    expect(r.stdout).toMatch(/SEM-MCP-004: MCP server "fs" has allowedTools: \["\*"\]/);
    expect(r.stdout).toMatch(/Capability & Authorization: 1\/3 \(33%\)/);
    expect(r.stdout).toMatch(/Compliance: 33% \(4\/12 verified controls\)/);
    expect(r.stdout).toMatch(/Unverified: 14 controls/);
    expect(r.status).toBe(1);
  });

  it('RED-ON-BASE json: 2.1 failed with the SEM-MCP-004 finding and the record remediation', () => {
    const body = json(run(wild, ['--format', 'json']).stdout);
    const c = body.categories.flatMap((x: any) => x.controls).find((x: any) => x.controlId === '2.1');
    expect(c.status).toBe('failed');
    expect(c.findings[0]).toMatch(/^SEM-MCP-004: /);
    expect(c.notApplicableSubjects).toBeUndefined();
    expect(body.failedControls).toBe(8);
    expect(body.unverifiedControls).toBe(14);
    expect(body.l1Compliance).toBe(33);
  });

  it('RED-ON-BASE sarif: an OASB-1/2.1 result is emitted', () => {
    const body = json(run(wild, ['--format', 'sarif']).stdout);
    const ids = body.runs[0].results.map((x: any) => x.ruleId);
    expect(ids).toContain('OASB-1/2.1');
    expect(ids).toHaveLength(8);
  });

  it('RED-ON-BASE with a lockfile: never Certified, and --fail-below 100 exits 1', () => {
    const r = run(wildLock, []);
    // #637 — was `Rating: Passing`, `92% (11/12)`, exit 0: the three surfaced
    // MCP controls fail, the rating drops a rung, and the rating's own exit 1
    // now precedes any --fail-below evaluation on this fixture, so there is
    // no observable lenient threshold left to pin here.
    expect(r.stdout).toMatch(/Rating: Needs Improvement/);
    expect(r.stdout).toMatch(/Compliance: 71% \(10\/14 verified controls\)/);
    expect(r.stdout).not.toMatch(/Certified/);
    expect(r.status).toBe(1);
    const gated = run(wildLock, ['--fail-below', '100']);
    expect(gated.status).toBe(1);
  });

  it('PIN: an empty directory is unmoved — 2.1 unverified, 3/4/19/0, compliance 43', () => {
    const body = json(run(empty, ['--format', 'json']).stdout);
    const c = body.categories.flatMap((x: any) => x.controls).find((x: any) => x.controlId === '2.1');
    expect(c.status).toBe('unverified');
    expect([body.passedControls, body.failedControls, body.unverifiedControls, body.notApplicableControls]).toEqual([3, 4, 19, 0]);
    expect(body.compliance).toBe(43);
  });
});
