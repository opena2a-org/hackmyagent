/**
 * #470 — an MCP server granted an unbounded filesystem root, with no tool key
 * and nothing else wrong in the file, is reported by `check <dir>`.
 *
 * Before #740, `check <dir>` ran only the semantic artifact matrix. The
 * structural MCP check that reads a server's arguments (SEM-MCP-001) ran under
 * `secure` alone, so this config scored 96/100 "Usable with caveats", exit 0,
 * under `check` while `secure` reported it CRITICAL. A local directory now goes
 * through the pipeline `secure` runs; this holds that on the issue's own
 * fixture, against a control rooted at a project subdirectory.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

const EXIT_FAIL = 1;

/** The issue's config, byte for byte: the root is the last argument. */
function config(root: string): string {
  return [
    '{',
    '  "mcpServers": {',
    '    "filesystem": {',
    '      "command": "npx",',
    `      "args": ["-y", "@modelcontextprotocol/server-filesystem", "${root}"]`,
    '    }',
    '  }',
    '}',
    '',
  ].join('\n');
}

const ARGS_LINE = 5;

let home: string;
let unbounded: string;
let scoped: string;

function run(args: string[]) {
  const res = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 240_000,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home },
  });
  return { status: res.status, stdout: res.stdout ?? '', out: `${res.stdout ?? ''}${res.stderr ?? ''}` };
}

function json(args: string[]) {
  const res = run([...args, '--json']);
  return { status: res.status, body: JSON.parse(res.stdout) as any };
}

const mcp001 = (findings: any[] | undefined) =>
  (findings ?? []).filter((f: any) => f.checkId === 'SEM-MCP-001' && !f.passed);

beforeAll(() => {
  const tmp = tempDir('hma-470-');
  home = path.join(tmp, 'home');
  unbounded = path.join(tmp, 'unbounded');
  scoped = path.join(tmp, 'scoped');
  for (const d of [home, unbounded, scoped]) fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(unbounded, 'mcp.json'), config('/'));
  fs.writeFileSync(path.join(scoped, 'mcp.json'), config('./docs'));
  // The cited line is the one that holds the root argument.
  expect(config('/').split('\n')[ARGS_LINE - 1]).toContain('"/"]');
});

describe('#470 check <dir> reports an unbounded MCP filesystem root', { timeout: 300_000 }, () => {
  // A checkout that has not built fails here, naming the command to run.
  beforeAll(assertDistFresh);

  it('check --no-registry: SEM-MCP-001 CRITICAL at the root argument, exit 1', () => {
    const { status, body } = json(['check', unbounded, '--no-registry']);
    expect(status).toBe(EXIT_FAIL);
    const findings = mcp001(body.details);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].file).toBe('mcp.json');
    expect(findings[0].line).toBe(ARGS_LINE);
  });

  it('the human report cites the same line and fails the run', () => {
    const { status, out } = run(['check', unbounded, '--no-registry']);
    expect(status).toBe(EXIT_FAIL);
    expect(out).toMatch(/CRITICAL\s+Overprivileged MCP server scope/);
    expect(out).toContain(`mcp.json:${ARGS_LINE}`);
  });

  it('check scores the tree the way secure scores it', () => {
    const check = json(['check', unbounded, '--no-registry']);
    const secure = json(['secure', unbounded, '--no-registry']);
    expect(secure.status).toBe(EXIT_FAIL);
    expect(mcp001(secure.body.findings)).toHaveLength(1);
    expect(check.body.score).toBe(secure.body.score);
  });

  it('control: the same server rooted at ./docs raises no SEM-MCP-001', () => {
    const { body } = json(['check', scoped, '--no-registry']);
    expect(body.measured).toBe(true);
    expect(mcp001(body.details)).toHaveLength(0);
  });
});
