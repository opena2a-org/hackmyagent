/**
 * `scan --help` names the ports a scan tries when `-p` is not given.
 *
 * Before: the `--ports` option read `(default: common MCP ports)`, while a
 * scan without `-p` tried `DEFAULT_PORTS` (80 and 443), so the help promised
 * a port set the scan never ran.
 *
 * Now the option help is built from `DEFAULT_PORTS`, so the text and the run
 * name the same list.
 *
 * RED-ON-BASE: both cells fail on the old help text.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { DEFAULT_PORTS } from '../../src/scanner/external-scanner';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SRC_CLI = path.join(REPO_ROOT, 'src', 'cli.ts');
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

function scanHelp(): string {
  const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: tempDir('hma-scan-ports-home-') };
  delete env.HMA_CLI_PREFIX;
  const { bin, argv } = cliCommand(['scan', '--help']);
  // eslint-disable-next-line no-control-regex
  return execFileSync(bin, argv, { env, encoding: 'utf8', cwd: REPO_ROOT }).replace(/\x1b\[[0-9;]*m/g, '');
}

describe('scan --help names the default port set', () => {
  let portsLine = '';

  beforeAll(() => {
    const help = scanHelp();
    // Commander may wrap a long description; join the option's continuation lines.
    const lines = help.split('\n');
    const start = lines.findIndex((l) => /^\s*-p, --ports <ports>/.test(l));
    expect(start, 'scan --help has no `-p, --ports` option line').toBeGreaterThanOrEqual(0);
    const parts = [lines[start]];
    for (let i = start + 1; i < lines.length && /^\s{10,}\S/.test(lines[i]) && !/^\s*-/.test(lines[i]); i++) {
      parts.push(lines[i].trim());
    }
    portsLine = parts.join(' ');
  }, 60_000);

  it('names every port in DEFAULT_PORTS', () => {
    expect(DEFAULT_PORTS.length).toBeGreaterThan(0);
    expect(portsLine).toContain(`(default: ${DEFAULT_PORTS.join(',')})`);
  });

  it('does not promise "common MCP ports"', () => {
    expect(portsLine).not.toContain('common MCP ports');
  });
});
