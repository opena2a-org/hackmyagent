/**
 * A `null` entry in a VS Code MCP config's `servers` map is skipped, not read
 * (#891).
 *
 * The VSCODE-002 loop read `server.args` on every value of the map, so a
 * `.vscode/mcp.json` holding `"a": null` made `secure` exit 1 with
 * "Cannot read properties of null (reading 'args')" and print no report. Every
 * other server loop in the scanner already skips a value that is not an
 * object; this one now does too, and the entries beside the `null` are still
 * evaluated.
 */
import { describe, it, expect, afterAll } from 'vitest';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { SecurityFinding } from '../../src/hardening/security-check';
import { initThrowawayRepo } from '../helpers/throwaway-repo';

const SCAN_TIMEOUT = 120_000;

const tempDirs: string[] = [];

afterAll(async () => {
  for (const dir of tempDirs) {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

async function vscodeTree(servers: Record<string, unknown>): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
  tempDirs.push(dir);
  await fs.writeFile(
    path.join(dir, 'package.json'),
    JSON.stringify({ name: 'vscode-null', version: '1.0.0', dependencies: { '@modelcontextprotocol/sdk': '^1.0.0' } }),
  );
  await fs.mkdir(path.join(dir, '.vscode'));
  await fs.writeFile(path.join(dir, '.vscode', 'mcp.json'), JSON.stringify({ servers }));
  initThrowawayRepo(dir);
  return dir;
}

async function vscode002(dir: string): Promise<SecurityFinding[]> {
  const result = await new HardeningScanner().scan({ targetDir: dir });
  return (result.allFindings ?? []).filter((f) => f.checkId === 'VSCODE-002');
}

describe('VSCODE-002 skips a null server entry', () => {
  it(
    'completes the scan and still evaluates the entry beside the null',
    async () => {
      const dir = await vscodeTree({ a: null, b: { command: 'node', args: ['/'] } });
      const found = await vscode002(dir);
      expect(found).toHaveLength(1);
      expect(found[0].passed).toBe(false);
      expect(found[0].message).toBe('VSCode MCP server has dangerous filesystem access');
    },
    SCAN_TIMEOUT,
  );

  it(
    'reports scoped access when the null is the only entry',
    async () => {
      const dir = await vscodeTree({ a: null });
      const found = await vscode002(dir);
      expect(found).toHaveLength(1);
      expect(found[0].passed).toBe(true);
      expect(found[0].message).toBe('VSCode MCP filesystem access is scoped');
    },
    SCAN_TIMEOUT,
  );
});
