/**
 * #869 — `secure` completes when an MCP server's `args` is not a list.
 *
 * The MCP checks in `scanner.ts` read `server.args` as a string array after a
 * truthiness check only. A server entry whose `args` is a string, a number or
 * an object passed that check and the first `findIndex` threw, so `secure`
 * ended with "server.args.findIndex is not a function", exit 1 and no report
 * at all — for the whole tree, on the strength of one malformed entry. Every
 * other `args` reader (`some`, `join`) failed the same way on the same input.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { SecurityFinding } from '../../src/hardening/security-check';

let dir: string;

beforeEach(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma-869-args-'));
  // `mcp`-typed: the MCP- check group applies to MCP projects only.
  await fs.writeFile(
    path.join(dir, 'package.json'),
    JSON.stringify({ name: 'test-project', version: '1.0.0', dependencies: { '@modelcontextprotocol/sdk': '^1.0.0' } }, null, 2),
  );
});

afterEach(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

function mcp001(findings: SecurityFinding[]): SecurityFinding | undefined {
  return findings.find((f) => f.checkId === 'MCP-001' && f.passed === false);
}

/** The `args` shapes that are not a list of strings. */
const SHAPES: Array<[string, unknown]> = [
  ['a string', '--foo'],
  ['a number', 7],
  ['an object', { a: 'b' }],
  ['a list with a non-string element', ['/', 7]],
];

describe('#869: an MCP server whose args is not a list does not stop secure', () => {
  for (const [label, args] of SHAPES) {
    for (const mapKey of ['mcpServers', 'servers'] as const) {
      it(`args as ${label} under ${mapKey}: the scan completes and the other server is still read`, async () => {
        await fs.writeFile(
          path.join(dir, 'mcp.json'),
          JSON.stringify(
            {
              [mapKey]: {
                malformed: { command: 'node', args },
                filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
              },
            },
            null,
            2,
          ) + '\n',
        );

        const result = await new HardeningScanner().scan({ targetDir: dir });

        expect(result.findings.length).toBeGreaterThan(0);
        const finding = mcp001(result.findings);
        expect(finding, `MCP-001 was silent on the root-scoped server beside a malformed one under ${mapKey}`).toBeDefined();
        expect(finding?.file).toBe('mcp.json');
      });
    }
  }
});
