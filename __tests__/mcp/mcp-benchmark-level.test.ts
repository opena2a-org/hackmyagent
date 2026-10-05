/**
 * `hackmyagent_benchmark` refuses a level outside L1-L3 with the CLI's message (#650).
 *
 * The low-level MCP `Server` does not enforce the tool schema's enum, so `L9`
 * reached the rating ladder and came back as `RATING_LADDER[level] is not
 * iterable`: an internal error, and no hint of what the tool accepts. The
 * handler now refuses before any scan runs, and the exported assessor refuses
 * on its own, both with the line the CLI prints for `-l L9`.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assessBenchmarkFindings, handleToolCall } from '../../src/mcp-server';
import type { BenchmarkLevel } from '../../src/index';

let root: string;
beforeAll(() => {
  // Real path: the roots check compares resolved paths, and macOS tmp is a /var symlink.
  root = realpathSync(mkdtempSync(join(tmpdir(), 'hma-650-')));
  writeFileSync(join(root, 'package.json'), '{"name":"t","version":"1.0.0"}\n');
});
afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

const textOf = (res: { content: { text?: string }[] }) => res.content.map((c) => c.text ?? '').join('\n');

describe('hackmyagent_benchmark validates level (#650)', () => {
  for (const level of ['L9', 'l0', '', 'L1 ', 3]) {
    it(`refuses ${JSON.stringify(level)} with the CLI's message`, async () => {
      const res = await handleToolCall('hackmyagent_benchmark', { directory: root, level }, [root]);
      expect(res.isError, textOf(res)).toBe(true);
      expect(textOf(res)).toBe(`Error: Invalid level '${String(level)}'. Use: L1, L2, or L3`);
      expect(textOf(res)).not.toContain('RATING_LADDER');
    });
  }

  it('still assesses every valid level, in either case, and defaults to L1', async () => {
    for (const level of ['L1', 'l2', 'L3', undefined]) {
      const res = await handleToolCall('hackmyagent_benchmark', { directory: root, level }, [root]);
      expect(res.isError, `${String(level)}: ${textOf(res)}`).toBeFalsy();
      expect(textOf(res)).toContain(`OASB-1 ${level === undefined ? 'L1' : level.toUpperCase()} Assessment`);
    }
  });

  // #865 — a client that serializes an unset optional argument as `null` gets
  // the default an omitted level gets, not a refusal of the string 'null'.
  it('treats an explicit null level as unset and assesses L1', async () => {
    const res = await handleToolCall('hackmyagent_benchmark', { directory: root, level: null }, [root]);
    expect(res.isError, textOf(res)).toBeFalsy();
    expect(textOf(res)).toContain('OASB-1 L1 Assessment');
  });

  it('the exported assessor refuses on its own', () => {
    expect(() => assessBenchmarkFindings([], 'L9' as BenchmarkLevel)).toThrow(
      "Invalid level 'L9'. Use: L1, L2, or L3",
    );
    expect(() => assessBenchmarkFindings([], 'L2')).not.toThrow();
  });
});
