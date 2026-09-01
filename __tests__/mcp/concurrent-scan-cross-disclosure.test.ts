/**
 * HMA-26.AC3 — no cross-disclosure through MCP.
 *
 * One MCP server process serves every client, so two overlapping
 * `hackmyagent_scan` calls against disjoint granted roots run concurrently in
 * one process. At the base the ledger they both read was the module global
 * (`activeLedger`, coverage-ledger.ts), so each call's confinement was
 * decided against whichever call installed last, and records keyed by `rel`
 * were visible across the two callers. Both fixtures here plant a link at the
 * SAME rel (`.env`) with a different resolved target, so an overwrite or a
 * cross-read is observable in the returned text: each call must disclose its
 * own `.env` record, and neither call's text may name a link, path, withheld
 * entry or file content from the other call's tree.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { handleToolCall } from '../../src/mcp-server';

const CANARY_A = 'CANARY_HMA26_TREE_A_7b3d';
const CANARY_B = 'CANARY_HMA26_TREE_B_e91c';

let tmp: string;
let rootA: string;
let rootB: string;
let outsideA: string;
let outsideB: string;
let resolvedA: string;
let resolvedB: string;

function project(dir: string, name: string): void {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), `{"name":"${name}","version":"1.0.0"}\n`);
  fs.writeFileSync(path.join(dir, 'README.md'), `# ${name}\n`);
}

function text(r: { content: Array<{ type: string; text?: string }> }): string {
  return r.content.map((c) => c.text ?? '').join('\n');
}

beforeAll(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hma26-mcp-')));
  rootA = path.join(tmp, 'tree-a');
  rootB = path.join(tmp, 'tree-b');
  outsideA = path.join(tmp, 'outside-a');
  outsideB = path.join(tmp, 'outside-b');
  project(rootA, 'tree-a');
  project(rootB, 'tree-b');
  fs.mkdirSync(outsideA, { recursive: true });
  fs.mkdirSync(outsideB, { recursive: true });
  // The SAME rel in both trees, resolving to different ungranted targets:
  // rel-keyed records that leak across the scans collide here and disclose
  // the wrong tree's target.
  resolvedA = path.join(outsideA, 'secrets.env');
  resolvedB = path.join(outsideB, 'secrets.env');
  fs.writeFileSync(resolvedA, `AWS_SECRET_ACCESS_KEY=${CANARY_A}\n`);
  fs.writeFileSync(resolvedB, `AWS_SECRET_ACCESS_KEY=${CANARY_B}\n`);
  fs.chmodSync(resolvedA, 0o644);
  fs.chmodSync(resolvedB, 0o644);
  fs.symlinkSync(resolvedA, path.join(rootA, '.env'));
  fs.symlinkSync(resolvedB, path.join(rootB, '.env'));
});

afterAll(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('overlapping hackmyagent_scan calls with disjoint roots', () => {
  it('HMA-26.AC3 neither call\'s text names the other tree\'s links or paths, and rel-keyed records are not overwritten across the scans', async () => {
    const [ra, rb] = await Promise.all([
      handleToolCall('hackmyagent_scan', { directory: rootA }, [rootA]),
      handleToolCall('hackmyagent_scan', { directory: rootB }, [rootB]),
    ]);
    expect(ra.isError).toBeUndefined();
    expect(rb.isError).toBeUndefined();
    const ta = text(ra);
    const tb = text(rb);

    // Each call withheld and disclosed ITS OWN `.env` — the record keyed by
    // that rel carries the resolved target of the caller's own tree.
    expect(ta).toContain(`.env -> ${resolvedA}`);
    expect(tb).toContain(`.env -> ${resolvedB}`);

    // Not overwritten across the scans: the same key never surfaces the other
    // caller's target.
    expect(ta).not.toContain(resolvedB);
    expect(tb).not.toContain(resolvedA);

    // No cross-disclosure on any channel: no path, link or withheld entry of
    // the other call's tree, and no file content from either side of it.
    expect(ta).not.toContain(rootB);
    expect(ta).not.toContain(outsideB);
    expect(ta).not.toContain(CANARY_B);
    expect(tb).not.toContain(rootA);
    expect(tb).not.toContain(outsideA);
    expect(tb).not.toContain(CANARY_A);

    // And confinement held for each call's own link too: withheld means the
    // bytes never came back to anyone.
    expect(ta).not.toContain(CANARY_A);
    expect(tb).not.toContain(CANARY_B);
  });
});
