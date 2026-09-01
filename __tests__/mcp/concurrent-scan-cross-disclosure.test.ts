/**
 * HMA-26.AC3 — no cross-disclosure through MCP.
 *
 * One MCP server process serves every client, so two overlapping
 * `hackmyagent_scan` calls against disjoint granted roots run concurrently in
 * one process. At the base the ledger they both read was the module global
 * (`activeLedger`, coverage-ledger.ts), so each call's confinement was
 * decided against whichever call installed last, and records keyed by `rel`
 * were visible across the two callers.
 *
 * Both fixtures here are the full all-basenames link tree, which plants the
 * SAME nine rels (`.env`, `CLAUDE.md`, `skills`, ...) resolving into each
 * fixture's own out-of-tree directory, and whose probes span the whole scan —
 * so the two calls genuinely overlap at withholding sites, and an overwrite
 * or cross-read of a rel-keyed record is observable in the returned text.
 * Each call must disclose every one of its own records with its own resolved
 * target, and neither call's text may name a link, path or withheld entry
 * from the other call's tree, nor return out-of-tree bytes from either.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { handleToolCall } from '../../src/mcp-server';
import { buildLinkFixture, CANARY, type LinkFixture } from '../helpers/out-of-tree-link-fixture';

let fxA: LinkFixture;
let fxB: LinkFixture;

function text(r: { content: Array<{ type: string; text?: string }> }): string {
  return r.content.map((c) => c.text ?? '').join('\n');
}

beforeAll(() => {
  fxA = buildLinkFixture('hma26-mcp-a-');
  fxB = buildLinkFixture('hma26-mcp-b-');
});

afterAll(() => {
  fs.rmSync(fxA.base, { recursive: true, force: true });
  fs.rmSync(fxB.base, { recursive: true, force: true });
});

describe('overlapping hackmyagent_scan calls with disjoint roots', () => {
  it('HMA-26.AC3 each call discloses exactly its own withheld links and neither text names the other tree\'s links, paths or bytes', async () => {
    const [ra, rb] = await Promise.all([
      handleToolCall('hackmyagent_scan', { directory: fxA.linked }, [fxA.linked]),
      handleToolCall('hackmyagent_scan', { directory: fxB.linked }, [fxB.linked]),
    ]);
    expect(ra.isError).toBeUndefined();
    expect(rb.isError).toBeUndefined();
    const ta = text(ra);
    const tb = text(rb);

    // Each call withheld and disclosed every one of ITS OWN links: the record
    // keyed by each rel carries the resolved target of the caller's own tree.
    // Both trees plant the same rels, so a record overwritten by — or read
    // from — the other scan surfaces the other tree's target here instead.
    for (const planted of fxA.plantedLinks) {
      expect(ta).toContain(`${planted.rel} -> ${planted.resolved}`);
    }
    for (const planted of fxB.plantedLinks) {
      expect(tb).toContain(`${planted.rel} -> ${planted.resolved}`);
    }

    // No cross-disclosure on any channel: nothing under the other fixture's
    // base (its tree, its shared directory, any withheld entry's target) is
    // named in the returned text.
    expect(ta).not.toContain(fxB.base);
    expect(tb).not.toContain(fxA.base);

    // And no out-of-tree bytes came back to either caller: withheld means
    // neither its own targets' contents nor the other's.
    expect(ta).not.toContain(CANARY);
    expect(tb).not.toContain(CANARY);
  });
});
