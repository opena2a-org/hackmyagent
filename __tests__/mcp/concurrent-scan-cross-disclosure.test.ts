/**
 * HMA-26.AC3 (revision 2) — no cross-disclosure through MCP, asserted on what
 * the base actually gets wrong.
 *
 * One MCP server process serves every client, so two overlapping
 * `hackmyagent_scan` calls against disjoint granted roots run concurrently in
 * one process. At the base the ledger both calls consulted was the module
 * global (`activeLedger`, coverage-ledger.ts), so each call's confinement was
 * decided against whichever call installed last: its own out-of-tree links
 * passed the guard, their bytes were read, and findings derived from them
 * joined the returned text (measured at the base: `Score: 64/100 | 5 issues`
 * under overlap vs `93/100 | 2 issues` sequential, the extra findings citing
 * the very rels the sequential run withholds).
 *
 * The tooth, per the r2 contract: for EACH call, (a) the text returned under
 * overlap is byte-identical to the same call run sequentially, and (b) no
 * finding `Location:` names a rel the sequential run lists under
 * withheldLinks. The r1 premise ("records keyed by rel are overwritten across
 * callers") was measured false — `withholdOutOfTree` returns null for a
 * target outside the deciding ledger's roots before any record is made — so
 * nothing here asserts on record overwrites.
 *
 * The fixtures are DIFFERENT sizes on purpose: fixture B carries a few
 * hundred pad files fixture A does not, so the two calls do not finish
 * symmetrically — the short scan ends (and at the base, restores the global
 * over the long one) while the long scan is still withholding.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { handleToolCall } from '../../src/mcp-server';
import { buildLinkFixture, CANARY, type LinkFixture } from '../helpers/out-of-tree-link-fixture';

let fxA: LinkFixture;
let fxB: LinkFixture;

const PAD_FILES = 300;

function text(r: { content: Array<{ type: string; text?: string }> }): string {
  return r.content.map((c) => c.text ?? '').join('\n');
}

/**
 * The rels the withheld-links section lists. `mcpWithheldLinksText` is the
 * FIRST part of the tool text (parts are joined with '\n\n'), so the block is
 * everything before the first blank line: a header, one `  rel -> resolved`
 * line per record, then `  To scan ...` retarget lines.
 */
function withheldRels(t: string): string[] {
  const block = t.split('\n\n')[0] ?? '';
  if (!/^\d+ links? inside the scanned tree/.test(block)) return [];
  const rels: string[] = [];
  for (const line of block.split('\n')) {
    const m = /^ {2}(.+?) -> /.exec(line);
    if (m) rels.push(m[1]);
  }
  return rels;
}

/** Every `Location:` a finding in the text carries. */
function locations(t: string): string[] {
  const out: string[] = [];
  for (const line of t.split('\n')) {
    const m = /^ {2}Location: (.+)$/.exec(line);
    if (m) out.push(m[1]);
  }
  return out;
}

/** True when the Location cites `rel` itself, a line in it, or a path under it. */
function namesRel(location: string, rel: string): boolean {
  return (
    location === rel
    || location.startsWith(`${rel}:`)
    || location.startsWith(`${rel}${path.sep}`)
  );
}

beforeAll(() => {
  fxA = buildLinkFixture('hma26-mcp-a-');
  fxB = buildLinkFixture('hma26-mcp-b-');
  // Different sizes: pad fixture B's tree with benign files so its scan runs
  // well past fixture A's and the two calls cannot finish symmetrically.
  for (let i = 0; i < PAD_FILES; i++) {
    const at = path.join(fxB.linked, 'pad', `mod-${String(i).padStart(3, '0')}`, 'index.js');
    fs.mkdirSync(path.dirname(at), { recursive: true });
    fs.writeFileSync(at, `// pad module ${i}\nmodule.exports = { id: ${i}, ok: true };\n`);
  }
});

afterAll(() => {
  fs.rmSync(fxA.base, { recursive: true, force: true });
  fs.rmSync(fxB.base, { recursive: true, force: true });
});

describe('overlapping hackmyagent_scan calls with disjoint roots', () => {
  it('HMA-26.AC3 each overlapped call returns byte-identical text to its sequential run and no finding Location names a sequentially-withheld rel', async () => {
    // Sequential controls: each call alone, nothing else scanning.
    const seqA = await handleToolCall('hackmyagent_scan', { directory: fxA.linked }, [fxA.linked]);
    const seqB = await handleToolCall('hackmyagent_scan', { directory: fxB.linked }, [fxB.linked]);
    expect(seqA.isError).toBeUndefined();
    expect(seqB.isError).toBeUndefined();
    const seqTa = text(seqA);
    const seqTb = text(seqB);

    // Non-vacuity: each sequential run really withheld every planted link of
    // its own tree — the withheld list this test measures overlap against is
    // the full nine-rel list, not a remnant.
    const seqRelsA = withheldRels(seqTa);
    const seqRelsB = withheldRels(seqTb);
    for (const planted of fxA.plantedLinks) expect(seqRelsA).toContain(planted.rel);
    for (const planted of fxB.plantedLinks) expect(seqRelsB).toContain(planted.rel);

    // The same two calls, overlapping in one process.
    const [ovA, ovB] = await Promise.all([
      handleToolCall('hackmyagent_scan', { directory: fxA.linked }, [fxA.linked]),
      handleToolCall('hackmyagent_scan', { directory: fxB.linked }, [fxB.linked]),
    ]);
    expect(ovA.isError).toBeUndefined();
    expect(ovB.isError).toBeUndefined();
    const ovTa = text(ovA);
    const ovTb = text(ovB);

    // (a) Byte-identical to the sequential run: overlap changes nothing about
    // what either caller is told — not the score line, not the findings, not
    // the withheld list (the base returned `64/100 | 5 issues` here against a
    // sequential `93/100 | 2 issues`).
    expect(ovTa).toBe(seqTa);
    expect(ovTb).toBe(seqTb);

    // (b) No finding derived from bytes the caller's own sequential run
    // withholds: a Location naming a withheld rel means that rel's target was
    // read past the guard while the other call's ledger decided confinement.
    for (const rel of seqRelsA) {
      for (const loc of locations(ovTa)) {
        expect(namesRel(loc, rel), `finding at ${loc} names withheld rel ${rel}`).toBe(false);
      }
    }
    for (const rel of seqRelsB) {
      for (const loc of locations(ovTb)) {
        expect(namesRel(loc, rel), `finding at ${loc} names withheld rel ${rel}`).toBe(false);
      }
    }

    // Supplementary, unchanged from r1: nothing under the other fixture's
    // base is named, and no out-of-tree bytes came back to either caller.
    expect(ovTa).not.toContain(fxB.base);
    expect(ovTb).not.toContain(fxA.base);
    expect(ovTa).not.toContain(CANARY);
    expect(ovTb).not.toContain(CANARY);
  });
});
