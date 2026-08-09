/**
 * #462 — a file Layer 3 could not read an answer for is REPORTED, not counted
 * as examined.
 *
 * `parseFindings` returned `[]` for an unreadable response, so a file that made
 * the analyst's answer unparseable scored exactly like a file with nothing in
 * it. The parse now has three states, and `LLMAnalyzer.analyze` hands back the
 * files it could not read — but handing them back closes nothing on its own.
 * The half that reaches a user is the emission in `HardeningScanner`, and
 * mutation found it untested: replacing `llmResult.unanalyzed` with an empty
 * array left the entire suite green, because nothing anywhere in the repo
 * mentioned `SEM-LLM-NOT-ANALYZED`.
 *
 * So this drives the real scanner over a real temp tree with Layer 3 stubbed,
 * and asserts the gap arrives as a finding a person can act on.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

/** Every batch of files Layer 3 was asked to analyse, across every scan. */
const analyzed: string[][] = [];

const REASON = "the analyst's response was not the JSON array the prompt asks for";

vi.mock('../../src/semantic', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/semantic')>();
  class UnreadableLLMAnalyzer {
    constructor(_opts: unknown) {}
    /**
     * Answers the way the defect does: the call SUCCEEDS, costs money, and
     * yields nothing readable. Throwing instead would exercise the outer catch,
     * which is a different path.
     */
    async analyze(files: { path: string }[]) {
      const paths = (files ?? []).map((f) => {
        if (typeof f?.path !== 'string') {
          throw new Error(
            `AnalysisFile.path is not a string (got ${typeof f?.path}). This test can no `
            + 'longer tell which files went unanalysed, so it cannot prove they are reported.',
          );
        }
        return f.path;
      });
      analyzed.push(paths);
      return {
        findings: [],
        cost: 0.01,
        cachedResults: 0,
        unanalyzed: paths.map((p) => ({ path: p, reason: REASON })),
      };
    }
  }
  return { ...actual, LLMAnalyzer: UnreadableLLMAnalyzer };
});

import { HardeningScanner } from '../../src/hardening/scanner';

let dir: string;
let priorKey: string | undefined;

beforeEach(async () => {
  analyzed.length = 0;
  dir = await mkdtemp(path.join(tmpdir(), 'hma-462-unanalyzed-'));
  // Layer 3 is gated on a key being present. The analyzer above never reads it.
  priorKey = process.env.ANTHROPIC_API_KEY;
  process.env.ANTHROPIC_API_KEY = 'unused-by-the-stub';
});

afterEach(async () => {
  if (priorKey === undefined) delete process.env.ANTHROPIC_API_KEY;
  else process.env.ANTHROPIC_API_KEY = priorKey;
  await rm(dir, { recursive: true, force: true });
});

async function scanWithUnreadableLayer3() {
  await writeFile(path.join(dir, 'settings.json'), JSON.stringify({ apiUrl: 'https://example.test' }, null, 2));
  await writeFile(path.join(dir, 'app.ts'), 'export const port = 8080;\n');
  const result = await new HardeningScanner().scan({ targetDir: dir, deep: true });
  // Loud, not silent: if discovery hands Layer 3 nothing, every assertion below
  // would pass vacuously against a scanner that emits nothing at all.
  expect(analyzed.length, 'Layer 3 was never reached — this test measured nothing').toBeGreaterThan(0);
  expect(analyzed[0].length, 'Layer 3 was reached with zero files — nothing could be unanalysed').toBeGreaterThan(0);
  return result;
}

describe('#462 a file Layer 3 could not read is reported, not counted as examined', () => {
  it('emits one finding per unanalysed file', async () => {
    const result = await scanWithUnreadableLayer3();
    const missed = result.findings.filter((f) => f.checkId === 'SEM-LLM-NOT-ANALYZED');
    expect(missed.length).toBe(analyzed[0].length);
  });

  it('does not report the gap as a passed check', async () => {
    const result = await scanWithUnreadableLayer3();
    const missed = result.findings.filter((f) => f.checkId === 'SEM-LLM-NOT-ANALYZED');
    expect(missed.length).toBeGreaterThan(0);
    for (const f of missed) expect(f.passed).toBe(false);
  });

  it('names the specific file and says why, rather than reporting a general gap', async () => {
    const result = await scanWithUnreadableLayer3();
    const missed = result.findings.filter((f) => f.checkId === 'SEM-LLM-NOT-ANALYZED');
    for (const f of missed) {
      expect(analyzed[0]).toContain(f.file);
      expect(f.message).toContain(f.file!);
      expect(f.message).toContain(REASON);
    }
  });

  it('offers a runnable command rather than advice', async () => {
    const result = await scanWithUnreadableLayer3();
    const [f] = result.findings.filter((x) => x.checkId === 'SEM-LLM-NOT-ANALYZED');
    expect(f.fix).toContain('secure ');
    expect(f.fix).toContain('--deep');
  });

  it('says the result is a coverage gap and not a clean bill', async () => {
    const result = await scanWithUnreadableLayer3();
    const [f] = result.findings.filter((x) => x.checkId === 'SEM-LLM-NOT-ANALYZED');
    // The distinction the whole fix is about. "Not analysed" reading as "nothing
    // found" is the defect; the text has to carry the difference to the person.
    expect(f.message.toLowerCase()).toContain('not a clean result');
    expect(f.description.toLowerCase()).toContain('has not been analyzed');
  });
});
