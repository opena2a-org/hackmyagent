/**
 * #479 — Layer 3 requested and unable to run at all is reported, not absorbed.
 *
 * Two origins, one condition: no `ANTHROPIC_API_KEY` (the layer used to be
 * skipped before discovery), and a throw that escapes `LLMAnalyzer.analyze`
 * (the catch around the layer was empty). Either way the scan used to look
 * exactly like a deep scan whose analyst found nothing. This drives the real
 * scanner with the analyzer replaced, and asserts ONE run-level record.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { tempDir } from '../helpers/temp-dir';

const behaviour: { mode: 'throw' | 'clean'; constructed: number } = { mode: 'clean', constructed: 0 };

vi.mock('../../src/semantic', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/semantic')>();
  class StubLLMAnalyzer {
    constructor(_opts: unknown) {
      behaviour.constructed++;
    }
    async analyze(_files: unknown[]) {
      if (behaviour.mode === 'throw') throw new Error('budget ledger unreadable');
      return { findings: [], cost: 0, cachedResults: 0, unanalyzed: [] };
    }
  }
  return { ...actual, LLMAnalyzer: StubLLMAnalyzer };
});

import { HardeningScanner } from '../../src/hardening/scanner';

let dir: string;
let priorKey: string | undefined;

beforeEach(async () => {
  behaviour.mode = 'clean';
  behaviour.constructed = 0;
  dir = tempDir('hma-479-not-run-');
  priorKey = process.env.ANTHROPIC_API_KEY;
});

afterEach(async () => {
  if (priorKey === undefined) delete process.env.ANTHROPIC_API_KEY;
  else process.env.ANTHROPIC_API_KEY = priorKey;
  await rm(dir, { recursive: true, force: true });
});

async function scan(deep: boolean) {
  await writeFile(path.join(dir, 'settings.json'), JSON.stringify({ apiUrl: 'https://example.test' }, null, 2));
  await writeFile(path.join(dir, 'app.ts'), 'export const port = 8080;\n');
  const result = await new HardeningScanner().scan({ targetDir: dir, deep });
  return result.findings.filter((f) => f.checkId === 'SEM-LLM-NOT-ANALYZED');
}

describe('#479 Layer 3 that could not run is reported once for the run', () => {
  it('no key: one record naming the key and the file count, and no analyzer is built', async () => {
    delete process.env.ANTHROPIC_API_KEY;
    const records = await scan(true);
    expect(records).toHaveLength(1);
    const [f] = records;
    expect(f.passed).toBe(false);
    expect(f.severity).toBe('medium');
    expect(f.message).toContain('ANTHROPIC_API_KEY is not set');
    expect(f.message).toMatch(/\d+ files? it would have analyzed (was|were) not analyzed/);
    expect(f.message.toLowerCase()).toContain('not a clean result');
    expect(f.fix).toBe('Set ANTHROPIC_API_KEY and re-run with --deep, or drop --deep for the static and semantic result');
    // Never a network call, so never an analyzer.
    expect(behaviour.constructed).toBe(0);
  });

  it('the Layer 3 call throws: one record naming the failure, where the catch used to be empty', async () => {
    process.env.ANTHROPIC_API_KEY = 'unused-by-the-stub';
    behaviour.mode = 'throw';
    const records = await scan(true);
    // Loud, not vacuous: the stub must have been reached for the throw to count.
    expect(behaviour.constructed, 'Layer 3 was never reached — this case measured nothing').toBeGreaterThan(0);
    expect(records).toHaveLength(1);
    expect(records[0].message).toContain('the Layer 3 call failed (budget ledger unreadable)');
  });

  it('Layer 3 runs and answers: no record', async () => {
    process.env.ANTHROPIC_API_KEY = 'unused-by-the-stub';
    const records = await scan(true);
    expect(behaviour.constructed).toBeGreaterThan(0);
    expect(records).toHaveLength(0);
  });

  it('not a deep scan: no record, even with no key', async () => {
    delete process.env.ANTHROPIC_API_KEY;
    expect(await scan(false)).toHaveLength(0);
  });

  it('no key and nothing for Layer 3 to analyze: no record', async () => {
    delete process.env.ANTHROPIC_API_KEY;
    const result = await new HardeningScanner().scan({ targetDir: dir, deep: true });
    expect(result.findings.filter((f) => f.checkId === 'SEM-LLM-NOT-ANALYZED')).toHaveLength(0);
  });
});
