/**
 * HMA-26 — the active CoverageLedger is carried per scan context.
 *
 * At the base, `withActiveLedger` saved and restored a module global, which
 * is correct for the nested case (the verify pass inside `--fix`) and wrong
 * for the concurrent one: two overlapping scans shared whichever ledger was
 * installed last, so each scan's reads were attributed — and its link
 * confinement decided — against the other scan's roots. The install now rides
 * `AsyncLocalStorage`, and this file pins the contract at the seam:
 * `currentLedger()` and every namespace reporter resolve the ledger of the
 * calling context, not of the last installer.
 *
 * The end-to-end halves live in `concurrent-scan-isolation.test.ts` (two real
 * `scan()` calls, zero out-of-tree reaches) and
 * `__tests__/mcp/concurrent-scan-cross-disclosure.test.ts`.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as realFs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fs } from '../../src/hardening/tracked-fs';
import { CoverageLedger, withActiveLedger, currentLedger } from '../../src/hardening/coverage-ledger';

let base: string;
let rootA: string;
let rootB: string;
let outsideA: string;
let outsideB: string;

beforeAll(() => {
  base = realFs.realpathSync(realFs.mkdtempSync(path.join(os.tmpdir(), 'hma26-ctx-')));
  rootA = path.join(base, 'tree-a');
  rootB = path.join(base, 'tree-b');
  outsideA = path.join(base, 'outside-a');
  outsideB = path.join(base, 'outside-b');
  for (const d of [rootA, rootB, outsideA, outsideB]) realFs.mkdirSync(d, { recursive: true });
  realFs.writeFileSync(path.join(rootA, 'one.txt'), 'A1\n');
  realFs.writeFileSync(path.join(rootA, 'two.txt'), 'A2\n');
  realFs.writeFileSync(path.join(rootB, 'one.txt'), 'B1\n');
  realFs.writeFileSync(path.join(outsideA, 'secret.txt'), 'OUT-A\n');
  realFs.writeFileSync(path.join(outsideB, 'secret.txt'), 'OUT-B\n');
  realFs.symlinkSync(path.join(outsideA, 'secret.txt'), path.join(rootA, 'link.txt'));
  realFs.symlinkSync(path.join(outsideB, 'secret.txt'), path.join(rootB, 'link.txt'));
});

afterAll(() => {
  realFs.rmSync(base, { recursive: true, force: true });
});

/** A real async yield, so interleaved contexts actually hand control over. */
const tick = (): Promise<void> => new Promise((r) => setImmediate(r));

describe('per-scan ledger context', () => {
  it('HMA-26.AC1 nested withActiveLedger attributes inner reads to the inner ledger and the outer ledger resumes intact', async () => {
    const outer = new CoverageLedger(rootA);
    const inner = new CoverageLedger(rootA);
    // Reads attribute only inside a registered check frame (`ledger.run`), as
    // in a real scan; each ledger's frame wraps its own scan's reads.
    await withActiveLedger(outer, () => outer.run('outer-check', async () => {
      expect(currentLedger()).toBe(outer);
      await fs.readFile(path.join(rootA, 'one.txt'), 'utf-8');
      expect(outer.filesExamined).toBe(1);

      // The verify pass inside `--fix` constructs its own scanner: its reads
      // belong to ITS ledger, and the outer one resumes when it returns.
      await withActiveLedger(inner, () => inner.run('inner-check', async () => {
        expect(currentLedger()).toBe(inner);
        await fs.readFile(path.join(rootA, 'two.txt'), 'utf-8');
      }));
      expect(inner.filesExamined).toBe(1);
      expect(outer.filesExamined).toBe(1);

      expect(currentLedger()).toBe(outer);
      await fs.readFile(path.join(rootA, 'two.txt'), 'utf-8');
      expect(outer.filesExamined).toBe(2);
      expect(inner.filesExamined).toBe(1);
    }));
    expect(currentLedger()).toBeNull();
  });

  it('HMA-26.AC1 the outer ledger resumes intact when the inner run throws', async () => {
    const outer = new CoverageLedger(rootA);
    const inner = new CoverageLedger(rootA);
    await withActiveLedger(outer, async () => {
      await expect(
        withActiveLedger(inner, () => inner.run('inner-check', async () => {
          await fs.readFile(path.join(rootA, 'one.txt'), 'utf-8');
          throw new Error('inner scan failed');
        })),
      ).rejects.toThrow('inner scan failed');
      expect(currentLedger()).toBe(outer);
      expect(inner.filesExamined).toBe(1);
      expect(outer.filesExamined).toBe(0);
    });
    expect(currentLedger()).toBeNull();
  });

  it('HMA-26.AC1 two interleaved contexts each consult their own ledger, not whichever installed last', async () => {
    const ledgerA = new CoverageLedger(rootA);
    const ledgerB = new CoverageLedger(rootB);

    // Interleave hard: each context yields between every step, so at every
    // observation point the OTHER context has installed since. Under the
    // module-global base, every assertion inside context A after B starts
    // sees ledger B and A's out-of-tree link is followed, not withheld.
    const contextA = withActiveLedger(ledgerA, () => ledgerA.run('check-a', async () => {
      await tick();
      expect(currentLedger()).toBe(ledgerA);
      await fs.readFile(path.join(rootA, 'one.txt'), 'utf-8');
      await tick();
      let refused = false;
      try {
        await fs.readFile(path.join(rootA, 'link.txt'), 'utf-8');
      } catch {
        refused = true;
      }
      expect(refused, 'A\'s own out-of-tree link is refused under A\'s ledger').toBe(true);
      await tick();
      expect(currentLedger()).toBe(ledgerA);
    }));

    const contextB = withActiveLedger(ledgerB, () => ledgerB.run('check-b', async () => {
      await tick();
      expect(currentLedger()).toBe(ledgerB);
      await fs.readFile(path.join(rootB, 'one.txt'), 'utf-8');
      await tick();
      let refused = false;
      try {
        await fs.readFile(path.join(rootB, 'link.txt'), 'utf-8');
      } catch {
        refused = true;
      }
      expect(refused, 'B\'s own out-of-tree link is refused under B\'s ledger').toBe(true);
      await tick();
      expect(currentLedger()).toBe(ledgerB);
    }));

    await Promise.all([contextA, contextB]);

    // Each withhold was decided by — and recorded on — the ledger of its own
    // scan: A's link resolved against A's root, never against B's.
    expect(ledgerA.withheldLinks.map((w) => ({ rel: w.rel, resolved: w.resolved }))).toEqual([
      { rel: 'link.txt', resolved: path.join(outsideA, 'secret.txt') },
    ]);
    expect(ledgerB.withheldLinks.map((w) => ({ rel: w.rel, resolved: w.resolved }))).toEqual([
      { rel: 'link.txt', resolved: path.join(outsideB, 'secret.txt') },
    ]);
    expect(ledgerA.filesExamined).toBe(1);
    expect(ledgerB.filesExamined).toBe(1);
    expect(currentLedger()).toBeNull();
  });
});
