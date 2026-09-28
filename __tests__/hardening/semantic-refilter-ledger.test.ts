/**
 * #427 — a finding the semantic merge reintroduces and the CLI's re-filter then
 * drops must still be recorded in `coverage.suppressedFailures`.
 *
 * `refilterAfterSemanticMerge` rebuilds `result.findings` from `allFindings`
 * after `scan()` has returned, so it cannot add to a ledger that was frozen at
 * scanner exit. It does not have to: the semantic pass runs inside the scan,
 * ahead of the ledger (#499), and the re-filter applies the scanner's own
 * reportability predicate. These tests hold both halves, in-process, through
 * the public `semanticPass` hook the CLI itself uses.
 *
 * RED-PROOF: move the `options.semanticPass` block in `scanInner` below the
 * `suppressedFailures` loop, or add a clause to `isReportableFinding` that the
 * scanner's `filteredFindings` filter does not have. Either reopens the gap
 * and the tests below fail.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { refilterAfterSemanticMerge } from '../../src/hardening/semantic-refilter';
import type { ScanResult, SecurityFindingDraft } from '../../src/hardening/security-check';

// `AUTH-` is scoped to webapp and api, so on a library the scanner's scope
// filter and the CLI's re-filter both drop it. It carries a file, so it is a
// real detection hidden by scoping — the only kind the ledger names.
const PLANTED: SecurityFindingDraft = {
  checkId: 'AUTH-427',
  name: 'Planted merge detection',
  description: 'A detection the semantic merge returns for an out-of-scope check.',
  category: 'authentication',
  severity: 'high',
  passed: false,
  message: 'planted by the #427 regression test',
  fixable: false,
  file: 'server.js',
  line: 1,
};

async function scanWithMerge(): Promise<{ dir: string; scanner: HardeningScanner; result: ScanResult }> {
  const dir = await mkdtemp(path.join(tmpdir(), 'hma-427-'));
  await writeFile(path.join(dir, 'package.json'), '{"name":"lib427","version":"1.0.0"}\n');
  await writeFile(path.join(dir, 'server.js'), 'module.exports = () => 1;\n');
  const scanner = new HardeningScanner();
  const result = await scanner.scan({
    targetDir: dir,
    autoFix: false,
    // The merge returns the whole set it was handed plus what it found, the
    // same contract `orchestrateNanoMind` keeps.
    semanticPass: async ({ findings }) => ({ findings: [...findings, { ...PLANTED }] }),
  });
  return { dir, scanner, result };
}

const key = (f: { checkId: string; file?: string; line?: number }) =>
  `${f.checkId}\u0000${f.file ?? ''}\u0000${f.line ?? ''}`;

describe('#427 — the CLI re-filter after the semantic merge is recorded in the ledger', () => {
  it('records a merge-reintroduced finding that the CLI re-filter drops', async () => {
    const { dir, scanner, result } = await scanWithMerge();
    try {
      expect(result.projectType).toBe('library');
      // The merge put it in the channel the CLI re-filters from.
      expect((result.allFindings ?? []).some((f) => f.checkId === PLANTED.checkId)).toBe(true);

      await refilterAfterSemanticMerge(scanner, result, dir);

      expect(result.findings.some((f) => f.checkId === PLANTED.checkId)).toBe(false);
      expect(result.coverage?.suppressedFailures ?? []).toContainEqual({
        checkId: PLANTED.checkId,
        name: PLANTED.name,
        category: PLANTED.category,
        severity: PLANTED.severity,
      });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('every located failure the CLI re-filter drops is in the ledger', async () => {
    const { dir, scanner, result } = await scanWithMerge();
    try {
      const before = [...(result.allFindings ?? [])];
      await refilterAfterSemanticMerge(scanner, result, dir);
      const kept = new Set(result.findings.map(key));
      const ledger = new Set((result.coverage?.suppressedFailures ?? []).map((e) => e.checkId));

      // A failure with a file that the re-filter removed and the user did not
      // suppress. Pathless absences are counted, not named, by design.
      const dropped = before.filter(
        (f) => f.passed === false && Boolean(f.file) && !f.suppressed && !kept.has(key(f)),
      );
      expect(dropped.map((f) => f.checkId)).toContain(PLANTED.checkId);
      for (const f of dropped) {
        expect(ledger.has(f.checkId), `${f.checkId} on ${f.file} dropped without a ledger entry`).toBe(true);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
