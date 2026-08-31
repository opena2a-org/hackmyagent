/**
 * HMA-15.AC2 — the PRODUCER masks an un-redactable value at the point of
 * production, and `redactionStatus` reports what was actually removed.
 *
 * The measured defect family, in two generations:
 *
 *   - r0 (shipped 0.32.0): a fixed-width slice reached the boundary with the
 *     name anchor or the value tail cut off, no shape rule matched, nothing
 *     was removed — and the leak was stamped `applied` or `clean`.
 *   - r1 (REJECTED by CISO, 2026-08-31, ledgered): a `details.credentialMatch`
 *     field carried the raw whole-line window and trusted `emitFinding` to
 *     remove it. For any shape the redactor's table does not cover — the
 *     table documents `jwt` and `entropy-blob` as deliberate omissions — it
 *     removed nothing, and the COMPLETE value shipped stamped clean
 *     (123-of-123). A control whose safety depends on the completeness of a
 *     table is only as good as that table. The field is DELETED, not capped
 *     or filtered, and this suite pins the deletion.
 *
 * The r2 mechanism under test: the credential analyzer's located arm emits
 * the canonical scan's masked classification (the value never entered the
 * record), its fallback arm masks every credential-format value out of a
 * whole-line evidence window BEFORE any slice (`maskCredentialValue` scheme:
 * vendor prefix preserved, unknown shape masked entirely), and the FACT of
 * each removal rides to `emitFinding` through its prior-status absorption —
 * so `applied` reports a removal that happened, and `clean` appears only
 * beside fields that carry no credential bytes.
 *
 * These tests run the real pipeline (`runNanoMindScan`) over trees minted
 * into an OS temp directory — every fixture planting one boundary-COVERED
 * control and one boundary-UNCOVERED value (HMA-15.AC5 r2) — and measure
 * leaks the AC4 way: against a same-run null-control floor, never a constant.
 */

import { describe, it, expect } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import type { SecurityFinding } from '../../src/hardening/security-check';
import {
  type CellArtifactType,
  buildFixture,
  longestSharedRun,
  mintNullControl,
  walkStringLeaves,
} from '../helpers/hma15-render-harness';

const CREDENTIAL_CLASS = /cred/i;

/**
 * The bridge types its merged output as drafts, but every finding on it has
 * crossed `emitFinding`; the status is read structurally, exactly the way
 * `emitFinding` itself reads priors off a draft.
 */
function statusOf(f: unknown): SecurityFinding['redactionStatus'] | undefined {
  return (f as Partial<SecurityFinding>).redactionStatus;
}

async function scanFixture(artifactType: CellArtifactType) {
  const fixture = buildFixture(artifactType);
  const dir = mkdtempSync(join(tmpdir(), 'hma15-status-'));
  writeFileSync(join(dir, fixture.fileName), fixture.content, 'utf8');
  const result = await runNanoMindScan(dir, []);
  return { dir, fixture, findings: result.mergedFindings };
}

function isCredentialClass(f: { category?: string; attackClass?: string }): boolean {
  return (
    (typeof f.attackClass === 'string' && CREDENTIAL_CLASS.test(f.attackClass)) ||
    (typeof f.category === 'string' && CREDENTIAL_CLASS.test(f.category))
  );
}

/** Longest run of any planted value in one finding's string leaves. */
function worstPlantedLeaf(
  finding: unknown,
  plantedValues: readonly string[],
): { run: number; path: string } {
  let run = 0;
  let path = '';
  walkStringLeaves(JSON.parse(JSON.stringify(finding)), (leafPath, leaf) => {
    const r = longestSharedRun(plantedValues, leaf);
    if (r > run) {
      run = r;
      path = leafPath;
    }
  });
  return { run, path };
}

describe('HMA-15.AC2 redactionStatus honesty', () => {
  it('HMA-15.AC2 the markdown fallback arm masks at production and stamps the removal applied', async () => {
    const { dir, fixture, findings } = await scanFixture('unknown');
    try {
      const credential = findings.filter((f) => !f.passed && isCredentialClass(f));
      expect(
        credential.length,
        'no credential-class finding on the markdown fixture — nothing below measures anything',
      ).toBeGreaterThan(0);

      // The producer removed material (the covered anchor's value out of the
      // evidence window), and the stamp records that removal — applied, not a
      // `clean` re-derived from fields the material is no longer in.
      const applied = credential.filter((f) => statusOf(f) === 'applied');
      expect(
        applied.length,
        `a removal happened at production but no credential finding stamps applied; saw ` +
          credential.map((f) => String(statusOf(f))).join(' '),
      ).toBeGreaterThan(0);

      // The masking is VISIBLE, not a lucky miss — the mask family, not one
      // spelling: producer masking leaves an asterisk run (vendor prefix
      // preserved, unknown shape fully masked), the span constructor's
      // boundary pass leaves a `[REDACTED…]` marker. Either proves bytes were
      // replaced in the shipped field.
      const visible = applied.some((f) => {
        const evidence = (f.details as Record<string, unknown> | undefined)?.evidence;
        return typeof evidence === 'string' && /\*{8,}|\[REDACTED/.test(evidence);
      });
      expect(visible, 'no applied finding shows a mask family in its evidence').toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('HMA-15.AC2 the r1 raw carry is DELETED: no finding ships a details.credentialMatch', async () => {
    for (const artifactType of ['unknown', 'source_code'] as const) {
      const { dir, findings } = await scanFixture(artifactType);
      try {
        for (const f of findings) {
          const details = f.details as Record<string, unknown> | undefined;
          expect(
            details !== undefined && 'credentialMatch' in details,
            `${artifactType}: finding ${f.checkId} still carries details.credentialMatch — ` +
              'the rejected r1 mechanism (a raw carry for a downstream table to clean up)',
          ).toBe(false);
        }
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
  });

  it('HMA-15.AC2 no emitted finding carries covered OR uncovered planted bytes above the measured floor', async () => {
    // The uncovered value is the r2 point: the report boundary provably does
    // not remove it (AC5 r2 predicate, asserted in the property run), so if
    // it is absent from every finding leaf, the PRODUCER removed it.
    for (const artifactType of ['unknown', 'agent_config'] as const) {
      const { dir, fixture, findings } = await scanFixture(artifactType);
      try {
        const plantedValues = fixture.planted.map((p) => p.value);
        const serialized = JSON.stringify(findings);
        const floor = longestSharedRun(mintNullControl(fixture.planted), serialized);
        const { run, path } = worstPlantedLeaf(findings, plantedValues);
        expect(
          run,
          `${artifactType}: finding leaf ${path} carries a planted run of ${run} (floor ${floor})`,
        ).toBeLessThanOrEqual(floor);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
  });

  it('HMA-15.AC2 clean appears only beside fields proven to carry no credential bytes', async () => {
    const { dir, fixture, findings } = await scanFixture('unknown');
    try {
      const plantedValues = fixture.planted.map((p) => p.value);
      const serialized = JSON.stringify(findings);
      const floor = longestSharedRun(mintNullControl(fixture.planted), serialized);
      const cleanFindings = findings.filter((f) => statusOf(f) === 'clean');
      for (const f of cleanFindings) {
        const { run, path } = worstPlantedLeaf(f, plantedValues);
        expect(
          run,
          `finding ${f.checkId} stamped clean while ${path} carries a run of ${run} (floor ${floor})`,
        ).toBeLessThanOrEqual(floor);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('HMA-15.AC2 the source-code located arm reports the canonical mask as applied', async () => {
    const { dir, findings } = await scanFixture('source_code');
    try {
      const credential = findings.filter((f) => !f.passed && isCredentialClass(f));
      expect(credential.length, 'no credential-class finding on config.py').toBeGreaterThan(0);
      // The canonical scan emitted `<label>: [REDACTED]` in place of the
      // value — production-time removal — and the located arm carries that
      // fact, so the stamp is applied, never a clean derived from fields the
      // value was never in.
      const applied = credential.filter(
        (f) =>
          statusOf(f) === 'applied' &&
          typeof (f.details as Record<string, unknown> | undefined)?.evidence === 'string' &&
          /\[REDACTED/.test(String((f.details as Record<string, unknown>).evidence)),
      );
      expect(
        applied.length,
        'the located arm must stamp applied beside its masked classification',
      ).toBeGreaterThan(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
