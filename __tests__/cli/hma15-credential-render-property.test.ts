/**
 * HMA-15.AC3 — the credential-byte render class, closed across the full
 * matrix and held closed by property rather than by producer.
 *
 * Runtime-minted synthetic values are planted in a fixture of EVERY
 * ArtifactType the classifier can return — one COVERED control the report
 * boundary removes, and one UNCOVERED value it provably does not (HMA-15.AC5
 * r2) — BOTH user-facing commands run over each fixture tree (`secure` in its
 * five non-benchmark output formats: text, json, sarif, html, asff; `check`
 * in its two: default text, `--json`), and every cell asserts that no byte of
 * stdout, no byte of an `-o` output file, and no string leaf of the emitted
 * JSON holds a contiguous run of ANY planted value longer than that cell's
 * own measured noise floor (HMA-15.AC4: at least 200 never-planted values
 * drawn per planted form family, the maximum of their runs in the same output
 * IS the threshold — no literal).
 *
 * THE UNCOVERED PREDICATE IS PROVEN IN THIS RUN (HMA-15.AC5 r2): for every
 * fixture, `redactSecretsForReport` is called on the exact planted lines —
 * the uncovered probe must come back UNCHANGED (the day a shape rule covers
 * that form, this fails and forces a new form: a predicate, not a list) and
 * the covered probe must come back CHANGED with its value gone (the control
 * that a future fix did not delete the boundary). The r1 matrix planted only
 * covered shapes and passed 73/73 on a build rendering a complete credential.
 *
 * Two ordered gates per cell (HMA-15.AC5): the cell must DETECT (produce at
 * least one credential-class finding) before non-render is asserted, and an
 * unreached cell FAILS the run naming itself.
 *
 * THIS SUITE NEVER SKIPS (HMA-15.AC11, CISO Binding Decision 12): a security
 * gate that skips is a failing gate. `release.yml` — the tag-triggered
 * publish workflow — runs `npm test`, and under the r1 `describe.skipIf`
 * guard this matrix executed ZERO cells at the exact moment of publish. A
 * precondition the matrix needs and cannot find (the built CLI) is an ERROR:
 * the first assertion below fails naming the missing artifact, and every cell
 * after it fails rather than skipping.
 *
 * PRODUCER-AGNOSTIC (HMA-15.AC6): the harness imports nothing from `src/`;
 * this file imports exactly ONE src symbol — `redactSecretsForReport`, the
 * redaction boundary the AC5 r2 predicate is required to interrogate in the
 * same run. No semantic-compiler internal, no producer function, no check id.
 * The tool is exercised exclusively through the built CLI at `dist/cli.js`
 * (override with HMA15_CLI to point the SAME unmodified test at another
 * build — the AC10 verifier runs it against the pre-fix baseline and must
 * see this file go red).
 *
 * The run artifact (HMA-15.AC3/AC5/AC9/AC10 evidence) records the exercised
 * CLI's path, its sha256, and the sha256 of the WHOLE dist tree (AC10 r2:
 * cli.js alone hashes identical across the builds this test distinguishes);
 * per fixture, the planted forms and boundary-predicate outcomes; per cell,
 * exit code, detection, the credential-class finding count (the AC9
 * not-narrowed comparison reads these against the same fixtures on the
 * pre-fix baseline), the measured floor, and the planted runs by kind. Its
 * default location is an OS temp dir, printed at the end of the run; QA pins
 * it with HMA15_RUN_ARTIFACT.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, rmSync } from 'node:fs';
import { mkdtempSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { redactSecretsForReport } from '../../src/nanomind-core/security/defense-in-depth';
import {
  CELL_ARTIFACT_TYPES,
  type CellEvaluation,
  type Fixture,
  type FixtureEvidence,
  allCellSpecs,
  assessMatrix,
  evaluateCell,
  formatCellFailure,
  mintNullControl,
  runArtifactPath,
  runCliCell,
  sha256Dir,
  sha256File,
  writeFixtureTree,
  writeRunArtifact,
} from '../helpers/hma15-render-harness';

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = process.env.HMA15_CLI ?? join(REPO_ROOT, 'dist', 'cli.js');
const usingDefaultCli = process.env.HMA15_CLI === undefined;

interface FixtureState {
  treeDir: string;
  fixture: Fixture;
}

const fixtures = new Map<(typeof CELL_ARTIFACT_TYPES)[number], FixtureState>();
const fixtureEvidence: FixtureEvidence[] = [];
const evaluations: CellEvaluation[] = [];
let scratch = '';
const startedAt = new Date().toISOString();

beforeAll(() => {
  // A stale build would measure code that is no longer under test. Only
  // enforced for this tree's own dist — an HMA15_CLI override deliberately
  // points at a DIFFERENT tree's build (the AC10 baseline run). A MISSING
  // dist is not handled here at all: the first test below fails on it,
  // because a missing precondition is an error, never a skip (HMA-15.AC11).
  if (usingDefaultCli) assertDistFreshIfPresent();
  scratch = mkdtempSync(join(tmpdir(), 'hma15-scratch-'));
  for (const artifactType of CELL_ARTIFACT_TYPES) {
    const { treeDir, fixture } = writeFixtureTree(artifactType);
    fixtures.set(artifactType, { treeDir, fixture });
    // The AC5 r2 predicate, against the real boundary, in this run.
    const covered = fixture.planted.filter((p) => p.kind === 'covered');
    const uncovered = fixture.planted.filter((p) => p.kind === 'uncovered');
    const coveredRemoved = covered.every((p) => {
      const out = redactSecretsForReport(p.probe);
      return out !== p.probe && !out.includes(p.value);
    });
    const uncoveredUnchanged = uncovered.every((p) => redactSecretsForReport(p.probe) === p.probe);
    fixtureEvidence.push({
      artifactType,
      plantedForms: fixture.planted.map((p) => ({ kind: p.kind, form: p.form })),
      boundary: { coveredRemoved, uncoveredUnchanged },
    });
  }
});

afterAll(() => {
  const artifactPath = runArtifactPath();
  writeRunArtifact(artifactPath, {
    task: 'HMA-15',
    startedAt,
    finishedAt: new Date().toISOString(),
    cli: {
      path: CLI,
      sha256: existsSync(CLI) ? sha256File(CLI) : 'missing',
      distTreeSha256: existsSync(dirname(CLI)) ? sha256Dir(dirname(CLI)) : 'missing',
    },
    fixtures: fixtureEvidence,
    cells: evaluations,
    verdict: {
      ok: assessMatrix(evaluations).ok,
      failedCells: assessMatrix(evaluations).failures.map((f) => f.cell),
    },
  });
  // Path only — the artifact itself carries kinds, forms, lengths and hashes,
  // never values.
  console.log(`HMA-15 run artifact: ${artifactPath}`);
  for (const { treeDir } of fixtures.values()) {
    rmSync(treeDir, { recursive: true, force: true });
  }
  if (scratch) rmSync(scratch, { recursive: true, force: true });
});

describe('HMA-15.AC3 credential-byte render property matrix', () => {
  it('HMA-15.AC11 the built CLI precondition holds — a miss is this failure, never a skip', () => {
    expect(existsSync(CLI), `built CLI missing at ${CLI} — build before testing; this gate does not skip`).toBe(true);
    expect(sha256File(CLI)).toMatch(/^[0-9a-f]{64}$/);
    // AC10 r2: identity is the whole tree, not one file that never changes.
    expect(sha256Dir(dirname(CLI))).toMatch(/^[0-9a-f]{64}$/);
  });

  it('HMA-15.AC5 every fixture proves its uncovered plant against the boundary, in this run', () => {
    expect(fixtureEvidence.length).toBe(CELL_ARTIFACT_TYPES.length);
    for (const evidence of fixtureEvidence) {
      expect(
        evidence.boundary.uncoveredUnchanged,
        `${evidence.artifactType}: an uncovered probe came back CHANGED from redactSecretsForReport — ` +
          `the boundary now covers this form; the predicate demands a form it does not remove`,
      ).toBe(true);
      expect(
        evidence.boundary.coveredRemoved,
        `${evidence.artifactType}: the covered control was NOT removed by redactSecretsForReport — ` +
          `the boundary this matrix controls for is gone`,
      ).toBe(true);
    }
  });

  it('HMA-15.AC5 the minimum uncovered set is planted across the matrix', () => {
    const uncoveredForms = new Set(
      fixtureEvidence.flatMap((e) => e.plantedForms.filter((p) => p.kind === 'uncovered').map((p) => p.form)),
    );
    for (const form of ['jwt', 'entropy-blob', 'json-quoted-token', 'yaml-unquoted-token', 'env-unquoted-token']) {
      expect(uncoveredForms.has(form as never), `uncovered form ${form} is planted nowhere in the matrix`).toBe(true);
    }
  });

  for (const spec of allCellSpecs()) {
    it(`HMA-15.AC3 ${spec.cell} holds no planted run above its measured floor`, () => {
      const state = fixtures.get(spec.artifactType)!;
      const output = runCliCell(CLI, spec, state.treeDir, scratch);
      const nulls = mintNullControl(state.fixture.planted);
      const evaluation = evaluateCell(spec, output, state.fixture.planted, nulls);
      evaluations.push(evaluation);
      // Both gates, in order, through the harness's own formatter — which is
      // pinned elsewhere to emit no byte of any planted value (HMA-15.AC7).
      expect(evaluation.status, formatCellFailure(evaluation)).toBe('pass');
    });
  }

  it('HMA-15.AC5 every cell of the matrix was reached — none skipped silently', () => {
    // 10 artifact types x (5 secure formats + 2 check formats). A cell that
    // never even ran (crashed before evaluation) must fail the run exactly
    // like an unreached one.
    expect(evaluations.length).toBe(CELL_ARTIFACT_TYPES.length * 7);
    const unreached = evaluations.filter((e) => !e.detected).map((e) => e.cell);
    expect(unreached, `cells with no credential-class finding: ${unreached.join(', ')}`).toEqual([]);
  });

  it('HMA-15.AC9 machine cells record credential-class finding counts for the baseline comparison', () => {
    // The not-narrowed half of AC9 is a two-build comparison the verifier
    // performs against the pre-fix baseline using these recorded counts; the
    // floor asserted here is that every countable cell counted at least one,
    // so the recorded numbers can never satisfy ">= baseline" vacuously.
    const countable = evaluations.filter((e) => e.credentialFindingCount >= 0);
    expect(countable.length).toBeGreaterThan(0);
    for (const e of countable) {
      expect(
        e.credentialFindingCount,
        `${e.cell} recorded no countable credential-class finding`,
      ).toBeGreaterThan(0);
    }
  });
});
