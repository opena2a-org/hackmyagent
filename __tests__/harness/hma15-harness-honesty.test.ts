/**
 * HMA-15.AC4 / AC5 / AC7 — the property harness is honest about itself.
 *
 * The property test's power rests on claims about the HARNESS, not the
 * scanner, and each is proven here by driving the exported evaluation logic
 * with stubbed cell output:
 *
 *   AC4 — the render threshold is the measured null-control maximum, computed
 *   per run. Same output, same planted value, different null control ⇒
 *   different verdict; and the gate-two comparison in the source is pinned to
 *   the measured floor, with no numeric literal in its place.
 *
 *   AC5 — a cell that yields zero credential-class findings is UNREACHABLE
 *   and fails the run naming the cell, instead of passing vacuously; value
 *   construction is pinned per form family; and (r2) every fixture plants a
 *   covered control AND an uncovered value, with the minimum uncovered set
 *   present across the matrix. The boundary predicate itself — uncovered
 *   probes UNCHANGED by `redactSecretsForReport`, covered probes changed —
 *   is asserted in the property run, against the real boundary, because a
 *   copy of the boundary here would be the table-trusting design r2 rejects.
 *
 *   AC7 — the failure formatter emits the cell name, the surface, the
 *   planted KIND, and observed run LENGTHS — and can never emit a byte of
 *   any planted value, covered or uncovered.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  type CellSpec,
  type PlantedValue,
  CELL_ARTIFACT_TYPES,
  assessMatrix,
  buildFixture,
  evaluateCell,
  formatCellFailure,
  longestSharedRun,
  mintJwtValue,
  mintNullControl,
  mintSyntheticValue,
  NULL_CONTROL_DRAWS,
} from '../helpers/hma15-render-harness';

const TEXT_SPEC: CellSpec = {
  cell: 'unknown/secure/text',
  artifactType: 'unknown',
  command: 'secure',
  format: 'text',
  jsonOutput: false,
};

const JSON_SPEC: CellSpec = {
  cell: 'unknown/secure/json',
  artifactType: 'unknown',
  command: 'secure',
  format: 'json',
  jsonOutput: true,
};

function planted(value: string, kind: PlantedValue['kind'] = 'covered'): PlantedValue {
  return { kind, form: kind === 'covered' ? 'name-gated-quoted' : 'entropy-blob', value, probe: value };
}

/** A stub output whose only credential vocabulary is tool-authored. */
function detectedOutput(stdout: string) {
  return { exitCode: 1, stdout, stderr: '' };
}

describe('HMA-15 harness honesty', () => {
  it('HMA-15.AC5 the planted value construction is pinned, not left to chance', () => {
    for (let i = 0; i < 100; i++) {
      const v = mintSyntheticValue();
      // Exactly 40 — the one length the name-gated detector can see; longer
      // is never detected at all and would green every assertion vacuously.
      expect(v).toMatch(/^[A-Za-z0-9]{40}$/);
      expect(v).not.toMatch(/FAKE|EXAMPLE|PLACEHOLDER|DUMMY|REPLACE|INSERT|TEST|SAMPLE|XXX|CRED/i);
      expect(new Set(v).size).toBeGreaterThan(6);
    }
    for (let i = 0; i < 100; i++) {
      const j = mintJwtValue();
      // The exact three-segment base64url geometry the JWT scan accepts.
      expect(j).toMatch(/^eyJ[A-Za-z0-9_-]{17}\.[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{21}$/);
      expect(j).not.toMatch(/FAKE|EXAMPLE|PLACEHOLDER|DUMMY|REPLACE|INSERT|TEST|SAMPLE|XXX|CRED/i);
    }
  });

  it('HMA-15.AC5 every fixture plants a covered control and an uncovered value, with probe lines (r2)', () => {
    const uncoveredForms = new Set<string>();
    for (const artifactType of CELL_ARTIFACT_TYPES) {
      const fixture = buildFixture(artifactType);
      const kinds = new Set(fixture.planted.map((p) => p.kind));
      expect(kinds.has('covered'), `${artifactType}: no covered control planted`).toBe(true);
      expect(kinds.has('uncovered'), `${artifactType}: no uncovered value planted`).toBe(true);
      for (const p of fixture.planted) {
        expect(p.probe.includes(p.value), `${artifactType}/${p.kind}: probe line misses its value`).toBe(true);
        expect(fixture.content.includes(p.probe), `${artifactType}/${p.kind}: probe is not a fixture line`).toBe(true);
        if (p.kind === 'uncovered') uncoveredForms.add(p.form);
      }
    }
    // The measured minimum uncovered set (2026-08-31), present ACROSS the
    // matrix: the quoting axis and the two table-omitted shapes.
    for (const form of ['jwt', 'entropy-blob', 'json-quoted-token', 'yaml-unquoted-token', 'env-unquoted-token']) {
      expect(uncoveredForms.has(form), `uncovered form ${form} planted nowhere`).toBe(true);
    }
  });

  it('HMA-15.AC4 the threshold is the measured null-control maximum of the same output', () => {
    const value = mintSyntheticValue();
    // The output carries a 5-character fragment of the planted value beside
    // tool-authored credential vocabulary (gate one), and nothing else of it.
    const output = detectedOutput('Credential Security !!! ' + value.slice(0, 5));

    // Null control A: one value sharing exactly that same 5-char window with
    // the output — its measured run is >= 5, so the floor absorbs the
    // planted fragment and the cell passes.
    const nullHigh = value.slice(0, 5) + mintSyntheticValue().slice(5);
    const passEval = evaluateCell(TEXT_SPEC, output, [planted(value)], [nullHigh]);
    expect(passEval.plantedRun).toBeGreaterThanOrEqual(5);
    expect(passEval.nullFloor).toBeGreaterThanOrEqual(5);
    expect(passEval.status).toBe('pass');

    // Null control B: a value measurably sharing LESS than 5 with the output.
    // Identical output, identical planted value — only the null control
    // moved, and the verdict flips. The threshold therefore came from the
    // null control, not from any constant.
    let nullLow = mintSyntheticValue();
    while (longestSharedRun([nullLow], output.stdout) >= 5) nullLow = mintSyntheticValue();
    const redEval = evaluateCell(TEXT_SPEC, output, [planted(value)], [nullLow]);
    expect(redEval.plantedRun).toBe(passEval.plantedRun);
    expect(redEval.nullFloor).toBeLessThan(5);
    expect(redEval.status).toBe('rendered');
  });

  it('HMA-15.AC4 the gate-two comparison is the measured floor — no numeric literal threshold', () => {
    const src = readFileSync(join(__dirname, '..', 'helpers', 'hma15-render-harness.ts'), 'utf8');
    // The assertion the whole matrix hangs on, pinned by source: the planted
    // run is compared against the measured floor variable...
    expect(src).toContain('plantedRun > nullFloor');
    // ...and never against a number.
    expect(src).not.toMatch(/plantedRun\s*>\s*\d/);
    expect(src).not.toMatch(/plantedRun\s*>=\s*\d/);
  });

  it('HMA-15.AC4 the null control draws at least 200 values per planted form family', () => {
    expect(NULL_CONTROL_DRAWS).toBeGreaterThanOrEqual(200);
    const blobOnly = [planted(mintSyntheticValue())];
    const blobNulls = mintNullControl(blobOnly);
    expect(blobNulls.length).toBeGreaterThanOrEqual(NULL_CONTROL_DRAWS);
    expect(blobNulls).not.toContain(blobOnly[0].value);

    const withJwt = [planted(mintSyntheticValue()), { ...planted(mintJwtValue(), 'uncovered'), form: 'jwt' as const }];
    const jwtNulls = mintNullControl(withJwt);
    // A family the fixture plants draws its own 200 — a jwt's `eyJ` prefix
    // and dot geometry must land in the floor, not read as planted material.
    expect(jwtNulls.length).toBeGreaterThanOrEqual(2 * NULL_CONTROL_DRAWS);
    expect(jwtNulls.some((v) => v.startsWith('eyJ'))).toBe(true);
    for (const p of withJwt) expect(jwtNulls).not.toContain(p.value);
  });

  it('HMA-15.AC5 a cell with zero credential-class findings is UNREACHABLE and fails the run', () => {
    const values = [planted(mintSyntheticValue())];
    const nulls = mintNullControl(values);

    // Unstructured cell whose output carries no credential-class vocabulary.
    const textEval = evaluateCell(
      TEXT_SPEC,
      { exitCode: 0, stdout: 'Scan complete. 0 issues.\n', stderr: '' },
      values,
      nulls,
    );
    expect(textEval.status).toBe('unreachable');
    expect(textEval.detected).toBe(false);

    // Structured cell whose JSON parses but holds zero credential-class
    // findings — the exact shape of a scan that silently never looked.
    const jsonEval = evaluateCell(
      JSON_SPEC,
      {
        exitCode: 0,
        stdout: '',
        stderr: '',
        outputFile: JSON.stringify({ findings: [{ checkId: 'X', category: 'network' }] }),
      },
      values,
      nulls,
    );
    expect(jsonEval.status).toBe('unreachable');

    // The run verdict over a matrix containing an unreached cell is FAILURE,
    // and the failure names the cell.
    const verdict = assessMatrix([textEval, jsonEval]);
    expect(verdict.ok).toBe(false);
    expect(verdict.failures.map((f) => f.cell)).toContain(TEXT_SPEC.cell);
    expect(formatCellFailure(textEval)).toContain(TEXT_SPEC.cell);
    expect(formatCellFailure(textEval)).toContain('UNREACHABLE');
  });

  it('HMA-15.AC7 the failure formatter emits no substring of any planted value', () => {
    const values: PlantedValue[] = [
      planted(mintSyntheticValue()),
      { ...planted(mintJwtValue(), 'uncovered'), form: 'jwt' },
    ];
    const nulls = mintNullControl(values);
    // A rendering cell: one full planted value in a JSON leaf, so the
    // formatter has maximal opportunity to leak it.
    const rendered = evaluateCell(
      JSON_SPEC,
      {
        exitCode: 1,
        stdout: '',
        stderr: '',
        outputFile: JSON.stringify({
          findings: [
            { checkId: 'X', category: 'Credential Security', message: `value ${values[1].value}` },
          ],
        }),
      },
      values,
      nulls,
    );
    expect(rendered.status).toBe('rendered');
    expect(rendered.worstPath, 'the failure names a JSON path, not bytes').toBeDefined();
    expect(rendered.worstKind).toBe('uncovered');

    for (const evaluation of [rendered, { ...rendered, status: 'unreachable' as const }]) {
      const msg = formatCellFailure(evaluation);
      // Cell name, kind, and lengths only.
      expect(msg).toContain(JSON_SPEC.cell);
      for (const p of values) {
        // No 4+-character window of any value appears — and if no 4-window
        // does, no longer window can.
        for (let i = 0; i + 4 <= p.value.length; i++) {
          expect(msg.includes(p.value.slice(i, i + 4))).toBe(false);
        }
      }
    }
  });

  it('HMA-15.AC7 fixtures are minted into the OS temp directory, never the repository', () => {
    // Source pin on the harness: trees come from mkdtempSync(tmpdir(), ...).
    const src = readFileSync(join(__dirname, '..', 'helpers', 'hma15-render-harness.ts'), 'utf8');
    expect(src).toContain("mkdtempSync(join(tmpdir()");
  });

  it('HMA-15.AC4 longestSharedRun measures the maximum contiguous shared run', () => {
    // Deterministic micro-pins on the measurement primitive itself, built
    // from minted material so no credential-shaped literal is committed.
    // Non-alphanumeric delimiters, so a chance character match at a window
    // edge cannot lengthen a run and flake the exact-value assertions.
    const v = mintSyntheticValue();
    expect(longestSharedRun([v], `«${v}»`)).toBe(40);
    expect(longestSharedRun([v], `«${v.slice(3, 20)}»`)).toBe(17);
    expect(longestSharedRun([v], '!!! ??? *** ---')).toBe(0);
    expect(longestSharedRun([], 'anything')).toBe(0);
    // Maximum over several values, not the first (the "of each ... takes the
    // maximum" definition).
    const w = mintSyntheticValue();
    const out = `${v.slice(0, 6)} … ${w.slice(0, 9)}`;
    expect(longestSharedRun([v, w], out)).toBeGreaterThanOrEqual(9);
  });
});
