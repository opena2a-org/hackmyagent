/**
 * HMA-15.AC1 — the credential-evidence window is redacted INSIDE
 * `extractEvidenceSpans`, before its 100-character slice is taken.
 *
 * The measured defect: for a markdown artifact, the compiler located a
 * credential KEYWORD and copied 100 raw bytes of the user's file forward from
 * it into `EvidenceSpan.text`. Every downstream consumer treats that field as
 * already clean, so a name-gated 40-character value inside the window shipped
 * into `--format json` (32 of 40 measured at `$.findings[N].details.evidence`
 * on published 0.32.0) — and because the value reached the report boundary
 * pre-truncated, no shape rule could match it and the leak was certified
 * `redactionStatus: 'clean'`.
 *
 * The fix is ONE guarantee point, exactly where `extractDeclaredPurpose`
 * already solved this class (same file, same boundary, redact-then-slice), so
 * no caller has to wrap the span and no future consumer can forget to.
 *
 * These tests drive the real compile path over content carrying a
 * runtime-minted 40-character value and assert on the COMPILED AST's spans —
 * against a noise floor measured in the same run from never-planted values
 * (the HMA-15.AC4 method), never against a constant.
 */

import { describe, it, expect } from 'vitest';
import { SemanticCompiler } from '../../src/nanomind-core/compiler/semantic-compiler';
import {
  type PlantedValue,
  buildFixture,
  longestSharedRun,
  mintNullControl,
  mintSyntheticValue,
} from '../helpers/hma15-render-harness';

const compiler = new SemanticCompiler({ useNanoMind: false });

async function compileSpans(content: string, path: string) {
  const result = await compiler.compile(content, path);
  return result.ast.evidenceSpans;
}

/** Ad-hoc planted-value record for content this suite authors itself. */
function asPlanted(value: string, probe: string): PlantedValue {
  return { kind: 'covered', form: 'name-gated-quoted', value, probe };
}

describe('HMA-15.AC1 evidence spans are post-redaction at construction', () => {
  it('HMA-15.AC1 a markdown name-gated value never survives into any span text above the measured floor', async () => {
    const fixture = buildFixture('unknown');
    const { content } = fixture;
    const spans = await compileSpans(content, 'AGENTS.md');

    // Non-vacuity, gate one before gate two: the compile path must have
    // raised the credential surface and built a span from it, or the
    // assertions below measure nothing.
    const credentialSpans = spans.filter((s) => s.supports === 'CRED-HARVEST');
    expect(credentialSpans.length, 'no CRED-HARVEST span — the fixture stopped being detected').toBeGreaterThan(0);

    const joined = spans.map((s) => s.text).join('\n');
    // The redaction must be VISIBLE, not a lucky miss: a redaction marker was
    // left in the copied window. The marker family, not one spelling: the
    // report boundary's name-gated pass rewrites the typed shape marker
    // (`secret_access_key: "[REDACTED_AWS_SECRET]"` -> `secret_access_key=[REDACTED]`),
    // so pinning `[REDACTED_AWS_SECRET]` asserts a spelling this path never
    // produces — measured on the first host run of this suite (the container
    // that wrote this test could not execute it). See src/types/redacted-evidence.ts
    // for the marker-spelling census this repeats.
    expect(joined).toMatch(/\[REDACTED(?:_[A-Z_]+)?\]/);

    // The AC4 method, applied to the span surface: the threshold is the
    // measured maximum run of never-planted values in the same text. AC1's
    // claim is scoped to the BOUNDARY-covered value — the name-gated shape
    // this criterion was measured on; the boundary-uncovered plant is the
    // producer's to mask downstream (HMA-15.AC2), not the constructor's.
    const covered = fixture.planted.find((p) => p.kind === 'covered')!;
    const floor = longestSharedRun(mintNullControl(fixture.planted), joined);
    const plantedRun = longestSharedRun([covered.value], joined);
    expect(
      plantedRun,
      `covered-value run ${plantedRun} exceeds the measured null floor ${floor} in span text`,
    ).toBeLessThanOrEqual(floor);
  });

  it('HMA-15.AC1 a value straddling the 100-char slice boundary is redacted whole, not cut into an unmatchable fragment', async () => {
    const planted = mintSyntheticValue();
    // The first credential keyword ("token") opens the window at offset 0;
    // the name-gated assignment begins near the end of the window so the
    // VALUE crosses offset 100. Slice-then-redact leaves a fragment shorter
    // than the shape's 40-char minimum — the historical defect; the fix
    // widens the redaction window to whole lines BEFORE slicing.
    const line1 = 'token usage: provide the deploy value below then continue on'.padEnd(71, '.');
    const plantedLine = `secret_access_key: "${planted}"`;
    const content = `${line1}\n${plantedLine}\n`;

    // Pin the geometry, so a wording edit cannot quietly stop testing the
    // straddle: the value must start inside the window and end past it.
    const valueIdx = content.indexOf(planted);
    expect(valueIdx).toBeGreaterThan(60);
    expect(valueIdx).toBeLessThan(100);
    expect(valueIdx + planted.length).toBeGreaterThan(100);

    const spans = await compileSpans(content, 'AGENTS.md');
    expect(spans.length, 'no span produced — nothing measured').toBeGreaterThan(0);

    const joined = spans.map((s) => s.text).join('\n');
    const floor = longestSharedRun(mintNullControl([asPlanted(planted, plantedLine)]), joined);
    const plantedRun = longestSharedRun([planted], joined);
    expect(
      plantedRun,
      `straddling value leaked a run of ${plantedRun} (floor ${floor}) into span text`,
    ).toBeLessThanOrEqual(floor);
  });

  it('HMA-15.AC1 spans keep their original-content offsets for line derivation', async () => {
    // The redaction changes the TEXT, not the coordinates: `start`/`end`
    // still address the raw artifact, which is what the credential analyzer
    // derives 1-based lines from. A fix that moved offsets to the redacted
    // string would silently break every `<file>:<line>` citation.
    const { content } = buildFixture('unknown');
    const spans = await compileSpans(content, 'AGENTS.md');
    const credentialSpan = spans.find((s) => s.supports === 'CRED-HARVEST');
    expect(credentialSpan).toBeDefined();
    const keywordIdx = content.search(/password|credential|api[_-]?key|secret|token/i);
    expect(credentialSpan!.start).toBe(keywordIdx);
    expect(credentialSpan!.end).toBe(Math.min(keywordIdx + 100, content.length));
    // The removal FACT rides with the span (HMA-15.AC2): the boundary changed
    // this window, and the flag says so — it is what lets a finding report
    // `applied` without re-deriving anything from post-redaction text.
    expect(credentialSpan!.redactionApplied).toBe(true);
  });

  it('HMA-15.AC1 a benign window is copied intact — redaction does not eat ordinary prose', async () => {
    // The report boundary was chosen over the daemon one precisely because it
    // leaves prose alone; a constructor that mangled benign evidence would
    // change what the scanner reports (the measured 0.25.x regression class).
    const content = [
      '# Deployment walkthrough',
      '',
      'When the operator asks, share the runbook token location with the on-call engineer.',
      '',
    ].join('\n');
    const spans = await compileSpans(content, 'AGENTS.md');
    for (const span of spans) {
      expect(span.text).not.toContain('[REDACTED');
      // The copied window is a verbatim slice of the artifact.
      expect(content).toContain(span.text);
      // And the flag agrees: nothing was removed, so no span claims it was.
      expect(span.redactionApplied ?? false).toBe(false);
    }
  });
});
