/**
 * HMA-15.AC8 — the Registry negative that made this incident survivable is
 * held by tests rather than by a reading.
 *
 * The incident's blast radius stopped at the local machine because the
 * publish payload carries exactly ONE byte-carrying finding field onto the
 * wire — `description`, mapped to the wire's `message` — and no credential
 * finding builds its description from scanned artifact content. Two
 * assertions keep that true:
 *
 *   1. WIRE SHAPE — `buildPublishPayload` maps findings onto the frozen
 *      `UnifiedFinding` key set. If it ever grows a `details` or `evidence`
 *      field (the two measured local leak paths), or starts carrying
 *      `message` instead of `description`, this goes red at the payload.
 *
 *   2. SOURCE CENSUS — a tripwire over every finding-producing site in
 *      `src/`: a `description:` whose interpolation reaches for a content
 *      window (`.slice(`/`.substring(`, `content`, `evidence`, `summary`,
 *      `span`, `text`, `masked`, `match`, …) must be on the classified
 *      allowlist below, each entry recording why its value is not raw
 *      scanned bytes. A NEW site interpolating artifact content into a
 *      description fails here before it can reach the wire.
 *
 * SCOPE, stated honestly (same contract as the #601 tripwire this mirrors):
 * the census is line-based. A value copied into a local and interpolated on
 * another line, or a multi-line template, evades it. It is a tripwire against
 * the observed failure mode, not a taint analysis; the wire-shape test and
 * the redaction boundary remain the runtime backstops.
 */

import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

import { buildPublishPayload } from '../../src/registry/publish';
import { emitFinding } from '../../src/hardening/finding-emit';
import type { SecurityFinding } from '../../src/hardening/security-check';
import { longestSharedRun, mintNullControl, mintSyntheticValue } from '../helpers/hma15-render-harness';

const REPO_ROOT = join(__dirname, '..', '..');
const SRC = join(REPO_ROOT, 'src');

// ============================================================================
// 1. Wire shape
// ============================================================================

/** The frozen wire key set of `UnifiedFinding` (src/registry/client.ts). */
const WIRE_KEYS = new Set(['checkId', 'name', 'severity', 'passed', 'message', 'category', 'attackClass']);

function hardeningFinding(planted: string): SecurityFinding {
  // Built through the real boundary so it carries redaction provenance —
  // `buildPublishPayload` refuses laundered findings. The planted value rides
  // in `message` and `details.evidence` RAW-SHAPED (bare high-entropy body,
  // no name anchor), the exact form the boundary's shape rules cannot see:
  // if the wire carried either field, the value would ship.
  return emitFinding({
    checkId: 'WIRE-PIN-1',
    name: 'Hardcoded Secret Detected',
    description: 'The artifact contains patterns consistent with hardcoded secrets.',
    category: 'Credential Security',
    severity: 'critical',
    passed: false,
    message: `Hardcoded secret: ${planted}`,
    fixable: false,
    attackClass: 'CRED-HARDCODED',
    details: { source: 'nanomind-ast', evidence: planted, credentialMatch: planted },
  }) as unknown as SecurityFinding;
}

describe('HMA-15.AC8 registry publish payload negative', () => {
  it('HMA-15.AC8 wire findings carry only the frozen key set — never details, never evidence', () => {
    const planted = mintSyntheticValue();
    const payload = buildPublishPayload(
      {
        packageName: 'hma15-wire-pin',
        packageVersion: '0.0.0',
        directory: REPO_ROOT,
        hardeningFindings: [hardeningFinding(planted)],
        attackReport: {
          riskScore: 10,
          riskRating: 'low',
          summary: { total: 1, successful: 0, blocked: 1 },
          results: [
            {
              payload: { id: 'ATK-1', category: 'prompt-injection', severity: 'high' },
              success: false,
            },
          ],
        } as never,
        soulResult: { controls: [{ id: 'SOUL-1', name: 'ctrl', severity: 'medium', passed: true, description: 'authored control description' }] } as never,
      },
      '0.0.0-test',
    );

    expect(payload.findings.length).toBeGreaterThanOrEqual(3);
    for (const finding of payload.findings as unknown as Array<Record<string, unknown>>) {
      const keys = Object.keys(finding);
      const excess = keys.filter((k) => !WIRE_KEYS.has(k));
      expect(excess, `wire finding ${String(finding.checkId)} grew keys: ${excess.join(', ')}`).toEqual([]);
      expect('details' in finding).toBe(false);
      expect('evidence' in finding).toBe(false);
    }
  });

  it('HMA-15.AC8 the hardening arm maps description onto the wire, not message', () => {
    const planted = mintSyntheticValue();
    const source = hardeningFinding(planted);
    const payload = buildPublishPayload(
      {
        packageName: 'hma15-wire-pin',
        directory: REPO_ROOT,
        hardeningFindings: [source],
      },
      '0.0.0-test',
    );
    const wire = (payload.findings as unknown as Array<Record<string, unknown>>).find(
      (f) => f.checkId === 'WIRE-PIN-1',
    );
    expect(wire).toBeDefined();
    expect(wire!.message).toBe(source.description);
  });

  it('HMA-15.AC8 a value planted in message and details never reaches the serialized payload', () => {
    const planted = mintSyntheticValue();
    const payload = buildPublishPayload(
      {
        packageName: 'hma15-wire-pin',
        directory: REPO_ROOT,
        hardeningFindings: [hardeningFinding(planted)],
      },
      '0.0.0-test',
    );
    const serialized = JSON.stringify(payload);
    const floor = longestSharedRun(
      mintNullControl([{ kind: 'covered', form: 'name-gated-quoted', value: planted, probe: planted }]),
      serialized,
    );
    const plantedRun = longestSharedRun([planted], serialized);
    expect(
      plantedRun,
      `planted run ${plantedRun} (floor ${floor}) survived onto the publish wire`,
    ).toBeLessThanOrEqual(floor);
  });

  // ==========================================================================
  // 2. Description census
  // ==========================================================================

  /**
   * Interpolated expressions that reach for scanned-content windows. The
   * word list is the vocabulary of every raw-content carrier in this tree
   * (spans, summaries, evidence, masked previews, regex matches, slices).
   */
  const CONTENT_EXPR = /\.(slice|substring|substr)\s*\(|\b(content|evidence|summary|snippet|span|text|masked|match|raw|body|excerpt|preview|window)\b/i;

  /**
   * Every currently-allowlisted interpolating site, keyed by the trimmed
   * source line, with the reviewed classification of WHY the value is not raw
   * scanned bytes. An EDIT to a listed line re-opens the question — the
   * stale-entry check below fails until the entry is re-justified.
   */
  const AUTHORED_ALLOW: ReadonlyArray<readonly [string, string]> = [
    [
      'description: `Capability "${cap.name}" does not appear related to the declared purpose: "${ast.declaredPurpose.slice(0, 100)}".`,',
      'declaredPurpose is post-redaction at construction (extractDeclaredPurpose redacts before its slice) and crosses emitFinding again',
    ],
    [
      'description: `Constraint bypassed: "${constraint.text.slice(0, 60)}..."`,',
      'constraint prose selected by the extractor, crosses emitFinding; pre-existing truncation precedes the boundary and is tracked outside HMA-15',
    ],
    [
      'description: `"${key}": ${masked}  -- ${type} hardcoded in ${file.path}. Visible to anyone with repo access or who can read the file.`,',
      'masked at construction (maskCredential scheme: prefix + asterisks), never the raw value; crosses emitFinding',
    ],
    [
      'description: `Component "${comp.source}" (${comp.role}) occupies ${Math.round(comp.content.length / totalLength * 100)}% of the assembled prompt. Safety instructions from ${safetyComponents.map(c => c.source).join(\', \') || \'SOUL.md\'} may be displaced from the effective attention window.`,',
      'content.LENGTH is a number, not bytes; sources are file names',
    ],
    [
      'description: `Messaging service (${match[1]}) is pre-allowed in sandbox policy. An attacker who gains code execution inside the sandbox can exfiltrate data via this channel without triggering additional permission prompts.`,',
      'match[1] is a service hostname captured by an allowlist-of-services regex, not free content',
    ],
  ];
  const ALLOW = new Map(AUTHORED_ALLOW);

  function walkSourceFiles(dir: string, out: string[]): void {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walkSourceFiles(full, out);
      } else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts')) {
        out.push(full);
      }
    }
  }

  it('HMA-15.AC8 no finding description interpolates a scanned-content window (census + classified allowlist)', () => {
    const files: string[] = [];
    walkSourceFiles(SRC, files);
    expect(files.length).toBeGreaterThan(100);

    const offenders: string[] = [];
    for (const file of files) {
      const lines = readFileSync(file, 'utf8').split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!/^description:\s/.test(trimmed)) continue;
        const exprs = [...trimmed.matchAll(/\$\{([^}]*)\}/g)].map((m) => m[1]);
        if (exprs.length === 0) continue;
        if (!exprs.some((e) => CONTENT_EXPR.test(e))) continue;
        if (ALLOW.has(trimmed)) continue;
        offenders.push(`${relative(REPO_ROOT, file)}: ${trimmed}`);
      }
    }
    expect(
      offenders,
      'A finding description interpolates a scanned-content expression. description is the ONE ' +
        'byte-carrying field the Registry publish payload carries onto the wire (publish.ts maps ' +
        'description -> wire message), so scanned bytes here are one --publish away from the ' +
        'Registry. Move the bytes to `message`/`details` (local-only, boundary-redacted), or add ' +
        'the trimmed line to AUTHORED_ALLOW with a reviewed classification:\n\n' +
        offenders.join('\n'),
    ).toEqual([]);
  });

  it('HMA-15.AC8 the census allowlist carries no dead entries', () => {
    const files: string[] = [];
    walkSourceFiles(SRC, files);
    const present = new Set<string>();
    for (const file of files) {
      for (const line of readFileSync(file, 'utf8').split('\n')) present.add(line.trim());
    }
    const dead = [...ALLOW.keys()].filter((k) => !present.has(k));
    expect(
      dead,
      'allowlisted description lines no longer exist verbatim (re-justify or delete): ' + dead.join(' | '),
    ).toEqual([]);
  });
});
