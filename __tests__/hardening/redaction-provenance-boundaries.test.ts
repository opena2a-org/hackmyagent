/**
 * Per-boundary injection proofs — [CHIEF-CISO] 2026-08-21 condition (ii):
 * every publish boundary's provenance read is proven by runtime injection
 * through the REAL channel builder, never by grep. A grep guard is satisfied
 * by dead code; an injection is not.
 *
 * Each case sends a laundered finding (emitted, then stripped of the two
 * redaction fields — the exact shape any named-field rebuild produces)
 * through one importable builder and asserts `RedactionProvenanceError`.
 * Each builder also gets a healthy-pass control so the throw cases cannot be
 * satisfied by a builder that always throws.
 *
 * NOT provable here (recorded, not hidden): the SARIF/HTML/ASP/benchmark
 * generators and the two `secure-json` / `benchmark-composite-json` inline
 * asserts live inside `cli.ts`, which exports nothing and cannot be imported
 * without executing the CLI. Their reads are the same `assertRedactionProvenance`
 * proven here and in the reader's own suite; their WIRING is exercised by the
 * healthy zero-fire e2e runs (corpus smoke + walkthrough) and pinned by the
 * stringify tripwire below.
 */
import { describe, it, expect } from 'vitest';
import {
  emitFinding,
  RedactionProvenanceError,
} from '../../src/hardening/finding-emit';
import type { SecurityFinding, SecurityFindingDraft } from '../../src/hardening/security-check';
import { buildJsonStdoutDocument } from '../../src/output/json-stdout';
import { buildPublishPayload } from '../../src/registry/publish';
import { buildScanReport, buildCommunityReport } from '../../src/registry/client';
import { toASSF } from '../../src/output/asff';
import { buildScanToolText, buildDeepScanLayer1 } from '../../src/mcp-server';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

function emitted(over: Record<string, unknown> = {}): SecurityFinding {
  return emitFinding({
    checkId: 'TEST-BOUNDARY-001',
    name: 'boundary test finding',
    description: 'exercises a publish boundary',
    category: 'credentials',
    severity: 'high',
    passed: false,
    message: 'boundary test message',
    fixable: false,
    ...over,
  } as unknown as SecurityFindingDraft);
}

/** The launder every named-field rebuild produces. */
function laundered(): SecurityFinding {
  const { redactionStatus: _s, redactedShapes: _h, ...rest } = emitted() as SecurityFinding &
    Record<string, unknown>;
  return rest as unknown as SecurityFinding;
}

describe('per-boundary injection: each real builder throws on a laundered finding', () => {
  it('json-stdout chokepoint (buildJsonStdoutDocument)', () => {
    expect(() => buildJsonStdoutDocument({ findings: [laundered()] }, '0.0.0-test')).toThrow(
      RedactionProvenanceError,
    );
    const doc = buildJsonStdoutDocument({ findings: [emitted()] }, '0.0.0-test');
    expect(JSON.parse(doc).hackmyagentVersion, 'healthy control must still stamp').toBe('0.0.0-test');
  });

  it('registry publish payload (buildPublishPayload)', () => {
    expect(() =>
      buildPublishPayload({ packageName: 'x', hardeningFindings: [laundered()] } as never, '0.0.0'),
    ).toThrow(RedactionProvenanceError);
    expect(() =>
      buildPublishPayload({ packageName: 'x', hardeningFindings: [emitted()] } as never, '0.0.0'),
    ).not.toThrow();
  });

  it('registry scan report (buildScanReport)', () => {
    expect(() => buildScanReport('v1', [laundered()])).toThrow(RedactionProvenanceError);
    expect(() => buildScanReport('v1', [emitted()])).not.toThrow();
  });

  it('registry community report (buildCommunityReport)', () => {
    expect(() => buildCommunityReport('pkg', [laundered()])).toThrow(RedactionProvenanceError);
    expect(() => buildCommunityReport('pkg', [emitted()])).not.toThrow();
  });

  it('ASFF output (toASSF)', () => {
    expect(() => toASSF([laundered()])).toThrow(RedactionProvenanceError);
    expect(() => toASSF([emitted()])).not.toThrow();
  });

  it('MCP scan text (buildScanToolText)', () => {
    expect(() =>
      buildScanToolText({ score: 50, maxScore: 100, findings: [laundered()] }),
    ).toThrow(RedactionProvenanceError);
    expect(() =>
      buildScanToolText({ score: 50, maxScore: 100, findings: [emitted()] }),
    ).not.toThrow();
  });

  it('MCP deep-scan payload (buildDeepScanLayer1)', () => {
    expect(() => buildDeepScanLayer1([laundered()])).toThrow(RedactionProvenanceError);
    expect(() => buildDeepScanLayer1([emitted()])).not.toThrow();
  });
});

describe('cli.ts JSON-serialization tripwire', () => {
  // [CHIEF-CA] D2: a new `JSON.stringify` site in cli.ts is a potential new
  // publish channel that silently misses the boundary read. This pin is
  // BLUNT on purpose — it forces the author of a new site to classify it
  // (route through writeJsonStdout, add an assert, or record why neither),
  // then update the count. It does not prove coverage; the injections above
  // and the healthy e2e runs do that for the known set.
  // HMA-08 added two, both classified here rather than routed: `mark-stub`
  // serializes its PATCH body twice — once into the request and once into the
  // `--dry-run` preview, which must print the SAME bytes to be worth reading.
  // Neither carries a `SecurityFinding`: the body is `{status, reason?,
  // evidence?}` where `evidence` is four measured scalars, so the
  // publish-boundary read has nothing to cover on either. The `--json`
  // envelope, which is the finding-adjacent channel, does go through
  // `writeJsonStdout`.
  it('the number of JSON.stringify sites in cli.ts is accounted for', () => {
    const cli = readFileSync(join(__dirname, '..', '..', 'src', 'cli.ts'), 'utf8');
    const count = (cli.match(/JSON\.stringify\(/g) ?? []).length;
    expect(
      count,
      'cli.ts gained or lost a JSON.stringify site — classify it against the publish-boundary read (unit 2) before updating this pin',
    ).toBe(20);
  });
});
