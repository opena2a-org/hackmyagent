/**
 * HMA-38 — a header-less private-key body line must never become the
 * declared purpose.
 *
 * `extractDeclaredPurpose` used to split content into lines FIRST, skip the
 * armor header via its '-' comment rule, and hand the first line longer than
 * 20 characters to `redactSecretsForReport` — one line at a time. Every rule
 * in CREDENTIAL_REDACTION_RULES is anchored to a vendor prefix, a name, an
 * armor header or a scheme, and the report boundary's name-gated rule needs
 * an identifier and quotes. A bare 64-character base64 body line carries none
 * of those anchors, so the per-line call was a no-op and the line — for an
 * Ed25519 PKCS#8 key, the entire 32-byte seed — flowed verbatim into
 * `declaredPurpose` and from there into every consumer that interpolates it.
 *
 * The key below is MINTED in-process with node:crypto and never written
 * anywhere. No committed line in this file carries an armor header literal:
 * the PEM (header, body, footer) comes out of the export call at runtime.
 */

import { generateKeyPairSync } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import { SemanticCompiler } from '../../src/nanomind-core/compiler/semantic-compiler';
import { analyzeScope } from '../../src/nanomind-core/analyzers/scope-analyzer';
import { analyzeCapabilities } from '../../src/nanomind-core/analyzers/capability-analyzer';
import type { ASTFinding } from '../../src/nanomind-core/analyzers/capability-analyzer';
import { enrichFindings } from '../../src/nanomind-core/fix-generator';
import { mergeFindings } from '../../src/nanomind-core/scanner-bridge';
import type { SecurityFinding } from '../../src/hardening/security-check';
import type { Capability } from '../../src/nanomind-core/types';

// ---------------------------------------------------------------------------
// The minted key. PKCS#8 PEM for Ed25519 is a fixed-shape document: one
// 64-character base64 body line whose DER bytes 16-47 are the raw seed.
// ---------------------------------------------------------------------------

const { privateKey } = generateKeyPairSync('ed25519');
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
const der = privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
const seedBase64 = der.subarray(16, 48).toString('base64');

const pemLines = pem.trimEnd().split('\n');
const bodyLines = pemLines.map(l => l.trim()).filter(l => l.length > 0 && !l.startsWith('-'));

/** Every 12-character window of `value`. Any longer leaked substring
 * necessarily contains one of these, so 12-windows are the whole check. */
function windowsOf(value: string, len = 12): string[] {
  const out: string[] = [];
  for (let i = 0; i + len <= value.length; i++) out.push(value.slice(i, i + len));
  return out;
}

function expectNoKeyWindows(text: string): void {
  for (const line of bodyLines) {
    for (const w of windowsOf(line)) {
      expect(text).not.toContain(w);
    }
  }
}

// ---------------------------------------------------------------------------
// The three artifact shapes. In each, the first line longer than 20 chars
// that survives the extractor's skip list IS the key body line: every line
// before the key is 20 characters or shorter (length-skipped), the heading
// and fence lines are short, and the armor header is skipped by the '-' rule.
// ---------------------------------------------------------------------------

const indent = (l: string) => '  ' + l;
const fence = '```';

/** (a) YAML block scalar. 'service: deploy' is 15 chars, 'private_key: |' is 14. */
const yamlArtifact = ['service: deploy', 'private_key: |', ...pemLines.map(indent), ''].join('\n');

/** (b) Markdown skill, no frontmatter description. '# Deploy' is 8 chars. */
const skillArtifact = ['# Deploy', '', fence, ...pemLines, fence, ''].join('\n');

/** (c) Agent file carrying the bare armored block. '# Agent' is 7 chars. */
const agentsArtifact = ['# Agent', '', ...pemLines, ''].join('\n');

/** Shape (a) with a qualifying prose line first, for the analyzer branches
 * that require a multi-word purpose. The key below it is still the minted
 * PEM, so purpose construction still removes key material. */
const prosePurposeLine = 'purpose: deploy analytics reporting pipelines';
const proseYamlArtifact = [prosePurposeLine, 'private_key: |', ...pemLines.map(indent), ''].join('\n');

const compiler = new SemanticCompiler({ useNanoMind: false });

async function compileAst(content: string, name: string) {
  return (await compiler.compile(content, name)).ast;
}

/** A declared capability with no keyword overlap with any purpose above,
 * so AST-SCOPE-001 / AST-SCOPE-003 fire when the purpose has enough words. */
const trojanCap: Capability = {
  name: 'exfil.transmit',
  scope: 'external endpoints',
  declared: true,
  inferred: true,
  riskLevel: 'critical',
  evidence: 'exfil.transmit',
};

function draftFinding(attackClass: string, checkId: string): ASTFinding {
  return {
    checkId,
    name: 'probe finding',
    description: 'probe finding for fix enrichment',
    category: 'test',
    severity: 'high',
    passed: false,
    message: 'probe finding',
    fixable: true,
    file: 'artifact-under-test',
    attackClass,
  };
}

/** Every byte-carrying string an ASTFinding renders to a user. */
function renderedStrings(f: ASTFinding): string[] {
  return [f.name, f.description, f.message, f.fix, f.guidance, f.evidence].filter(
    (s): s is string => typeof s === 'string',
  );
}

describe('HMA-38 declaredPurpose never surfaces an armored key body line', () => {
  it('HMA-38.AC1 the minted PEM has the measured shape: one 64-char base64 body line', () => {
    expect(bodyLines.length).toBeGreaterThanOrEqual(1);
    expect(bodyLines[0]).toHaveLength(64);
    expect(bodyLines[0]).toMatch(/^[A-Za-z0-9+/=]{64}$/);
  });

  const shapes: Array<{ label: string; name: string; content: string }> = [
    { label: 'YAML block scalar', name: 'deploy-config.yaml', content: yamlArtifact },
    { label: 'markdown skill fenced block', name: 'SKILL.md', content: skillArtifact },
    { label: 'bare armored block in agent file', name: 'AGENTS.md', content: agentsArtifact },
  ];

  for (const shape of shapes) {
    it(`HMA-38.AC1 ${shape.label}: declaredPurpose carries no 12-char window of any key body line`, async () => {
      const purpose = (await compileAst(shape.content, shape.name)).declaredPurpose;
      expectNoKeyWindows(purpose);
      // The purpose must be one of the three honest outcomes: a value carrying
      // a redaction marker, the first qualifying non-key prose line (none of
      // these shapes has one), or the fallback.
      expect(purpose.includes('[REDACTED') || purpose === 'Unknown purpose').toBe(true);
    });
  }

  it('HMA-38.AC2 bare key, no prose to fall back to: purpose is the fallback or a marker, never the body or any window of the seed', async () => {
    const purpose = (await compileAst(agentsArtifact, 'AGENTS.md')).declaredPurpose;
    expect(purpose === 'Unknown purpose' || purpose.includes('[REDACTED')).toBe(true);
    for (const line of bodyLines) {
      expect(purpose).not.toBe(line);
    }
    expectNoKeyWindows(purpose);
    // The unit measured the full seed leaking on exactly this shape: DER bytes
    // 16-47 are the raw seed, so no window of its base64 form may survive either.
    for (const w of windowsOf(seedBase64)) {
      expect(purpose).not.toContain(w);
    }
  });

  it('HMA-38.AC3 analyzeScope executes the purpose-interpolating AST-SCOPE-003 branch and renders no key window', async () => {
    const ast = await compileAst(proseYamlArtifact, 'deploy-config.yaml');
    ast.declaredCapabilities.push(trojanCap);
    const findings = analyzeScope(ast, () => true, undefined, proseYamlArtifact);
    const mismatches = findings.filter(f => f.checkId === 'AST-SCOPE-003');
    expect(mismatches.length).toBeGreaterThan(0);
    // The branch really interpolated the purpose into description and message.
    expect(mismatches[0].description).toContain('deploy analytics reporting');
    expect(mismatches[0].message).toContain('deploy analytics');
    for (const f of findings) {
      for (const s of renderedStrings(f)) expectNoKeyWindows(s);
    }
  });

  it('HMA-38.AC3 analyzeCapabilities executes the purpose-interpolating AST-SCOPE-001 branch and renders no key window', async () => {
    const ast = await compileAst(proseYamlArtifact, 'deploy-config.yaml');
    ast.declaredCapabilities.push(trojanCap);
    const findings = analyzeCapabilities(ast, undefined, undefined);
    const mismatches = findings.filter(f => f.checkId === 'AST-SCOPE-001');
    expect(mismatches.length).toBeGreaterThan(0);
    expect(mismatches[0].description).toContain('deploy analytics reporting');
    for (const f of findings) {
      for (const s of renderedStrings(f)) expectNoKeyWindows(s);
    }
  });

  it('HMA-38.AC3 enrichFindings executes every purpose-interpolating fix branch and renders no key window', async () => {
    // Attack classes chosen so generateFix reads ast.declaredPurpose:
    // CRED-EXPOSURE, SKILL-EXFIL (skill artifact), PERSISTENCE, SOUL-MISSING,
    // and SEMANTIC-MISMATCH with no analyzer fix (fixScopeMismatch).
    const purposeBranches = [
      draftFinding('CRED-EXPOSURE', 'PROBE-CRED'),
      draftFinding('SKILL-EXFIL', 'PROBE-EXFIL'),
      draftFinding('PERSISTENCE', 'PROBE-PERSIST'),
      draftFinding('SOUL-MISSING', 'PROBE-SOUL'),
      draftFinding('SEMANTIC-MISMATCH', 'PROBE-SCOPE'),
    ];
    for (const shape of [
      { name: 'deploy-config.yaml', content: yamlArtifact },
      { name: 'SKILL.md', content: skillArtifact },
      { name: 'AGENTS.md', content: agentsArtifact },
      { name: 'deploy-config.yaml', content: proseYamlArtifact },
    ]) {
      const ast = await compileAst(shape.content, shape.name);
      const enriched = enrichFindings(purposeBranches, ast);
      expect(enriched).toHaveLength(purposeBranches.length);
      for (const f of enriched) {
        for (const s of renderedStrings(f)) expectNoKeyWindows(s);
      }
      // The CRED-EXPOSURE branch interpolates the purpose whenever it is
      // truthy — prove the branch ran by finding the purpose (marker or
      // prose) inside the generated fix text.
      const credFix = enriched.find(f => f.checkId === 'PROBE-CRED')?.fix ?? '';
      expect(credFix).toContain('are exposed in version control');
      expect(
        credFix.includes('[REDACTED') || credFix.includes('deploy analytics reporting'),
      ).toBe(true);
    }
  });

  it('HMA-38.AC3 an emitted finding whose construction removed key material reads redactionStatus applied, never clean', async () => {
    // Purpose-interpolating findings from an artifact whose purpose
    // construction removed the minted key. The redacted purpose itself changes
    // nothing under emitFinding's own pass (a marker matches no rule), so
    // without stamped provenance the emitted status would read 'clean' over a
    // removal. The stamp rides the draft; emitFinding's absorbing rule keeps it.
    for (const shape of [
      { name: 'deploy-config.yaml', content: yamlArtifact },
      { name: 'SKILL.md', content: skillArtifact },
      { name: 'AGENTS.md', content: agentsArtifact },
    ]) {
      const ast = await compileAst(shape.content, shape.name);
      const enriched = enrichFindings([draftFinding('CRED-EXPOSURE', 'PROBE-CRED')], ast);
      const emitted = mergeFindings([], enriched) as SecurityFinding[];
      expect(emitted).toHaveLength(1);
      expect(emitted[0].redactionStatus).toBe('applied');
      expect(emitted[0].redactedShapes).toContain('pem-private-key');
    }

    // The analyzer path carries the same provenance end to end.
    const proseAst = await compileAst(proseYamlArtifact, 'deploy-config.yaml');
    proseAst.declaredCapabilities.push(trojanCap);
    const scopeFindings = analyzeScope(proseAst, () => true, undefined, proseYamlArtifact)
      .filter(f => f.checkId === 'AST-SCOPE-003');
    const emittedScope = mergeFindings([], scopeFindings) as SecurityFinding[];
    expect(emittedScope.length).toBeGreaterThan(0);
    expect(emittedScope[0].redactionStatus).toBe('applied');
    expect(emittedScope[0].redactedShapes).toContain('pem-private-key');
  });

  it('HMA-38.AC3 a finding from whose construction nothing was removed honestly stays clean', async () => {
    const cleanAst = await compileAst(
      'summarizes analytics reports for the finance team in detail\n',
      'notes.md',
    );
    expect(cleanAst.declaredPurpose).toContain('summarizes analytics reports');
    const enriched = enrichFindings([draftFinding('CRED-EXPOSURE', 'PROBE-CRED')], cleanAst);
    const emitted = mergeFindings([], enriched) as SecurityFinding[];
    expect(emitted).toHaveLength(1);
    expect(emitted[0].redactionStatus).toBe('clean');
  });
});
