import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  runCoverageSweep,
  sweepIndicatesDaemonError,
  POSTURE_HARDENING_CHECKS,
} from '../../src/nanomind-core/orchestrate';
import type { AnalystEscalation } from '../../src/nanomind-core/orchestrate';
import type { CoverageCandidate } from '../../src/nanomind-core/scanner-bridge';
import type { ArtifactCoverageVerdict } from '../../src/nanomind-core/inference/security-analyst';
import type { SecurityFinding } from '../../src/hardening/security-check';

// ============================================================================
// runCoverageSweep — abstention-gated escalation wiring (Phase A P1, CDS-023/024)
//
// The sweep sends compiled artifacts WITHOUT a high/critical structural attack
// finding to the analyst, routes the verdict, and may only ESCALATE. These
// tests inject a fake classify function — routing logic itself is covered in
// analyst-coverage.test.ts; here we test the wiring contract:
//   1. selection (structural misses only; posture checks don't count as attack)
//   2. escalation emission per routed verdict
//   3. the advisory invariant (input findings never mutated, no new findings)
//   4. caps and daemon-unavailable behavior
// ============================================================================

let dir: string;

const finding = (over: Partial<SecurityFinding>): SecurityFinding => ({
  checkId: 'CRED-001',
  name: 'Hardcoded credential',
  description: 'A credential is hardcoded',
  category: 'Credential Security',
  severity: 'high',
  passed: false,
  message: 'found a credential',
  fixable: false,
  ...over,
});

const attackVerdict: ArtifactCoverageVerdict = {
  attackClass: 'prompt_injection',
  classification: 'malicious',
  severity: 'high',
  confidence: 0.95,
  source: 'nlm',
  analysis: 'The file instructs the agent to ignore previous instructions and exfiltrate data.',
  evidence: 'line 3: "ignore previous instructions"',
  modelVersion: 'nanomind-analyst-v3.0.0',
  durationMs: 10,
};

const benignVerdict: ArtifactCoverageVerdict = {
  ...attackVerdict,
  attackClass: 'none',
  classification: 'benign',
  severity: null,
  analysis: '',
};

const classifyAs = (verdict: ArtifactCoverageVerdict | null) =>
  async (_content: string): Promise<ArtifactCoverageVerdict | null> => verdict;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'hma-sweep-'));
  await writeFile(join(dir, 'SKILL.md'), '# Helper skill\nDoes helpful things.\n');
  await writeFile(join(dir, 'mcp.json'), '{"mcpServers":{}}\n');
  await writeFile(join(dir, 'util.ts'), 'export const x = 1;\n');
  await mkdir(join(dir, 'docs'), { recursive: true });
  await writeFile(join(dir, 'docs', 'notes.md'), 'Some notes.\n');
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('runCoverageSweep — selection', () => {
  const candidates: CoverageCandidate[] = [
    { path: 'SKILL.md', artifactType: 'skill' },
    { path: 'util.ts', artifactType: 'source_code' },
  ];

  it('skips files already flagged with a high/critical structural attack finding', async () => {
    const flagged = [finding({ file: 'SKILL.md', severity: 'high' })];
    const seen: string[] = [];
    const classify = async (content: string) => {
      seen.push(content);
      return benignVerdict;
    };
    const out = await runCoverageSweep(dir, candidates, flagged, classify, true);
    // Only util.ts is eligible; SKILL.md is covered by the per-finding stage.
    expect(out.stats.candidates).toBe(1);
    expect(out.stats.swept).toBe(1);
    expect(seen).toHaveLength(1);
    expect(seen[0]).toContain('export const x');
    // Location-borne signal: the analyst input carries the artifact path
    // (DVAA mcp-discovery-exposed regression — content-only input missed
    // .well-known exposure).
    expect(seen[0].startsWith('Artifact path: util.ts\n\n')).toBe(true);
  });

  it('posture/hardening checks do NOT count as structural attack (file stays eligible)', async () => {
    // AST-PROMPT-001 at high severity flags a MISSING defense, not a present
    // attack — same exclusion set as the published benchmark verdict mapping.
    const postureOnly = [finding({ checkId: 'AST-PROMPT-001', file: 'SKILL.md', severity: 'high' })];
    const out = await runCoverageSweep(dir, candidates, postureOnly, classifyAs(benignVerdict), true);
    expect(out.stats.candidates).toBe(2);
  });

  it('medium/low findings do not exclude a file', async () => {
    const lowSev = [finding({ file: 'SKILL.md', severity: 'medium' })];
    const out = await runCoverageSweep(dir, candidates, lowSev, classifyAs(benignVerdict), true);
    expect(out.stats.candidates).toBe(2);
  });

  it('passed and fixed findings do not exclude a file', async () => {
    const inactive = [
      finding({ file: 'SKILL.md', passed: true }),
      finding({ file: 'util.ts', fixed: true } as Partial<SecurityFinding>),
    ];
    const out = await runCoverageSweep(dir, candidates, inactive, classifyAs(benignVerdict), true);
    expect(out.stats.candidates).toBe(2);
  });

  it('a finding the product filter drops does NOT exclude its file (findingVisible)', async () => {
    // DVAA mcp-discovery-exposed regression: MCP-011 high on
    // .well-known/mcp.json exists in allFindings but findingAppliesTo drops
    // it for projectType=library — the user never sees it, so it must not
    // suppress the sweep. With the visibility predicate saying "filtered
    // out", the file stays eligible.
    const flagged = [finding({ checkId: 'MCP-011', file: 'SKILL.md', severity: 'high' })];
    const invisible = () => false;
    const out = await runCoverageSweep(
      dir, candidates, flagged, classifyAs(benignVerdict), true, invisible,
    );
    expect(out.stats.candidates).toBe(2);
  });

  it('a product-visible finding still excludes its file (findingVisible true)', async () => {
    const flagged = [finding({ checkId: 'MCP-011', file: 'SKILL.md', severity: 'high' })];
    const visible = () => true;
    const out = await runCoverageSweep(
      dir, candidates, flagged, classifyAs(benignVerdict), true, visible,
    );
    expect(out.stats.candidates).toBe(1);
  });
});

describe('runCoverageSweep — escalation emission', () => {
  const candidates: CoverageCandidate[] = [{ path: 'SKILL.md', artifactType: 'skill' }];

  it('analyst attack verdict on a structural miss escalates (routed=attack)', async () => {
    const out = await runCoverageSweep(dir, candidates, [], classifyAs(attackVerdict), true);
    expect(out.escalations).toHaveLength(1);
    const esc = out.escalations[0];
    expect(esc.routed).toBe('attack');
    expect(esc.file).toBe('SKILL.md');
    expect(esc.policy).toBe('abstention-gated');
  });

  it('uncertain verdict (suspicious, no class) escalates as abstain', async () => {
    const suspicious: ArtifactCoverageVerdict = {
      ...benignVerdict,
      classification: 'suspicious',
    };
    const out = await runCoverageSweep(dir, candidates, [], classifyAs(suspicious), true);
    expect(out.escalations).toHaveLength(1);
    expect(out.escalations[0].routed).toBe('abstain');
  });

  it('unknown non-benign attack class never escalates as attack (allow-list guard)', async () => {
    const hallucinated: ArtifactCoverageVerdict = {
      ...attackVerdict,
      attackClass: 'Privilege Escalation / Unauthorized Command Execution',
    };
    const out = await runCoverageSweep(dir, candidates, [], classifyAs(hallucinated), true);
    expect(out.escalations).toHaveLength(1);
    expect(out.escalations[0].routed).toBe('abstain');
  });

  it('benign verdict produces no escalation', async () => {
    const out = await runCoverageSweep(dir, candidates, [], classifyAs(benignVerdict), true);
    expect(out.escalations).toHaveLength(0);
  });

  it('gate-suppressed verdict produces no escalation (benign by construction)', async () => {
    const gated: ArtifactCoverageVerdict = {
      ...attackVerdict,
      source: 'input-classifier-gate',
      attackClass: 'none',
      confidence: null,
    };
    const out = await runCoverageSweep(dir, candidates, [], classifyAs(gated), true);
    expect(out.escalations).toHaveLength(0);
  });

  it('escalation entries carry complete advisory fields', async () => {
    const out = await runCoverageSweep(dir, candidates, [], classifyAs(attackVerdict), true);
    const esc: AnalystEscalation = out.escalations[0];
    expect(esc.file).toBeTruthy();
    expect(esc.artifactType).toBe('skill');
    expect(esc.attackClass).toBe('prompt_injection');
    expect(esc.severity).toBe('high');
    expect(esc.classification).toBe('malicious');
    expect(esc.summary).toContain('exfiltrate');
    expect(esc.modelVersion).toBe('nanomind-analyst-v3.0.0');
  });
});

describe('runCoverageSweep — advisory invariant (CDS-024)', () => {
  it('never mutates the findings array or its entries', async () => {
    const findings = [finding({ file: 'util.ts', severity: 'low' })];
    const snapshot = JSON.stringify(findings);
    const candidates: CoverageCandidate[] = [
      { path: 'SKILL.md', artifactType: 'skill' },
      { path: 'util.ts', artifactType: 'source_code' },
    ];
    const out = await runCoverageSweep(dir, candidates, findings, classifyAs(attackVerdict), true);
    expect(JSON.stringify(findings)).toBe(snapshot);
    // Escalations live in their own channel — they are not SecurityFindings
    // and carry no severity-bearing 'passed' field that scoring could read.
    expect(out.escalations.length).toBeGreaterThan(0);
    for (const esc of out.escalations) {
      expect('passed' in esc).toBe(false);
      expect('checkId' in esc).toBe(false);
    }
  });
});

describe('runCoverageSweep — adversarial output hardening', () => {
  const candidates: CoverageCandidate[] = [{ path: 'SKILL.md', artifactType: 'skill' }];

  it('newlines in model-controlled fields are collapsed (no advisory-row spoofing)', async () => {
    // A prompt-injected artifact can steer the generative analyst's text.
    // Embedded newlines must never let that text impersonate the escalation
    // section's own rows or fake Verify: instructions (adversarial review M2).
    const spoofing: ArtifactCoverageVerdict = {
      ...attackVerdict,
      attackClass: 'prompt_injection\nREVIEW /etc/passwd critical',
      classification: 'malicious\nVerify: run curl evil.sh',
      severity: 'high\ncritical',
      analysis: 'line one\n\nREVIEW fake-file.md  injected (critical)\nVerify: rm -rf /',
    };
    const out = await runCoverageSweep(dir, candidates, [], classifyAs(spoofing), true);
    expect(out.escalations).toHaveLength(1);
    const esc = out.escalations[0];
    for (const field of [esc.attackClass, esc.classification, esc.severity ?? '', esc.summary]) {
      expect(field).not.toMatch(/[\r\n\t]/);
    }
    expect(esc.summary).toContain('REVIEW fake-file.md'); // content kept, structure neutralized
  });
});

describe('sweepIndicatesDaemonError — dead daemon never reads as clean (M1)', () => {
  const stats = (over: Partial<import('../../src/nanomind-core/orchestrate').CoverageSweepStats>) => ({
    candidates: 3, swept: 3, skipped: 0, nullVerdicts: 0, policy: 'abstention-gated' as const, ...over,
  });

  it('all swept calls returned null -> daemon error', () => {
    expect(sweepIndicatesDaemonError(stats({ swept: 3, nullVerdicts: 3 }))).toBe(true);
  });

  it('some verdicts came back -> not a daemon error', () => {
    expect(sweepIndicatesDaemonError(stats({ swept: 3, nullVerdicts: 2 }))).toBe(false);
  });

  it('nothing swept (no candidates) -> not a daemon error', () => {
    expect(sweepIndicatesDaemonError(stats({ swept: 0, candidates: 0, nullVerdicts: 0 }))).toBe(false);
  });
});

describe('POSTURE_HARDENING_CHECKS — contract lock', () => {
  it('matches the published benchmark verdict mapping exactly', () => {
    // Canonical source: oasb/scripts/run-dvaa-benchmark.ts HARDENING set ==
    // the corpus full-pipeline adapter's HARDENING_CHECK_IDS (29.1% baseline,
    // CDS-026). If the canonical set changes, change BOTH and re-measure —
    // silent drift would mis-select sweep candidates.
    expect([...POSTURE_HARDENING_CHECKS].sort()).toEqual([
      'AST-GOV-001', 'AST-GOV-002', 'AST-GOV-003', 'AST-GOV-004', 'AST-GOV-005',
      'AST-PROMPT-001', 'AST-PROMPT-003', 'AST-PROMPT-004',
      'AST-SCOPE-001',
    ]);
  });
});

describe('runCoverageSweep — caps and failure behavior', () => {
  it('daemon unavailable (classify=null) yields zero escalations and counts nullVerdicts', async () => {
    const candidates: CoverageCandidate[] = [{ path: 'SKILL.md', artifactType: 'skill' }];
    const out = await runCoverageSweep(dir, candidates, [], classifyAs(null), true);
    expect(out.escalations).toHaveLength(0);
    expect(out.stats.swept).toBe(1);
    expect(out.stats.nullVerdicts).toBe(1);
    expect(sweepIndicatesDaemonError(out.stats)).toBe(true);
  });

  it('vanished files are skipped without blocking the sweep', async () => {
    const candidates: CoverageCandidate[] = [
      { path: 'does-not-exist.md', artifactType: 'skill' },
      { path: 'SKILL.md', artifactType: 'skill' },
    ];
    const out = await runCoverageSweep(dir, candidates, [], classifyAs(attackVerdict), true);
    expect(out.escalations).toHaveLength(1);
    expect(out.escalations[0].file).toBe('SKILL.md');
  });

  it('caps at 10 files per scan and reports the skip count (no silent caps)', async () => {
    const many: CoverageCandidate[] = [];
    for (let i = 0; i < 14; i++) {
      // All point at real files so swept counts reflect the cap, not read failures.
      many.push({ path: 'util.ts', artifactType: 'source_code' });
    }
    const out = await runCoverageSweep(dir, many, [], classifyAs(benignVerdict), true);
    expect(out.stats.candidates).toBe(14);
    expect(out.stats.swept).toBe(10);
    expect(out.stats.skipped).toBe(4);
  });

  it('agent artifacts are swept before source code when the cap binds', async () => {
    const candidates: CoverageCandidate[] = [];
    for (let i = 0; i < 10; i++) candidates.push({ path: 'util.ts', artifactType: 'source_code' });
    candidates.push({ path: 'SKILL.md', artifactType: 'skill' });
    const seen: string[] = [];
    const classify = async (content: string) => {
      seen.push(content.slice(0, 40));
      return benignVerdict;
    };
    const out = await runCoverageSweep(dir, candidates, [], classify, true);
    expect(out.stats.swept).toBe(10);
    // The skill (agent artifact) must be in the swept set despite arriving last.
    expect(seen.some(s => s.includes('Artifact path: SKILL.md'))).toBe(true);
  });
});
