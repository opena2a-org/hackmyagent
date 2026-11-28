/**
 * #505 — each output states the values it measured, the same way in every
 * view: a value nothing produced is `null` / `not measured` / `--`, never a
 * zero, a pass, or a score.
 *
 *   - `secure -b oasb-2`: a governance domain with nothing to grade printed
 *     `0/0  (0%)` where `scan-soul` prints `--`.
 *   - `trust`: the batch and audit tables printed a number for a pending or
 *     failed registry scan that the single-package view calls not scanned.
 *   - `--format asp`: `signedComponents: true` for a tree where SKILL-001 never
 *     ran, `capabilities: 'none'` from a keyword miss, and an `attestation`
 *     key with no signature.
 *   - `secure --json`: no record of why the run exited as it did.
 *   - `wild`: a target with no fetchable page scored `100/100 (strong)`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tempDir } from '../helpers/temp-dir';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { governanceDomainCell } from '../../src/soul/domain-cell';
import { measuredTrustScore, trustScoreCell } from '../../src/ui/trust-score';
import { aspCapabilities, aspSupplyChainFlags, checkOutcome, credentialChecksRan } from '../../src/benchmarks/asp-posture';
import { secureGate } from '../../src/hardening/settled-outcome';
import { computeResilienceScore } from '../../src/wild/scorer';

describe('#505 oasb-2 governance domain cells', () => {
  it('a graded domain prints its count and percentage', () => {
    expect(governanceDomainCell({ passed: 3, total: 5, percentage: 60 }, 'TOOL')).toBe('3/5  (60%)');
  });
  it('a graded domain with nothing passed still prints its zero', () => {
    expect(governanceDomainCell({ passed: 0, total: 4, percentage: 0 }, 'TOOL')).toBe('0/4  (0%)');
  });
  it('a domain the profile skips prints --, as scan-soul does', () => {
    expect(governanceDomainCell({ passed: 0, total: 0, percentage: 0, skippedByProfile: true }, 'TOOL'))
      .toBe('--  (skipped by profile)');
  });
  it('a domain with no control at the tier prints --, as scan-soul does', () => {
    expect(governanceDomainCell({ passed: 0, total: 0, percentage: 0, skippedByTier: true }, 'BASIC'))
      .toBe('--  (not applicable at BASIC tier)');
  });
});

describe('#505 one trust-score rule for every trust view', () => {
  it('a completed scan shows the score on a 0-100 scale, from either scale', () => {
    expect(measuredTrustScore(0.35, 'completed')).toBe(35);
    expect(measuredTrustScore(35, 'completed')).toBe(35);
    expect(trustScoreCell(0.8, 'passed')).toBe('80/100');
    expect(trustScoreCell(0.6, 'warnings')).toBe('60/100');
  });
  it('a pending, failed or absent scan shows no number', () => {
    for (const status of ['pending', 'error', 'failed', 'not_applicable', '', undefined]) {
      expect(measuredTrustScore(0.42, status)).toBeNull();
      expect(trustScoreCell(0.42, status)).toBe('Not scanned');
    }
  });
  it('a completed scan with no numeric score shows no number', () => {
    expect(measuredTrustScore(undefined, 'completed')).toBeNull();
    expect(measuredTrustScore(Number.NaN, 'completed')).toBeNull();
  });
  it('a completed scan that scored zero shows its zero', () => {
    expect(trustScoreCell(0, 'completed')).toBe('0/100');
  });
});

describe('#505 asp sections state what was measured', () => {
  it('a check with no measured record is null, a failure false, a pass true', () => {
    expect(checkOutcome([], 'SKILL-001')).toBeNull();
    expect(checkOutcome([{ checkId: 'DEP-001', notApplicable: { subject: 'x', reason: 'y' } }], 'DEP-001')).toBeNull();
    expect(checkOutcome([{ checkId: 'DEP-001', passed: true }], 'DEP-001')).toBe(true);
    expect(checkOutcome([{ checkId: 'DEP-001', passed: true }, { checkId: 'DEP-001', passed: false }], 'DEP-001')).toBe(false);
  });
  it('a failure in the reported findings stays false; an unrun check is null, not true', () => {
    const flags = aspSupplyChainFlags([{ checkId: 'DEP-001', passed: false }], []);
    expect(flags.pinnedDependencies).toBe(false);
    expect(flags.signedComponents).toBeNull();
    expect(aspSupplyChainFlags([], [{ checkId: 'SKILL-001', passed: true }]).signedComponents).toBe(true);
    expect(aspSupplyChainFlags([], [{ checkId: 'SKILL-001', passed: false }]).signedComponents).toBe(false);
  });
  it('a capability keyword miss is "not detected", a hit is "detected"', () => {
    expect(aspCapabilities([])).toEqual({ filesystem: 'not detected', network: 'not detected', shell: 'not detected' });
    expect(aspCapabilities([{ checkId: 'NET-001', description: '' }, { checkId: 'X-1', description: 'Runs exec()' }]))
      .toEqual({ filesystem: 'not detected', network: 'detected', shell: 'detected' });
  });
  it('credential checks ran only when a CRED-* or SEM-CRED-* record was measured', () => {
    expect(credentialChecksRan([])).toBe(false);
    expect(credentialChecksRan([{ checkId: 'CRED-001', notApplicable: { subject: 'x', reason: 'y' } }])).toBe(false);
    expect(credentialChecksRan([{ checkId: 'CRED-001', passed: true }])).toBe(true);
    expect(credentialChecksRan([{ checkId: 'SEM-CRED-002', passed: false }])).toBe(true);
  });
});

describe('#505 secure --json gate', () => {
  const base = { findings: [], score: 90, coverage: { filesExamined: 3 } } as any;
  it('a clean run: not failed, no reason, no threshold', () => {
    expect(secureGate(base, 0, undefined)).toEqual({
      failed: false, exitCode: 0, reason: null, reasons: [], criticalOrHigh: 0, unreadInputs: 0, failBelow: null,
    });
  });
  it('a high finding sets exit 1 and names it, suppressed or not', () => {
    const r = { ...base, findings: [{ checkId: 'CRED-001', passed: false, severity: 'high', file: 'a' }] };
    const g = secureGate(r, 1, undefined);
    expect(g).toMatchObject({ failed: true, exitCode: 1, reason: 'critical-or-high-findings', criticalOrHigh: 1 });
  });
  it('--fail-below carries the threshold, the score and whether it was breached', () => {
    expect(secureGate(base, 1, 95)).toMatchObject({
      reason: 'below-fail-below', reasons: ['below-fail-below'], failBelow: { threshold: 95, score: 90, breached: true },
    });
    expect(secureGate(base, 0, 50).failBelow).toEqual({ threshold: 50, score: 90, breached: false });
  });
  it('unread inputs outrank a high finding at exit 2', () => {
    const r = {
      ...base,
      findings: [{ checkId: 'CRED-001', passed: false, severity: 'critical', file: 'a' }],
      coverage: { filesExamined: 3, unreadableInputs: { count: 2, codes: { EACCES: 2 }, directories: 0 } },
    };
    const g = secureGate(r, 2, undefined);
    expect(g.reason).toBe('unread-inputs');
    expect(g.reasons).toEqual(['unread-inputs', 'critical-or-high-findings']);
    expect(g.unreadInputs).toBe(2);
  });
});

describe('#505 wild scores nothing when no page was fetched', () => {
  it('the empty set has no score and is not measured', () => {
    const r = computeResilienceScore({ pages: [], fileFetches: [], pagesScanned: 0 });
    expect(r.score).toBeNull();
    expect(r.rating).toBe('not-measured');
  });
});

describe('#505 the outputs, end to end', { timeout: 300_000 }, () => {
  beforeAll(assertDistFreshIfPresent);

  function run(args: string[]) {
    return spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf8',
      timeout: 240_000,
      maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: tempDir('hma-505-home-') },
    });
  }
  function cleanTree(): string {
    const dir = tempDir('hma-505-tree-');
    fs.writeFileSync(path.join(dir, 'package.json'), '{ "name": "fx505", "version": "1.0.0", "private": true }\n');
    return dir;
  }
  function parse(out: string): any {
    return JSON.parse(out.slice(out.indexOf('{'), out.lastIndexOf('}') + 1));
  }

  it('secure --json carries a gate object that agrees with exitCode and the process exit', () => {
    const r = run(['secure', cleanTree(), '--json', '--no-machine-posture', '--fail-below', '0']);
    const j = parse(r.stdout);
    expect(j.gate).toBeTruthy();
    expect(j.gate.exitCode).toBe(j.exitCode);
    expect(j.gate.exitCode).toBe(r.status);
    expect(j.gate.failed).toBe(r.status !== 0);
    expect(j.gate.failBelow).toEqual({ threshold: 0, score: j.score, breached: false });
  });

  it('--format asp does not report an unrun skill-signing check as signed, and says it is unsigned', () => {
    const r = run(['secure', cleanTree(), '-b', 'oasb-1', '--format', 'asp', '--no-machine-posture']);
    const j = parse(r.stdout);
    expect(j.supplyChain.signedComponents).toBeNull();
    expect(Object.values(j.capabilities).every((v) => v === 'detected' || v === 'not detected')).toBe(true);
    expect(j.attestation.signed).toBe(false);
    // The clean tree's credential checks ran, so its zero is a count.
    expect(j.credentials.hardcodedSecrets).toBe(0);
  });

  it('wild against a target with no fetchable page prints no score and exits 2', () => {
    const r = run(['wild', 'http://127.0.0.1:9', '--timeout', '200', '--delay', '0']);
    expect(r.stdout).toMatch(/Wild Resilience Score: not measured/);
    expect(r.stdout).not.toMatch(/100\/100/);
    expect(r.status).toBe(2);
    const j = run(['wild', 'http://127.0.0.1:9', '--timeout', '200', '--delay', '0', '--json']);
    const body = JSON.parse(j.stdout);
    expect(body.wildResilienceScore).toBeNull();
    expect(body.resilienceRating).toBe('not-measured');
    expect(j.status).toBe(2);
  });
});
