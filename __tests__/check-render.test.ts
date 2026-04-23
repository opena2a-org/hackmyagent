/**
 * Unit tests for the pure helpers behind `check` render + --json emission.
 *
 * Closes F1 / F3 test coverage for CA-034 M2 Day-2. The shape assertions
 * are the parity contract consumers (opena2a-parity) rely on; changing
 * them here is a breaking change for the F1 parity fixture.
 */
import { describe, it, expect } from 'vitest';
import {
  buildCheckJsonOutput,
  mapScanStatusForMeter,
  translateNpmPackError,
  type RegistryTrustDataLike,
} from '../src/check-render';
import type { SecurityFinding } from '../src/index';

const EMPTY_FINDINGS: SecurityFinding[] = [];

const MCP_REGISTRY: RegistryTrustDataLike = {
  found: true,
  name: '@modelcontextprotocol/server-filesystem',
  trustScore: 0.824,
  trustLevel: 3,
  verdict: 'passed',
  scanStatus: 'warnings',
  packageType: 'mcp_server',
  lastScannedAt: '2026-03-02T00:00:00Z',
  communityScans: 1,
};

describe('buildCheckJsonOutput (F1)', () => {
  it('emits registry fields at the top level when registry.found === true', () => {
    const out = buildCheckJsonOutput({
      name: '@modelcontextprotocol/server-filesystem',
      type: 'npm-package',
      projectType: 'library',
      score: 100,
      maxScore: 100,
      findings: EMPTY_FINDINGS,
      registry: MCP_REGISTRY,
    });
    expect(out.trustLevel).toBe(3);
    expect(out.trustScore).toBe(0.824);
    expect(out.verdict).toBe('passed');
    expect(out.scanStatus).toBe('warnings');
    expect(out.packageType).toBe('mcp_server');
    expect(out.name).toBe('@modelcontextprotocol/server-filesystem');
    expect(out.source).toBe('local-scan');
    expect(out.score).toBe(100);
  });

  it('omits registry fields when registry is null', () => {
    const out = buildCheckJsonOutput({
      name: 'express',
      type: 'npm-package',
      projectType: 'library',
      score: 100,
      maxScore: 100,
      findings: EMPTY_FINDINGS,
      registry: null,
    });
    expect(out.trustLevel).toBeUndefined();
    expect(out.trustScore).toBeUndefined();
    expect(out.verdict).toBeUndefined();
    expect(out.packageType).toBeUndefined();
  });

  it('omits registry fields when registry.found === false', () => {
    const out = buildCheckJsonOutput({
      name: 'new-package-xyz',
      type: 'npm-package',
      projectType: 'library',
      score: 100,
      maxScore: 100,
      findings: EMPTY_FINDINGS,
      registry: {
        found: false,
        name: 'new-package-xyz',
        trustScore: 0,
        trustLevel: 0,
        verdict: 'unknown',
      },
    });
    expect(out.trustLevel).toBeUndefined();
    expect(out.verdict).toBeUndefined();
  });

  it('preserves the canonical top-level keys for the parity contract', () => {
    const out = buildCheckJsonOutput({
      name: '@modelcontextprotocol/server-filesystem',
      type: 'npm-package',
      projectType: 'library',
      score: 100,
      maxScore: 100,
      findings: EMPTY_FINDINGS,
      registry: MCP_REGISTRY,
    });
    // Parity fixture must_match keys — changing this list is a breaking
    // change for opena2a-parity F1 golden fixtures.
    for (const key of ['trustLevel', 'name', 'verdict', 'packageType', 'scanStatus']) {
      expect(out).toHaveProperty(key);
    }
  });

  it('passes through analyst findings when provided', () => {
    const out = buildCheckJsonOutput({
      name: 'express',
      type: 'npm-package',
      score: 90,
      maxScore: 100,
      findings: EMPTY_FINDINGS,
      registry: null,
      analystFindings: [{ taskType: 'threatAnalysis', result: {} }],
    });
    expect(Array.isArray(out.analystFindings)).toBe(true);
    expect((out.analystFindings as unknown[]).length).toBe(1);
  });

  it('omits analystFindings when empty or absent', () => {
    const out1 = buildCheckJsonOutput({
      name: 'express',
      type: 'npm-package',
      score: 90,
      maxScore: 100,
      findings: EMPTY_FINDINGS,
      registry: null,
      analystFindings: [],
    });
    expect(out1.analystFindings).toBeUndefined();

    const out2 = buildCheckJsonOutput({
      name: 'express',
      type: 'npm-package',
      score: 90,
      maxScore: 100,
      findings: EMPTY_FINDINGS,
      registry: null,
    });
    expect(out2.analystFindings).toBeUndefined();
  });

  it('includes version when provided (PyPI path)', () => {
    const out = buildCheckJsonOutput({
      name: 'requests',
      type: 'pypi-package',
      score: 100,
      maxScore: 100,
      findings: EMPTY_FINDINGS,
      registry: null,
      version: '2.32.0',
    });
    expect(out.version).toBe('2.32.0');
    expect(out.type).toBe('pypi-package');
  });
});

describe('mapScanStatusForMeter (F6 meter gate)', () => {
  it('maps "completed" / "complete" / "passed" to "completed"', () => {
    expect(mapScanStatusForMeter('completed')).toBe('completed');
    expect(mapScanStatusForMeter('complete')).toBe('completed');
    expect(mapScanStatusForMeter('passed')).toBe('completed');
  });

  it('maps "warnings" / "warning" to "warnings"', () => {
    expect(mapScanStatusForMeter('warnings')).toBe('warnings');
    expect(mapScanStatusForMeter('warning')).toBe('warnings');
  });

  it('suppresses the meter for pending / empty / unknown states', () => {
    expect(mapScanStatusForMeter(undefined)).toBeUndefined();
    expect(mapScanStatusForMeter('')).toBeUndefined();
    expect(mapScanStatusForMeter('pending')).toBeUndefined();
    expect(mapScanStatusForMeter('not_applicable')).toBeUndefined();
    expect(mapScanStatusForMeter('mystery')).toBeUndefined();
  });

  it('suppresses the meter on error / failed (F6: no number without measurement)', () => {
    expect(mapScanStatusForMeter('error')).toBeUndefined();
    expect(mapScanStatusForMeter('failed')).toBeUndefined();
  });

  it('handles mixed-case input', () => {
    expect(mapScanStatusForMeter('COMPLETED')).toBe('completed');
    expect(mapScanStatusForMeter('  Warnings  ')).toBe('warnings');
  });
});

describe('translateNpmPackError (F3)', () => {
  it('translates `code 128` on a git-style name to a scoped did-you-mean', () => {
    const translated = translateNpmPackError('anthropic/code-review', 'Command failed with code 128');
    expect(translated).toBeDefined();
    expect(translated?.suggestions).toEqual(['@anthropic/code-review']);
    expect(translated?.errorHint).toContain('@anthropic/code-review');
  });

  it('returns undefined for scoped names (already npm-valid)', () => {
    const translated = translateNpmPackError('@anthropic/code-review', 'Command failed with code 128');
    expect(translated).toBeUndefined();
  });

  it('returns undefined for bare names (no slash)', () => {
    const translated = translateNpmPackError('express', 'Command failed with code 128');
    expect(translated).toBeUndefined();
  });

  it('returns undefined when the error is not code 128', () => {
    const translated = translateNpmPackError('anthropic/code-review', '404 Not Found');
    expect(translated).toBeUndefined();
  });

  it('handles variant `code128` / `code  128` spellings', () => {
    expect(translateNpmPackError('foo/bar', 'code128')).toBeDefined();
    expect(translateNpmPackError('foo/bar', 'error: code  128')).toBeDefined();
  });

  it('rejects names with characters that are not valid npm chars', () => {
    // Disallows spaces, colons, etc. in either segment.
    expect(translateNpmPackError('anthropic/code review', 'code 128')).toBeUndefined();
  });
});
