import { describe, it, expect } from 'vitest';
import {
  enforceSeverityFloor,
  validateEnhancement,
  requireBenignConsensus,
  redactSecretsForNanoMind,
  assertASTIntegrity,
  SecurityError,
  verifyTrainingProvenance,
  logSecurityEvent,
  getAuditEvents,
} from '../../src/nanomind-core/security/defense-in-depth';
import type { SecurityAST } from '../../src/nanomind-core/types';

describe('Defense-in-Depth: NanoMind Security', () => {

  describe('Rule 1: NanoMind can UPGRADE but NEVER SUPPRESS', () => {
    it('allows upgrading severity', () => {
      expect(enforceSeverityFloor('medium', 'critical')).toBe('critical');
      expect(enforceSeverityFloor('low', 'high')).toBe('high');
    });

    it('blocks downgrading severity', () => {
      expect(enforceSeverityFloor('high', 'low')).toBe('high');
      expect(enforceSeverityFloor('critical', 'info')).toBe('critical');
    });

    it('maintains severity when equal', () => {
      expect(enforceSeverityFloor('high', 'high')).toBe('high');
    });

    it('blocks NanoMind from passing a static failure', () => {
      expect(validateEnhancement(false, true)).toBe(false); // BLOCKED
    });

    it('allows NanoMind to fail a static pass', () => {
      expect(validateEnhancement(true, false)).toBe(true); // OK - upgrade
    });
  });

  describe('Rule 3: Two-System Agreement for Benign', () => {
    it('overrules NanoMind benign when static findings exist', () => {
      const result = requireBenignConsensus('benign', 3);
      expect(result.finalClassification).toBe('suspicious');
      expect(result.consensusReached).toBe(false);
    });

    it('trusts NanoMind malicious classification (can only upgrade)', () => {
      const result = requireBenignConsensus('malicious', 0);
      expect(result.finalClassification).toBe('malicious');
      expect(result.consensusReached).toBe(true);
    });

    it('overrules NanoMind benign when simulation says malicious', () => {
      const result = requireBenignConsensus('benign', 0, 'MALICIOUS');
      expect(result.finalClassification).toBe('malicious');
    });

    it('reaches consensus when all agree benign', () => {
      const result = requireBenignConsensus('benign', 0, 'CLEAN');
      expect(result.finalClassification).toBe('benign');
      expect(result.consensusReached).toBe(true);
    });

    it('stays suspicious without consensus', () => {
      const result = requireBenignConsensus('suspicious', 1);
      expect(result.finalClassification).toBe('suspicious');
    });
  });

  describe('Rule 4: NanoMind Never Sees Secrets', () => {
    it('redacts Anthropic API keys', () => {
      const input = 'key: ' + ['sk', '-ant-api03-abc123def456ghi789jkl012mno345pqr678'].join('');
      const redacted = redactSecretsForNanoMind(input);
      expect(redacted).not.toContain('sk-ant-api03');
      expect(redacted).toContain('[REDACTED_ANTHROPIC_KEY]');
    });

    it('redacts OpenAI API keys', () => {
      const input = 'OPENAI_API_KEY=' + ['sk', '-proj-abcdefghijklmnopqrstuvwx'].join('');
      const redacted = redactSecretsForNanoMind(input);
      expect(redacted).not.toContain('sk-proj-');
      expect(redacted).toContain('[REDACTED_OPENAI_KEY]');
    });

    it('redacts AWS keys', () => {
      const input = 'aws_key = ' + ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
      const redacted = redactSecretsForNanoMind(input);
      expect(redacted).not.toContain('AKIA');
      expect(redacted).toContain('[REDACTED_AWS_KEY]');
    });

    it('redacts GitHub tokens', () => {
      const input = 'token: ' + ['ghp', '_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'].join('');
      const redacted = redactSecretsForNanoMind(input);
      expect(redacted).not.toContain('ghp_');
    });

    it('redacts private keys', () => {
      const input = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----';
      const redacted = redactSecretsForNanoMind(input);
      expect(redacted).not.toContain('MIIEowIBAAKCAQEA');
      expect(redacted).toContain('[REDACTED_PRIVATE_KEY]');
    });

    it('redacts connection strings', () => {
      const input = 'DATABASE_URL=postgres://user:password123@host:5432/db';
      const redacted = redactSecretsForNanoMind(input);
      expect(redacted).not.toContain('password123');
      expect(redacted).toContain('[REDACTED_CONNECTION_STRING]');
    });

    it('preserves non-secret content', () => {
      const input = 'This skill helps users track fitness goals.';
      const redacted = redactSecretsForNanoMind(input);
      expect(redacted).toBe(input);
    });
  });

  describe('Rule 6: AST Integrity Verification', () => {
    it('throws on unsigned AST', () => {
      const ast = { signature: '' } as SecurityAST;
      expect(() => assertASTIntegrity(ast, () => true)).toThrow(SecurityError);
    });

    it('throws on missing content hash', () => {
      const ast = { signature: 'abc', contentHash: '' } as SecurityAST;
      expect(() => assertASTIntegrity(ast, () => true)).toThrow(SecurityError);
    });

    it('throws on failed verification', () => {
      const ast = { signature: 'abc', contentHash: 'def' } as SecurityAST;
      expect(() => assertASTIntegrity(ast, () => false)).toThrow(SecurityError);
      expect(() => assertASTIntegrity(ast, () => false)).toThrow('tampered');
    });

    it('passes valid AST', () => {
      const ast = { signature: 'valid', contentHash: 'valid' } as SecurityAST;
      expect(() => assertASTIntegrity(ast, () => true)).not.toThrow();
    });
  });

  describe('Rule 7: Training Data Provenance', () => {
    it('rejects samples without content hash', () => {
      expect(verifyTrainingProvenance({
        contentHash: '',
        source: 'hma_payload',
        labeledBy: 'heuristic',
        confidence: 0.8,
        createdAt: new Date().toISOString(),
        claudeReviewed: false,
        signature: 'sig',
      })).toBe(false);
    });

    it('rejects external samples not reviewed by Claude', () => {
      expect(verifyTrainingProvenance({
        contentHash: 'abc123',
        source: 'registry_scan',
        labeledBy: 'heuristic',
        confidence: 0.8,
        createdAt: new Date().toISOString(),
        claudeReviewed: false, // NOT reviewed
        signature: 'sig',
      })).toBe(false);
    });

    it('accepts Claude-reviewed external samples', () => {
      expect(verifyTrainingProvenance({
        contentHash: 'abc123',
        source: 'registry_scan',
        labeledBy: 'claude_review',
        confidence: 0.9,
        createdAt: new Date().toISOString(),
        claudeReviewed: true,
        signature: 'sig',
      })).toBe(true);
    });

    it('accepts internal samples without Claude review', () => {
      expect(verifyTrainingProvenance({
        contentHash: 'abc123',
        source: 'hma_payload',
        labeledBy: 'heuristic',
        confidence: 0.8,
        createdAt: new Date().toISOString(),
        claudeReviewed: false,
        signature: 'sig',
      })).toBe(true);
    });

    it('rejects invalid confidence', () => {
      expect(verifyTrainingProvenance({
        contentHash: 'abc123',
        source: 'dvaa',
        labeledBy: 'human',
        confidence: 1.5, // invalid
        createdAt: new Date().toISOString(),
        claudeReviewed: false,
        signature: 'sig',
      })).toBe(false);
    });
  });

  describe('Audit Logging', () => {
    it('logs security events', () => {
      logSecurityEvent({
        event: 'suppression_blocked',
        details: 'NanoMind attempted to suppress static finding CRED-001',
        severity: 'critical',
      });

      const events = getAuditEvents();
      expect(events.length).toBeGreaterThan(0);
      const last = events[events.length - 1];
      expect(last.event).toBe('suppression_blocked');
      expect(last.severity).toBe('critical');
    });
  });
});
