import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  enforceSeverityFloor,
  validateEnhancement,
  requireBenignConsensus,
  redactSecretsForNanoMind,
  redactSecretsForReport,
  redactSecretsForReportReporting,
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

/**
 * HMA-34 — the `pem-private-key` redaction body is bounded per BLOCK at
 * N = 32768 and refuses to cross another armor header.
 *
 * Nothing below is a committed key. The two real blocks are MINTED in-process
 * by `node:crypto` and never written to disk; every synthetic block is built
 * from the pattern's own alphabet. Armor headers and footers are assembled FROM
 * PARTS on purpose — a whole header line written as one literal is refused by
 * the lander's private-key-block rule, so a committed fixture pair could not
 * land even if one were wanted here.
 */
const ARMOR_BEGIN = '-----BEGIN ';
const ARMOR_END = '-----END ';
const ARMOR_TAIL = ' KEY-----';
const armorHeader = (kind: string): string => ARMOR_BEGIN + kind + ARMOR_TAIL;
const armorFooter = (kind: string): string => ARMOR_END + kind + ARMOR_TAIL;

const PRIVATE_KEY_MARKER = '[REDACTED_PRIVATE_KEY]';

/** The budget the three quadratic shapes must each come in under. */
const BUDGET_MS = 500;

/** Elapsed ms for ONE call, timed around that call and nothing else. */
function msFor(fn: () => unknown): number {
  const t0 = performance.now();
  fn();
  return performance.now() - t0;
}

/** A PKCS#8 PEM, minted here and discarded with the process. */
function mintPkcs8(kind: 'rsa' | 'ec'): string {
  const { privateKey } =
    kind === 'rsa'
      ? generateKeyPairSync('rsa', { modulusLength: 2048 })
      : generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
}

/** Every line prefixed, the trailing newline kept — the YAML-embedded shape. */
function indentBlock(pem: string, width: number): string {
  const pad = ' '.repeat(width);
  const trailing = pem.endsWith('\n');
  const body = trailing ? pem.slice(0, -1) : pem;
  return body.split('\n').map(line => pad + line).join('\n') + (trailing ? '\n' : '');
}

/**
 * A body span of EXACTLY `total` chars: a leading newline, then 64-column runs
 * of `A`. The span is every char between the header's closing `-----` and the
 * footer's leading `-----END`, newlines included, which is what the `{0,32768}`
 * quantifier counts (JS counts UTF-16 code units; PEM armor is ASCII, so units,
 * chars and bytes all agree).
 */
function spanOfLength(total: number): string {
  const line = 'A'.repeat(64) + '\n';
  let span = '\n';
  while (span.length < total) span += line;
  return span.slice(0, total);
}

describe('HMA-34: pem-private-key body bounded per block, never crossing a header', () => {
  // One header run, 22 chars, no END anywhere. This is the pattern's own
  // alphabet: the shape that makes an unbounded lazy body quadratic, because
  // every header without a footer scans to end-of-input before failing.
  const H = armorHeader('A') + '\n';

  describe('AC1 — the three quadratic shapes, each under 500 ms', () => {
    it('HMA-34.AC1 probe A: 1 MiB of headers with no END is returned unchanged, under budget', () => {
      const a = H.repeat(47662);
      expect(a.length).toBe(1_048_564); // under MAX_REDACTION_INPUT_BYTES, so not withheld

      let out = '';
      const ms = msFor(() => {
        out = redactSecretsForReport(a);
      });

      // Measured on the base literal in this worktree: 10,685 ms through this
      // very call (11,309 ms regex-only), against 5 ms at the ruled literal.
      // Base timing is machine-dependent — the ledger's row is 9,196 ms
      // through a built dist, the unit's filing 11.7 s / 12.3 s — so the
      // number stays a COMMENT and only the budget is asserted.
      expect(ms).toBeLessThan(BUDGET_MS);
      expect(out).toBe(a);
    });

    it('HMA-34.AC1 probe B: only the LAST header pairs with the END, under budget', () => {
      const b = H.repeat(47660) + armorFooter('A') + '\n';
      expect(b.length).toBe(1_048_540);

      let out = '';
      const ms = msFor(() => {
        out = redactSecretsForReport(b);
      });

      // Probe B is red at base on its OUTPUT, not its clock: the unbounded body
      // swallows all 1 MiB as one block and returns 23 chars, in 4 ms here and
      // 0.4 ms in the ledger — timing alone cannot separate base from fix on B.
      // What is pinned here is that the body refuses to cross another header,
      // so the 47,659 headers ahead of the last one survive verbatim.
      expect(ms).toBeLessThan(BUDGET_MS);
      expect(out).toBe(H.repeat(47659) + PRIVATE_KEY_MARKER + '\n');
    });

    it('HMA-34.AC1 probe C: a real block ahead of a 1 MiB header run redacts, under budget', () => {
      const ec = mintPkcs8('ec');
      const c = ec + H.repeat(47651);
      expect(c.length).toBe(1_048_563);

      let out = '';
      const ms = msFor(() => {
        out = redactSecretsForReport(c);
      });

      // Base: 10,781 ms here — every header after the minted block scans to
      // end-of-input. 5 ms at the ruled literal. Comment, not assertion.
      expect(ms).toBeLessThan(BUDGET_MS);
      expect(out).toBe(PRIVATE_KEY_MARKER + '\n' + H.repeat(47651));
    });
  });

  describe('AC2 — real blocks, minted at test time, redact to exactly the marker', () => {
    it('HMA-34.AC2 a minted RSA-2048 PKCS#8 block redacts whole, plain and 16-space-indented', () => {
      const pem = mintPkcs8('rsa');
      // ~1,704 chars, and deliberately NOT pinned: DER integers drop leading
      // zero bytes, so a fresh RSA-2048 PKCS#8 block measured 1700 / 1704 /
      // 1708 over 60 mints here (1704 in 56 of them). The EC block below IS
      // pinned — its scalar and point are fixed-width, 241 chars in 500 of 500
      // mints — which is what probe C's length arithmetic rests on.
      expect(pem.startsWith(armorHeader('PRIVATE'))).toBe(true);
      expect(pem.endsWith(armorFooter('PRIVATE') + '\n')).toBe(true);

      // The PEM's own trailing newline is the only residue.
      expect(redactSecretsForReport(pem)).toBe(PRIVATE_KEY_MARKER + '\n');
      expect(redactSecretsForReport(indentBlock(pem, 16))).toBe(
        ' '.repeat(16) + PRIVATE_KEY_MARKER + '\n',
      );
    });

    it('HMA-34.AC2 a minted EC P-256 PKCS#8 block redacts whole, plain and 16-space-indented', () => {
      const pem = mintPkcs8('ec');
      expect(pem.length).toBe(241);

      expect(redactSecretsForReport(pem)).toBe(PRIVATE_KEY_MARKER + '\n');
      expect(redactSecretsForReport(indentBlock(pem, 16))).toBe(
        ' '.repeat(16) + PRIVATE_KEY_MARKER + '\n',
      );
    });

    it('HMA-34.AC2 the report boundary names exactly the pem-private-key shape', () => {
      const { shapes } = redactSecretsForReportReporting(mintPkcs8('rsa'));
      expect(shapes).toEqual(['pem-private-key']);
    });
  });

  describe('AC3 — the bound is structural, per block, at N = 32768', () => {
    const KIND = 'RSA PRIVATE';

    it('HMA-34.AC3 a 32,768-char span is replaced by exactly the marker', () => {
      const span = spanOfLength(32_768);
      expect(span.length).toBe(32_768);

      expect(redactSecretsForReport(armorHeader(KIND) + span + armorFooter(KIND))).toBe(
        PRIVATE_KEY_MARKER,
      );
    });

    it('HMA-34.AC3 a 32,769-char span is left VERBATIM rather than partly consumed', () => {
      const span = spanOfLength(32_769);
      expect(span.length).toBe(32_769);

      // One char past the bound is not a key either producing toolchain can
      // emit (OpenSSL caps RSA at 16384 bits; the largest measured formatted
      // body is 15,884 chars). The rule declines the whole block rather than
      // eating a bounded prefix of it — red at base, where the unbounded body
      // redacts this.
      const input = armorHeader(KIND) + span + armorFooter(KIND);
      const out = redactSecretsForReport(input);

      expect(out).toBe(input);
      expect(out).not.toContain(PRIVATE_KEY_MARKER);
      expect(out).toContain(armorHeader(KIND));
      expect(out).toContain(armorFooter(KIND));
    });

    it('HMA-34.AC3 the largest-real-variant stand-in is comfortably inside the bound', () => {
      // 197 x 64-column lines at 16-space YAML indentation = a 15,958-char
      // span, at or above the largest real body measured (an encrypted
      // RSA-16384 PKCS#8 block indented 16, at 15,884). RSA-16384 is not minted
      // here: generating one costs ~14 s.
      const kind = 'ENCRYPTED PRIVATE';
      const span = '\n' + (' '.repeat(16) + 'A'.repeat(64) + '\n').repeat(197);
      expect(span.length).toBe(15_958);

      expect(redactSecretsForReport(armorHeader(kind) + span + armorFooter(kind))).toBe(
        PRIVATE_KEY_MARKER,
      );
    });
  });

  describe('AC4 — the ruled literal and its hand-held mirror move together', () => {
    const REPO_ROOT = resolve(__dirname, '..', '..');

    // Built from the same parts as everything else above, so no line in this
    // file is a whole armor header. `[\\s\\S]` here is the two-character class
    // `[\s\S]` as it is spelled in both sources.
    const RULED_PATTERN =
      armorHeader('[A-Z ]+') +
      '(?:(?!' +
      ARMOR_BEGIN.trimEnd() +
      ')[\\s\\S]){0,32768}?' +
      armorFooter('[A-Z ]+');

    it('HMA-34.AC4 the rule table carries the ruled bounded entry verbatim', () => {
      const src = readFileSync(
        join(REPO_ROOT, 'src', 'nanomind-core', 'security', 'defense-in-depth.ts'),
        'utf-8',
      );

      expect(src).toContain(
        "{ id: 'pem-private-key', pattern: /" +
          RULED_PATTERN +
          "/g, replacement: '" +
          PRIVATE_KEY_MARKER +
          "' },",
      );
      // The old unbounded body is gone, not merely shadowed.
      expect(src).not.toContain(armorHeader('[A-Z ]+') + '[\\s\\S]*?' + armorFooter('[A-Z ]+'));
    });

    it('HMA-34.AC4 the parity oracle was hand-edited to the same ruled pattern', () => {
      // The oracle at `redaction-rule-table-parity.test.ts` is a deliberate
      // hand-written copy in a different FORM. It proves nothing about the new
      // rule unless it carries the new rule.
      const oracle = readFileSync(
        join(REPO_ROOT, '__tests__', 'nanomind-core', 'redaction-rule-table-parity.test.ts'),
        'utf-8',
      );

      expect(oracle).toContain('/' + RULED_PATTERN + '/g');
      expect(oracle).not.toContain(armorHeader('[A-Z ]+') + '[\\s\\S]*?' + armorFooter('[A-Z ]+'));
    });
  });
});
