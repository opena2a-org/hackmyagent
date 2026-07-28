/**
 * Credential-format predicate — entropy floor on the high-entropy fallback.
 *
 * The fallback used to be a pure LENGTH test (`\b[A-Za-z0-9+=_]{40,}\b`), so a
 * fill-in-the-blank form rule read as a credential. That shipped a HIGH
 * "Hardcoded Secret Detected" on a public incident-response contact-sheet
 * template whose only "secret" was the heading "U.S. Secret Service (Cyber
 * Fraud)" next to two form blanks.
 *
 * These tests lock both directions: filler is rejected, and every realistic
 * credential shape is still accepted. The "still accepted" half is the one
 * that matters most — an FP fix that quietly narrows detection is worse than
 * the FP.
 */

import { describe, it, expect } from 'vitest';
import {
  isCredibleEntropyBlob,
  isAcceptedCredentialMatch,
  findCredentialFormatMatch,
  hasCredentialFormat,
  MIN_DISTINCT_CHARS_IN_ENTROPY_BLOB,
} from '../../src/types/credential-format';

// The exact blank from the real-world false positive: 47 underscores.
const FORM_BLANK = '_'.repeat(47);

describe('credential-format entropy floor', () => {
  describe('filler runs are not credentials', () => {
    it('rejects a 47-underscore form blank (the reported false positive)', () => {
      expect(hasCredentialFormat(`**Local Office**: ${FORM_BLANK}`)).toBe(false);
    });

    it('rejects form blanks of any length past the 40-char threshold', () => {
      for (const n of [40, 47, 60, 120]) {
        expect(hasCredentialFormat(`Phone: ${'_'.repeat(n)}`), `${n} underscores`).toBe(false);
      }
    });

    it('rejects a run of one repeated letter or digit', () => {
      expect(isAcceptedCredentialMatch('A'.repeat(40))).toBe(false);
      expect(isAcceptedCredentialMatch('0'.repeat(64))).toBe(false);
    });

    it('rejects a two-character alternating run', () => {
      expect(isAcceptedCredentialMatch('ab'.repeat(30))).toBe(false);
    });

    it('rejects the full contact-sheet stanza that produced the false positive', () => {
      const stanza = [
        `**Cyber Task Force**: ${FORM_BLANK}`,
        '',
        '---',
        '',
        '### U.S. Secret Service (Cyber Fraud)',
        `**Local Office**: ${FORM_BLANK}`,
      ].join('\n');
      expect(hasCredentialFormat(stanza)).toBe(false);
    });
  });

  describe('real credential shapes are still detected', () => {
    const realCredentials: Array<[string, string]> = [
      ['sha1 hex digest', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'],
      ['sha256 hex digest', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
      ['base62 API token', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0'],
      ['raw 43-char secret (b17c shape)', 'Zk3nQ7pR2mT9wX4vL8jH5yB0cF6dS1aG3eN7uI2oQ9w'],
      ['snake_case high-entropy blob', 'aB3_dE7_fG1_hJ4_kL9_mN2_pQ6_rS8_tU5_vW0_xY7'],
      ['base64 with padding chars', 'QWxhZGRpbjpvcGVuIHNlc2FtZQ==QWxhZGRpbjpvcGVu'],
    ];

    for (const [label, value] of realCredentials) {
      it(`accepts ${label}`, () => {
        expect(isAcceptedCredentialMatch(value), `${label}: ${value}`).toBe(true);
        expect(hasCredentialFormat(`password = ${value}`), label).toBe(true);
      });
    }

    const vendorCredentials: Array<[string, string]> = [
      ['OpenAI/Anthropic sk-', 'sk-abcdefghijklmnopqrstuvwxyz0123456789'],
      ['Stripe live', ['sk', '_live_abcdefghijklmnopqrstuvwxyz'].join('')],
      ['GitHub PAT', ['ghp', '_abcdefghijklmnopqrstuvwxyz', '0123456789'].join('')],
      ['AWS access key id', 'AKIAIOSFODNN7EXAMPLE'],
      ['Google API key', ['AIza', 'SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q'].join('')],
      ['Slack bot token', 'xoxb-123456789012-abcdefghijkl'],
      ['JWT', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcDEF123'],
    ];

    for (const [label, value] of vendorCredentials) {
      it(`accepts vendor-prefixed ${label} (bypasses the entropy floor)`, () => {
        expect(isAcceptedCredentialMatch(value), `${label}: ${value}`).toBe(true);
      });
    }

    it('accepts a vendor-prefixed key whose body is low-diversity', () => {
      // A real key is a real key even if its body happens to repeat. The
      // prefix is the positive identification, so the floor must not apply.
      const lowDiversityRealKey = `ghp_${'A'.repeat(36)}`;
      expect(new Set(lowDiversityRealKey).size).toBeLessThan(MIN_DISTINCT_CHARS_IN_ENTROPY_BLOB + 3);
      expect(isAcceptedCredentialMatch(lowDiversityRealKey)).toBe(true);
    });
  });

  describe('a form blank must not mask a later real credential', () => {
    it('finds the real credential when a form blank appears first', () => {
      const content = [
        '# Incident response contacts',
        `**Local Office**: ${FORM_BLANK}`,
        'apiKey = A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0',
      ].join('\n');

      const hit = findCredentialFormatMatch(content);
      expect(hit, 'the real credential after the form blank must still be found').toBeDefined();
      expect(hit?.value).toBe('A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0');
    });

    it('reports the offset of the real credential, not the blank', () => {
      const content = `${FORM_BLANK}\nsecret=Zk3nQ7pR2mT9wX4vL8jH5yB0cF6dS1aG3eN7uI2oQ9w`;
      const hit = findCredentialFormatMatch(content);
      expect(hit?.index).toBeGreaterThan(FORM_BLANK.length);
    });
  });

  describe('isCredibleEntropyBlob', () => {
    it('counts distinct characters against the documented floor', () => {
      expect(isCredibleEntropyBlob('abcd'.repeat(12))).toBe(false); // 4 distinct
      expect(isCredibleEntropyBlob('abcde'.repeat(10))).toBe(true); // 5 distinct
    });

    it('exposes the floor as a named constant', () => {
      expect(MIN_DISTINCT_CHARS_IN_ENTROPY_BLOB).toBe(5);
    });
  });
});
