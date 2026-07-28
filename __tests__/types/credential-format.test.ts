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
  hasAnyCredentialCandidate,
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

    it('accepts a vendor-prefixed key whose body is a single repeated character', () => {
      // A real key is a real key even if its body repeats. The prefix is the
      // positive identification, so the floor must not apply. The body alone
      // would be rejected by the floor, which is what makes this meaningful.
      const body = 'A'.repeat(36);
      expect(isCredibleEntropyBlob(body), 'the body alone must fail the floor').toBe(false);
      expect(isAcceptedCredentialMatch(`ghp_${body}`)).toBe(true);
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

  describe('the shared vendor matcher is stateless across calls', () => {
    it('returns the same verdict for the same input on repeated calls', () => {
      // The vendor matcher is a module-level RegExp reused across candidates.
      // If it ever gains the `g` flag it would carry `lastIndex` between
      // `.test()` calls and start skipping matches non-deterministically.
      const key = ['ghp', '_abcdefghijklmnopqrstuvwxyz', '0123456789'].join('');
      for (let i = 0; i < 5; i++) {
        expect(isAcceptedCredentialMatch(key), `call ${i + 1}`).toBe(true);
      }
    });

    it('does not let one candidate affect the next', () => {
      const vendor = ['ghp', '_abcdefghijklmnopqrstuvwxyz', '0123456789'].join('');
      const filler = '_'.repeat(47);
      expect(isAcceptedCredentialMatch(vendor)).toBe(true);
      expect(isAcceptedCredentialMatch(filler)).toBe(false);
      expect(isAcceptedCredentialMatch(vendor)).toBe(true);
      expect(isAcceptedCredentialMatch(filler)).toBe(false);
    });

    it('finds every credential in a document with many candidate runs', () => {
      const filler = '_'.repeat(47);
      const doc = Array.from({ length: 20 }, (_, i) =>
        `**Field ${i}**: ${filler}`,
      ).join('\n') + '\napiKey = A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0\n';
      const hit = findCredentialFormatMatch(doc);
      expect(hit?.value, 'the real credential after 20 form blanks must still be found').toBe(
        'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0',
      );
    });
  });

  describe('the floor rejects only zero-entropy runs, never real secrets', () => {
    // Adversarial review killed an earlier floor of 5 distinct characters.
    // Distinct-character count is not an entropy measure: four symbols still
    // carry two bits per character, so a 64-char base-4 blob holds 128 bits.
    // A floor of 5 discarded exactly that, and the two suppression vetoes turned
    // the discard into a hiding place for a planted secret.
    it('accepts a low-alphabet blob that still carries real entropy', () => {
      expect(isAcceptedCredentialMatch('ACGT'.repeat(16)), '64 chars over 4 symbols = 128 bits').toBe(true);
      expect(isAcceptedCredentialMatch('ab'.repeat(30)), '60 chars over 2 symbols').toBe(true);
      expect(isAcceptedCredentialMatch('a1b2'.repeat(16)), 'hex over 4 nibbles').toBe(true);
    });

    it('rejects only a run of a single repeated character', () => {
      expect(isCredibleEntropyBlob('_'.repeat(47))).toBe(false);
      expect(isCredibleEntropyBlob('A'.repeat(40))).toBe(false);
      expect(isCredibleEntropyBlob('ab'.repeat(30))).toBe(true);
    });

    it('exposes the floor as a named constant set to the minimum that works', () => {
      expect(MIN_DISTINCT_CHARS_IN_ENTROPY_BLOB).toBe(2);
    });
  });

  describe('vendor tokens with a repetitive body are still detected', () => {
    // These live in the analyzer's vendor list. When the two lists were
    // maintained separately these fell through to the entropy fallback and a
    // floor above 2 dropped them outright.
    const lowDiversityVendorTokens: Array<[string, string]> = [
      ['Hugging Face', 'hf_' + 'a'.repeat(40)],
      ['GitLab PAT', 'glpat-' + 'a'.repeat(40)],
      ['GitHub server token', 'ghs_' + 'g'.repeat(40)],
      ['npm token', 'npm_' + 'm'.repeat(40)],
      ['SendGrid', 'SG.' + 'a'.repeat(40)],
      ['OpenAI project key', 'sk-proj-' + 'a'.repeat(40)],
    ];

    for (const [label, value] of lowDiversityVendorTokens) {
      it(`detects a ${label} token whose body repeats`, () => {
        expect(isAcceptedCredentialMatch(value), `${label}: ${value.slice(0, 12)}…`).toBe(true);
      });
    }
  });

  describe('filler glued to a credential must not swallow it', () => {
    // The entropy fallback is greedy over a class containing `_`, so filler
    // glued directly to a credential is absorbed into one candidate run.
    // Resuming the scan past the whole rejected run skipped the credential's
    // own prefix and lost it. The scan now resumes one character past where the
    // rejected candidate STARTED.
    const glued: Array<[string, string]> = [
      ['anthropic key', '_'.repeat(38) + 'sk-ant-api03-R3alK3yV4lu3W1thEntropy0'],
      ['slack token', '_'.repeat(38) + 'xoxb-123456789012-abcdefghijkl'],
      ['github pat', '_'.repeat(38) + ['ghp', '_abcdefghijklmnopqrstuvwxyz', '0123456789'].join('')],
    ];

    for (const [label, content] of glued) {
      it(`finds a ${label} glued directly to a form blank`, () => {
        expect(
          hasCredentialFormat(content),
          `a credential glued to filler must still be found: ${label}`,
        ).toBe(true);
      });
    }
  });

  describe('hasAnyCredentialCandidate is deliberately unfiltered', () => {
    // Used by the suppression vetoes, where the predicate is NEGATED. Applying
    // the entropy floor there would make the carve-out fire more often and turn
    // every floor-rejected value into a hiding place.
    it('reports a candidate even for a run the detection floor rejects', () => {
      const filler = '_'.repeat(47);
      expect(hasCredentialFormat(filler), 'detection gate rejects it').toBe(false);
      expect(hasAnyCredentialCandidate(filler), 'veto still sees a candidate').toBe(true);
    });

    it('reports a candidate for a low-alphabet planted secret', () => {
      expect(hasAnyCredentialCandidate('ACGT'.repeat(16))).toBe(true);
    });
  });
});
