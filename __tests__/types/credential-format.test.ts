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
 * credential shape is still accepted. The "still accepted" half is the one that
 * matters most — an FP fix that quietly narrows detection is worse than the FP,
 * and three consecutive adversarial passes on this branch each shipped exactly
 * that, past a fully green suite.
 *
 * Two rules follow from those three passes and are load-bearing here:
 *
 *   1. Assertions run against the PRODUCTION entry points. An earlier version
 *      of this file put ~19 assertions on `isAcceptedCredentialMatch`, which no
 *      production code path ever called, so they locked nothing. That export is
 *      gone and the assertions moved onto `hasCredentialFormat` /
 *      `findCredentialFormatMatch` / `hasAnchoredVendorCredential`.
 *
 *   2. Where `origin/main` has an answer, it is the ORACLE, quoted verbatim
 *      below. Every detection regression on this branch was a narrowing against
 *      main that no absolute assertion would have caught.
 */

import { describe, it, expect } from 'vitest';
import {
  isCredibleEntropyBlob,
  isVisualFiller,
  findCredentialFormatMatch,
  findJwtMatch,
  hasCredentialFormat,
  hasAnyCredentialCandidate,
  hasAnchoredVendorCredential,
  matchVendorPrefix,
  VENDOR_PREFIX_ALTERNATIVES,
} from '../../src/types/credential-format';

/**
 * `origin/main`'s (4837510) credential regexes, verbatim, as the oracle.
 *
 * MAIN_DETECT_RE is `buildCredentialFormatRegex()`; MAIN_VENDOR_RE is the body
 * of `hasVendorPrefixCredential`. Neither bounds the JWT and neither knows
 * `SG.`. They are quoted rather than described because "matches main" was
 * asserted in a code comment three times on this branch and was wrong each time.
 */
const MAIN_DETECT_RE = new RegExp(
  [
    'sk-[a-zA-Z0-9_-]{20,}', 'sk_live_[a-zA-Z0-9]{20,}', 'sk_test_[a-zA-Z0-9]{20,}',
    'ghp_[a-zA-Z0-9]{20,}', 'gho_[a-zA-Z0-9]{20,}', 'github_pat_[a-zA-Z0-9_]{20,}',
    'AKIA[0-9A-Z]{16}', 'AIza[0-9A-Za-z_-]{35}', 'xox[abprs]-[0-9A-Za-z-]{10,}',
    'eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+',
    '\\b[A-Za-z0-9+=_]{40,}\\b',
  ].join('|'),
);
const MAIN_JWT_RE = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;

// The exact blank from the real-world false positive: 47 underscores.
const FORM_BLANK = '_'.repeat(47);

/**
 * Split so the file never contains a contiguous `ghp_` + 36-character literal.
 * GitHub push protection scans raw file bytes, and this repo already follows the
 * convention for the Slack fixture in `benign-fp-regression.test.ts`. The value
 * is a dummy: a real PAT carries a checksum in its last six characters.
 */
const GITHUB_PAT_FIXTURE = ['ghp', '_abcdefghijklmnopqrstuvwxyz', '0123456789'].join('');

/**
 * A deterministic draw from a small alphabet.
 *
 * The distinction the filler rules turn on is ENTROPY, not alphabet size, so
 * "low alphabet" fixtures have to be RANDOM over that alphabet. Writing them as
 * `'ACGT'.repeat(16)` — which an earlier version of these tests did — produces a
 * string with period 4, i.e. filler, and then asserts filler must be detected.
 * That fixture tested the alphabet floor it was written against and would have
 * blocked any rule that measured structure instead. Seeded, not `Math.random`,
 * so a failure reproduces.
 */
function drawFrom(alphabet: string, length: number, seed: number): string {
  let state = seed;
  let out = '';
  for (let i = 0; i < length; i++) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    out += alphabet[Math.floor((state / 0x7fffffff) * alphabet.length)];
  }
  return out;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** A real SendGrid key: `SG.<22-char id>.<43-char secret>`, both fixed. */
function sendGridKey(seed = 11): string {
  return `SG.${drawFrom(B64, 22, seed)}.${drawFrom(B64, 43, seed + 1)}`;
}

describe('credential-format entropy floor', () => {
  describe('filler runs are not credentials', () => {
    it('rejects a 47-underscore form blank (the reported false positive)', () => {
      expect(hasCredentialFormat(`**Local Office**: ${FORM_BLANK}`)).toBe(false);
    });

    it('rejects form blanks of any length past the 40-char threshold', () => {
      for (const n of [40, 47, 60, 120, 400, 1000]) {
        expect(hasCredentialFormat(`Phone: ${'_'.repeat(n)}`), `${n} underscores`).toBe(false);
      }
    });

    it('rejects a run of one repeated letter or digit', () => {
      expect(hasCredentialFormat(`key = ${'A'.repeat(40)}`)).toBe(false);
      expect(hasCredentialFormat(`key = ${'0'.repeat(64)}`)).toBe(false);
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
        expect(hasCredentialFormat(value), `${label}: ${value}`).toBe(true);
        expect(hasCredentialFormat(`password = ${value}`), label).toBe(true);
        expect(MAIN_DETECT_RE.test(value), `${label}: main must agree`).toBe(true);
      });
    }

    const vendorCredentials: Array<[string, string]> = [
      ['OpenAI/Anthropic sk-', 'sk-abcdefghijklmnopqrstuvwxyz0123456789'],
      ['Stripe live', ['sk', '_live_abcdefghijklmnopqrstuvwxyz'].join('')],
      ['GitHub PAT', GITHUB_PAT_FIXTURE],
      ['AWS access key id', 'AKIAIOSFODNN7EXAMPLE'],
      ['Google API key', ['AIza', 'SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q'].join('')],
      ['Slack bot token', 'xoxb-123456789012-abcdefghijkl'],
      ['JWT', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcDEF123'],
      ['SendGrid', sendGridKey()],
    ];

    for (const [label, value] of vendorCredentials) {
      it(`accepts vendor-prefixed ${label} (bypasses the entropy floor)`, () => {
        expect(hasCredentialFormat(value), `${label}: ${value}`).toBe(true);
      });
    }

    it('accepts a vendor-prefixed key whose body is a single repeated character', () => {
      // A real key is a real key even if its body repeats. The prefix is the
      // positive identification, so the floor must not apply. The body alone
      // would be rejected by the floor, which is what makes this meaningful.
      const body = 'A'.repeat(36);
      expect(isCredibleEntropyBlob(body), 'the body alone must fail the floor').toBe(false);
      expect(hasCredentialFormat(`ghp_${body}`)).toBe(true);
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
      // The vendor matchers are module-level RegExps reused across candidates.
      // If one ever gains the `g` flag it would carry `lastIndex` between
      // `.test()` calls and start skipping matches non-deterministically.
      const key = GITHUB_PAT_FIXTURE;
      for (let i = 0; i < 5; i++) {
        expect(hasCredentialFormat(key), `hasCredentialFormat call ${i + 1}`).toBe(true);
        expect(hasAnchoredVendorCredential(key), `anchored gate call ${i + 1}`).toBe(true);
        expect(hasAnyCredentialCandidate(key), `veto call ${i + 1}`).toBe(true);
      }
    });

    it('does not let one candidate affect the next', () => {
      const vendor = GITHUB_PAT_FIXTURE;
      const filler = '_'.repeat(47);
      for (let i = 0; i < 2; i++) {
        expect(hasCredentialFormat(vendor), `vendor, round ${i}`).toBe(true);
        expect(hasCredentialFormat(filler), `filler, round ${i}`).toBe(false);
        expect(hasAnchoredVendorCredential(vendor), `anchored vendor, round ${i}`).toBe(true);
        expect(hasAnchoredVendorCredential(filler), `anchored filler, round ${i}`).toBe(false);
      }
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

  describe('the floor rejects filler, never a secret that carries entropy', () => {
    // Two earlier floors were tried and killed by adversarial review:
    //
    //   1. Five DISTINCT characters. Distinct-character count is not an entropy
    //      measure — four symbols carry two bits each, so a 64-char base-4 blob
    //      holds 128 bits — and the two suppression vetoes turned every
    //      discarded value into a hiding place for a planted secret.
    //   2. "Not a single repeated character" (distinct >= 2). One character
    //      from failing: `'_'x46 + '1'` and `'_='x25` both still read as
    //      credentials.
    //
    // What replaced them measures STRUCTURE, so it separates the classes the
    // alphabet-size floors could not: a short repeated unit, or one character
    // dominating the run.
    it('accepts a low-alphabet secret that carries real entropy', () => {
      // Random over the alphabet, which is what a low-alphabet secret is.
      expect(hasCredentialFormat(drawFrom('ACGT', 64, 7)), '64 chars over 4 symbols = 128 bits').toBe(true);
      expect(hasCredentialFormat(drawFrom('ACGT', 40, 99)), '40 chars over 4 symbols = 80 bits').toBe(true);
      expect(hasCredentialFormat(drawFrom('01', 64, 5)), '64 chars over 2 symbols = 64 bits').toBe(true);
      expect(hasCredentialFormat(drawFrom('0123456789abcdef', 40, 11)), 'hex').toBe(true);
    });

    it('rejects a short repeated unit, which is what filler looks like', () => {
      expect(isCredibleEntropyBlob('_'.repeat(47)), 'period 1: the reported blank').toBe(false);
      expect(isCredibleEntropyBlob('A'.repeat(40)), 'period 1').toBe(false);
      expect(isCredibleEntropyBlob('_='.repeat(25)), 'period 2: dot leader').toBe(false);
      expect(isCredibleEntropyBlob('01'.repeat(25)), 'period 2').toBe(false);
      expect(isCredibleEntropyBlob('de'.repeat(24)), 'period 2').toBe(false);
      expect(isCredibleEntropyBlob('a1'.repeat(24)), 'period 2').toBe(false);
      expect(isCredibleEntropyBlob('ACGT'.repeat(16)), 'period 4').toBe(false);
      expect(isCredibleEntropyBlob('abcd'.repeat(12)), 'period 4').toBe(false);
    });

    it('rejects a run dominated by one character, which the period rule alone misses', () => {
      // The "one character from failing" case: aperiodic, so only the
      // dominance rule reaches it.
      expect(isCredibleEntropyBlob('_'.repeat(46) + '1'), 'form blank + stray digit').toBe(false);
      expect(isCredibleEntropyBlob('_'.repeat(60) + 'ab'), 'form blank + stray pair').toBe(false);
      expect(isCredibleEntropyBlob('x'.repeat(45) + 'Q9'), '45/47 one symbol').toBe(false);
    });

    it('does not treat a short period as filler when the unit barely repeats', () => {
      // `abcdabcd` has period 4 but only two repeats — too short to be filler,
      // and this keeps the rule off the 8-char values SEM-CRED-002 inspects.
      expect(isCredibleEntropyBlob('abcdabcd')).toBe(true);
      expect(isCredibleEntropyBlob('a1b2a1b2')).toBe(true);
    });

    it('keeps a genuine secret that merely contains a repeated stretch', () => {
      // A real secret with a run of repeats inside it is neither periodic
      // overall nor dominated by one symbol.
      const secret = 'K3y' + 'a'.repeat(20) + drawFrom('0123456789abcdefXYZ', 25, 42);
      expect(isCredibleEntropyBlob(secret)).toBe(true);
      expect(hasCredentialFormat(`apiKey = ${secret}`)).toBe(true);
    });
  });

  describe('the filler rules are judged on a sliding window, not the whole run', () => {
    // THIRD adversarial pass, HIGH. `'_'x361 + <40-char secret>` is a single
    // 401-character greedy run in which underscores are 90.02% of the total —
    // just over the dominance threshold — so the run was rejected whole and the
    // secret with it. `'_'x300` sat just UNDER the threshold, which is the only
    // reason the shape looked covered, and the one test for it used
    // `'_'x400 + '=' + secret`: the `=` is a non-word character, so it gave the
    // old walk an interior `\b` to restart from. Delete the `=` and it failed.
    const secret = drawFrom(B64, 40, 77);

    it('finds a secret glued to a filler run of ANY length', () => {
      for (const n of [38, 100, 300, 360, 361, 400, 1000, 5000]) {
        const hit = findCredentialFormatMatch('_'.repeat(n) + secret);
        expect(hit?.value, `'_'x${n} + secret must still be found`).toContain(secret);
        expect(MAIN_DETECT_RE.test('_'.repeat(n) + secret), `main finds '_'x${n} + secret`).toBe(true);
      }
    });

    it('reports the secret offset, not the run start, so the line points at the key', () => {
      const hit = findCredentialFormatMatch('_'.repeat(361) + secret);
      // The window may carry up to 36 characters of tolerated leading filler;
      // what must never happen is reporting from the start of a 361-char blank.
      expect(hit!.index).toBeGreaterThan(300);
    });

    it('still rejects the filler shapes the window could have re-admitted', () => {
      // The window is the risk: judging 40 characters at a time could let a
      // long blank through on some sub-window. These are the exact shapes the
      // rules exist for, at lengths where a window exists.
      for (const [label, run] of [
        ["'_'x47", '_'.repeat(47)],
        ["'_'x400", '_'.repeat(400)],
        ["'_'x46+'1'", '_'.repeat(46) + '1'],
        ["'_='x25", '_='.repeat(25)],
        ["'_='x200", '_='.repeat(200)],
        ["'a'x40+'=' repeated", ('a'.repeat(40) + '=').repeat(20)],
      ] as Array<[string, string]>) {
        expect(hasCredentialFormat(`x: ${run}`), label).toBe(false);
      }
    });

    it('keeps a SHORT secret glued to a long blank, which pins the dominance share', () => {
      // Pins `MAX_DOMINANT_CHAR_SHARE`. Adversarial review proved the constant
      // was unpinned: dropping 0.9 to 0.5 left the whole suite green while
      // `'_'x400 + <16-char secret>` went from found to lost, because no window
      // then carries few enough underscores. The shorter the secret, the
      // tighter the constraint, so a short one is what locks the value.
      for (const len of [16, 24, 40]) {
        const secret = drawFrom(B64, len, 5);
        const hit = findCredentialFormatMatch('_'.repeat(400) + secret);
        expect(hit?.value, `a ${len}-char secret after a 400-char blank`).toContain(secret);
      }
    });

    it('cross-checks the incremental dominance counter against the direct predicate', () => {
      // The sliding walk maintains a running character count so the dominance
      // rule is O(1) per step. That counter is an ACCELERATOR, not a second
      // opinion — if it ever disagrees with `isCredibleEntropyBlob` the walk
      // silently skips windows, which is a detection loss that no absolute
      // assertion would show. Randomised runs, seeded so failures reproduce.
      for (let seed = 1; seed <= 60; seed++) {
        const run =
          '_'.repeat(seed % 50) +
          drawFrom('ab_=01', 40 + (seed % 30), seed) +
          '_'.repeat((seed * 7) % 40);
        const hit = findCredentialFormatMatch(run);
        // Recompute the answer the slow, obvious way.
        let expected: number | undefined;
        for (let k = 0; k + 40 <= run.length; k++) {
          if (isCredibleEntropyBlob(run.slice(k, k + 40))) { expected = k; break; }
        }
        expect(hit?.index, `seed ${seed}: incremental walk disagrees with the direct predicate`)
          .toBe(expected);
      }
    });
  });

  describe('the JWT is matched by a linear scan, unbounded, exactly as main matches it', () => {
    // THIRD adversarial pass, CRITICAL. The JWT used to be a regex alternative
    // whose segments were capped (256-char header, 4096-char tail) to stop a
    // quadratic. That cap leaked into `VENDOR_PREFIX_CONTENT_RE` — the one gate
    // that LIFTS the corpus and integrity-manifest carve-outs — so a real DPoP
    // proof or `x5c` chain header stopped matching and a live token planted in
    // a corpus path was fully suppressed, CRITICAL included.
    const oversized: Array<[string, number, number]> = [
      ['ordinary JWT', 36, 40],
      ['DPoP proof with an embedded JWK', 550, 40],
      ['x5c certificate-chain header', 430, 40],
      ['5000-character payload', 36, 5000],
      ['both segments oversized', 2000, 9000],
    ];

    for (const [label, headLen, bodyLen] of oversized) {
      it(`lifts suppression for a ${label}`, () => {
        const jwt = `eyJ${drawFrom(B64, headLen, 3)}.${drawFrom(B64, bodyLen, 5)}.${drawFrom(B64, 43, 7)}`;
        // Mutation guard: reintroducing ANY segment bound turns these red.
        expect(hasAnchoredVendorCredential(jwt), `${label}: the suppression-lifting gate`).toBe(true);
        expect(hasCredentialFormat(jwt), `${label}: the detection path`).toBe(true);
        expect(hasAnyCredentialCandidate(jwt), `${label}: the negated veto`).toBe(true);
        expect(MAIN_JWT_RE.test(jwt), `${label}: main matches it`).toBe(true);
      });
    }

    it('rejects the degenerate segment shapes, exactly as main rejects them', () => {
      // Each segment must be NON-EMPTY (`[A-Za-z0-9_-]+` in main's regex). These
      // are pinned explicitly rather than left to the randomised sweep below:
      // relaxing the header check to allow an empty segment survived a 300-case
      // random parity test, because the shapes are too rare to be drawn
      // reliably. An edge case worth asserting is worth asserting by name.
      for (const text of ['eyJ.abc.def', 'eyJa..def', 'eyJa.bcd.', 'eyJ..', 'eyJabc.def', 'eyJ']) {
        expect(findJwtMatch(text, false), `must not match: ${text}`).toBeUndefined();
        expect(MAIN_JWT_RE.test(text), `main must also reject: ${text}`).toBe(false);
      }
      expect(findJwtMatch('eyJa.bcd.ef', false)?.value, 'the minimal real shape').toBe('eyJa.bcd.ef');
    });

    it('agrees with main\'s regex on leftmost match over randomised inputs', () => {
      // Existence AND position, because the scan replaced a regex and the whole
      // point is that nothing about what it accepts changed.
      //
      // The generator uses `Math.imul` and the HIGH bits. Written as
      // `(state * 1103515245 + 12345) & 0x7fffffff` with `% alphabet.length`,
      // the product exceeds 2**53 and loses its low bits, so `% 10` yielded
      // only EVEN indices — `.` was never emitted, no input ever contained a
      // JWT, and 300 cases compared undefined to undefined. Mutation caught it.
      const alphabet = ['eyJ', '.', '-', '_', 'a', 'Z', '9', ' ', 'eyJ', '..'];
      let drew = 0;
      for (let seed = 1; seed <= 300; seed++) {
        let text = '';
        let state = seed >>> 0;
        for (let i = 0; i < 40; i++) {
          state = (Math.imul(state, 1103515245) + 12345) >>> 0;
          text += alphabet[Math.floor((state / 0x100000000) * alphabet.length)];
        }
        const mine = findJwtMatch(text, false);
        const theirs = MAIN_JWT_RE.exec(text);
        if (theirs) drew++;
        expect(mine?.index, `seed ${seed}: index on ${JSON.stringify(text)}`).toBe(theirs?.index);
        expect(mine?.value, `seed ${seed}: value on ${JSON.stringify(text)}`).toBe(theirs?.[0]);
      }
      // Non-vacuity: a sweep that never generates a JWT proves nothing.
      expect(drew, 'the randomised sweep must actually produce JWTs to compare').toBeGreaterThan(20);
    });

    it('anchors only where the anchored gate asks it to', () => {
      const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcDEF123';
      // `_` and `-` are base64url characters but not alphanumeric, so an `eyJ`
      // in the middle of a run can clear an anchor the run's first one fails.
      expect(findJwtMatch(`prefix${jwt}`, true), 'glued to letters: anchored').toBeUndefined();
      expect(findJwtMatch(`prefix${jwt}`, false), 'glued to letters: unanchored').toBeDefined();
      expect(findJwtMatch(`prefix_${jwt}`, true), 'after filler: anchored still matches').toBeDefined();
    });
  });

  describe('a vendor prefix must not be glued to an alphanumeric identifier', () => {
    // The vendor-list unification put `SG.` into the DETECTION path and
    // re-created the very false-positive class this unit exists to remove:
    // ordinary dotted identifiers were positively identified as credentials.
    // The first fix was an anchor, which turned out to be both insufficient
    // (it cannot reach the UNANCHORED veto, where the same FP raised a
    // CRITICAL) and harmful (it dropped `tokenghp_…`, which main detects).
    // What fixes it in BOTH paths is the pattern: SendGrid's segments are
    // fixed at 22 and 43 characters, and a namespace is not.
    it('does not fire on a message-bus constant whose namespace ends in SG', () => {
      for (const text of [
        'MSG.INCIDENT_ESCALATION_QUEUE',
        'MSG.INCIDENT_ESCALATION_QUEUE.HIGH_PRIORITY_ROUTE',
        'using SG.Configuration_Providers_Internal;',
        'using MSG.Configuration_Providers_Internal.Retry_Policy_Defaults;',
      ]) {
        expect(hasCredentialFormat(text), `detection: ${text}`).toBe(false);
        // The veto is where this raised a CRITICAL on a benign taxonomy
        // document, and it is unanchored by design, so the pattern has to
        // carry the fix on its own.
        expect(hasAnyCredentialCandidate(text), `veto: ${text}`).toBe(false);
        expect(MAIN_DETECT_RE.test(text), `main is clean on: ${text}`).toBe(false);
      }
    });

    it('still fires on a real SendGrid key, in every gate', () => {
      const key = sendGridKey();
      expect(hasCredentialFormat(key), 'detection').toBe(true);
      expect(hasAnyCredentialCandidate(key), 'veto').toBe(true);
      expect(hasAnchoredVendorCredential(key), 'suppression-lifting gate').toBe(true);
    });

    it('detects a SendGrid key by its 43-char secret even if the prefix is unrecognised', () => {
      // Belt and braces: the secret segment is its own 43-character run, so the
      // entropy fallback finds it even if the `SG.` alternative ever drifts.
      expect(hasCredentialFormat(drawFrom(B64, 43, 12))).toBe(true);
    });

    it('DOES fire on a vendor prefix continuing an identifier, as main does', () => {
      // The `(?<![A-Za-z0-9])` anchor on the DETECTION path was a pure
      // narrowing: main detects all three of these, and the false positives the
      // anchor was added for are removed by the SendGrid fixed lengths instead.
      // Losing a detection to fix an FP that is already fixed elsewhere is the
      // trade this unit exists to stop making.
      for (const text of [
        'MYghp_' + 'a'.repeat(20),
        'xAKIAIOSFODNN7EXAMPLE',
        'token' + 'ghp_' + 'a'.repeat(20),
        'v1AKIAIOSFODNN7EXAMPLE',
      ]) {
        expect(hasCredentialFormat(text), `detection: ${text}`).toBe(true);
        expect(MAIN_DETECT_RE.test(text), `main detects: ${text}`).toBe(true);
      }
    });

    it('keeps the anchor on the one gate main anchors', () => {
      // `hasVendorPrefixCredential` — a POSITIVE gate whose result BLOCKS
      // suppression. main anchors it with `\b`; this anchors with
      // `(?<![A-Za-z0-9])`, which is strictly wider (it also matches after `_`).
      expect(hasAnchoredVendorCredential('MYghp_' + 'a'.repeat(20))).toBe(false);
      expect(hasAnchoredVendorCredential('_'.repeat(38) + GITHUB_PAT_FIXTURE),
        'wider than main: a key glued to a form blank must still lift suppression').toBe(true);
    });

    it('STILL fires on a credential glued to underscore filler', () => {
      // The anchor is `(?<![A-Za-z0-9])`, deliberately NOT `\b`. `\b` counts `_`
      // as a word character, so it would drop a real key glued to a form blank —
      // the exact document shape this unit is about. Mutation guard: swapping the
      // anchor for `\b` turns these red.
      expect(hasAnchoredVendorCredential('_'.repeat(38) + 'sk-ant-api03-R3alK3yV4lu3W1thEntropy0')).toBe(true);
      expect(hasAnchoredVendorCredential('_'.repeat(47) + 'AKIAIOSFODNN7EXAMPLE')).toBe(true);
    });
  });

  describe('masking derives its prefixes from the same vendor list', () => {
    // A fourth hand-maintained copy of the vendor list lived in
    // `maskCredentialValue` and was five entries behind, so every newly
    // detectable token took the unknown-shape branch and printed the first 8
    // characters — 2-5 characters of live secret body — into finding evidence.
    it('recognises every vendor prefix that the detector recognises', () => {
      const cases: Array<[string, string]> = [
        ['sk-ant-api03-' + 'a'.repeat(30), 'sk-ant-api0'],
        ['sk-proj-' + 'a'.repeat(30), 'sk-proj-'],
        ['ghp_' + 'a'.repeat(30), 'ghp_'],
        ['ghu_' + 'a'.repeat(30), 'ghu_'],
        ['ghs_' + 'a'.repeat(30), 'ghs_'],
        ['hf_' + 'a'.repeat(30), 'hf_'],
        ['glpat-' + 'a'.repeat(30), 'glpat-'],
        ['npm_' + 'a'.repeat(30), 'npm_'],
        ['github_pat_' + 'a'.repeat(30), 'github_pat_'],
        ['AKIAIOSFODNN7EXAMPLE', 'AKIA'],
        [sendGridKey(), 'SG.'],
        // The JWT left the alternation for a linear scan, so its prefix has to
        // be carried into the masking list explicitly. Without it every
        // detected JWT takes the unknown-shape branch and leaks 5 header bytes.
        ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcDEF123', 'eyJ'],
      ];
      for (const [value, expected] of cases) {
        expect(matchVendorPrefix(value), `prefix of ${value.slice(0, 14)}…`).toBe(expected);
      }
    });

    it('keeps a Slack token recognisable as a bot/user token, not a bare xox', () => {
      // `xox[abprs]-` — the single-character class is unquantified, so the
      // letter that says WHICH kind of Slack token this is stays visible.
      expect(matchVendorPrefix('xoxb-123456789012-abcdefghijkl')).toBe('xoxb-');
      expect(matchVendorPrefix('xoxp-123456789012-abcdefghijkl')).toBe('xoxp-');
    });

    it('returns undefined for an anonymous high-entropy blob', () => {
      expect(matchVendorPrefix(drawFrom('0123456789abcdef', 44, 3))).toBeUndefined();
    });

    it('derives a non-empty prefix for EVERY vendor alternative, by sweep', () => {
      // The hand-written case list above cannot fail for an alternative nobody
      // remembered to add to it. A future alternative beginning with a
      // metacharacter derives an empty head, `^` matches everything at length
      // 0, never wins the longest-prefix contest, and the token silently falls
      // to the unknown-shape masking branch that prints its first 8 characters
      // — the exact leak deriving the list was introduced to close. This sweeps
      // the source of truth instead.
      for (const alt of VENDOR_PREFIX_ALTERNATIVES) {
        // A literal head is everything before the first quantified atom, so
        // synthesising from the alternative's own literal prefix is enough.
        const literal = alt.replace(/\\\./g, '.').match(/^[A-Za-z0-9_.-]+/)?.[0] ?? '';
        expect(literal.length, `alternative has no literal head to derive from: ${alt}`).toBeGreaterThan(0);
      }
    });
  });

  describe('the scan is linear against adversarial filler, with no cap on input', () => {
    // Two quadratics were found here, and the fixes for BOTH were caps that
    // turned into detection holes. The defense is linearity: the JWT is a
    // linear scan, and each blob run is judged exactly once by sliding window,
    // so there is no resume to bound and no budget to exhaust.
    //
    // A regression here is quadratic, so it blows past the limit by orders of
    // magnitude rather than drifting past it.
    const megabyte: Array<[string, string]> = [
      ['dot-free JWT filler', '_'.repeat(47) + '-' + 'eyJ-'.repeat((1024 * 1024) / 4)],
      ['overlapping large candidates', ('a'.repeat(40) + '=').repeat(Math.floor((1024 * 1024) / 41))],
      ['rejected filler runs', ('_'.repeat(47) + '\n').repeat((1024 * 1024) / 48)],
      ['a single 1 MB periodic run', 'ab'.repeat((1024 * 1024) / 2)],
      ['a single 1 MB uniform run', 'a'.repeat(1024 * 1024)],
      ['1 MB of near-uniform aperiodic filler', ('_'.repeat(999) + 'q').repeat(1024)],
    ];

    for (const [label, payload] of megabyte) {
      it(`scans 1 MB of ${label} in well under a second`, () => {
        const started = performance.now();
        expect(hasCredentialFormat(payload)).toBe(false);
        const elapsed = performance.now() - started;
        expect(elapsed, `1 MB ${label} took ${elapsed.toFixed(0)} ms`).toBeLessThan(2000);
      });
    }

    it('does not pay asymptotically more for PERIODIC filler than for uniform filler', () => {
      // Guards the whole-run periodicity short circuit. Without it every window
      // of `'ab'x500k` is judged separately — 121 ms measured against 7 ms —
      // and no absolute threshold loose enough to be stable on CI can see that.
      // A RATIO can: both scans are the same size, in the same process, so
      // machine load cancels out. Measured ratio is ~1.2 with the short circuit
      // and ~14 without, so 5 is a wide margin either way.
      const uniform = 'a'.repeat(1024 * 1024);
      const periodic = 'ab'.repeat((1024 * 1024) / 2);
      const time = (payload: string) => {
        hasCredentialFormat(payload); // warm
        const started = performance.now();
        hasCredentialFormat(payload);
        return performance.now() - started;
      };
      const uniformMs = Math.max(time(uniform), 1);
      const periodicMs = time(periodic);
      expect(
        periodicMs / uniformMs,
        `periodic filler cost ${periodicMs.toFixed(0)} ms vs ${uniformMs.toFixed(0)} ms uniform`,
      ).toBeLessThan(5);
    });

    it('finds a VENDOR key buried behind a megabyte of filler', () => {
      const filler = ('a'.repeat(40) + '=').repeat(Math.floor((1024 * 1024) / 41));
      const key = 'sk-ant-api03-R3alK3yV4lu3W1thEntropy0';
      expect(hasCredentialFormat(`${filler}\n${key}\n`), 'key after 1 MB of filler').toBe(true);
      expect(findCredentialFormatMatch(`${filler}\n${key}\n`)?.value).toBe(key);
    });

    it('finds an ANONYMOUS key buried behind a megabyte of filler', () => {
      // THIRD adversarial pass, CRITICAL. This is the case the character budget
      // lost: the vendor pre-pass cannot cover an anonymous secret, so once the
      // budget was exhausted the walk gave up and `findCredentialFormatMatch`
      // returned undefined — the CLI score went 91 -> 96 purely from losing a
      // true positive. 12 KB of padding was enough. The only test that existed
      // used `sk-ant-…`, which the unbudgeted vendor pass finds regardless.
      const secret = drawFrom(B64, 40, 77);
      for (const kb of [12, 64, 1024]) {
        const filler = ('a'.repeat(40) + '=').repeat(Math.floor((kb * 1024) / 41));
        const hit = findCredentialFormatMatch(`${filler}\napiKey = ${secret}\n`);
        expect(hit?.value, `anonymous secret behind ${kb} KB of filler`).toContain(secret);
      }
    });

    it('still finds a real JWT', () => {
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      expect(hasCredentialFormat(jwt)).toBe(true);
      expect(findCredentialFormatMatch(`token: ${jwt}`)?.value).toBe(jwt);
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
      ['SendGrid', 'SG.' + 'a'.repeat(22) + '.' + 'b'.repeat(43)],
      ['OpenAI project key', 'sk-proj-' + 'a'.repeat(40)],
    ];

    for (const [label, value] of lowDiversityVendorTokens) {
      it(`detects a ${label} token whose body repeats`, () => {
        expect(hasCredentialFormat(value), `${label}: ${value.slice(0, 12)}…`).toBe(true);
        expect(hasAnchoredVendorCredential(value), `${label}: lifts suppression`).toBe(true);
      });
    }
  });

  describe('filler glued to a credential must not swallow it', () => {
    const glued: Array<[string, string]> = [
      ['anthropic key', '_'.repeat(38) + 'sk-ant-api03-R3alK3yV4lu3W1thEntropy0'],
      ['slack token', '_'.repeat(38) + 'xoxb-123456789012-abcdefghijkl'],
      ['github pat', '_'.repeat(38) + GITHUB_PAT_FIXTURE],
    ];

    for (const [label, content] of glued) {
      it(`finds a ${label} glued directly to a form blank`, () => {
        expect(
          hasCredentialFormat(content),
          `a credential glued to filler must still be found: ${label}`,
        ).toBe(true);
      });
    }

    it('returns the CREDENTIAL, not the filler run that swallowed its prefix', () => {
      // Guards the VENDOR pass: the greedy blob absorbs `'_'x38 + 'sk'` into one
      // 40-character candidate, so a blob-only scan reports the filler run (or,
      // once the dominance rule rejects it, nothing at all). Mutation guard:
      // removing the vendor pass turns this red.
      const key = 'sk-ant-api03-R3alK3yV4lu3W1thEntropy0';
      const hit = findCredentialFormatMatch('_'.repeat(38) + key);
      expect(hit?.value, 'the match must be the key itself').toBe(key);
      expect(hit?.index, 'and it must be reported at the key offset').toBe(38);
    });

    it('finds an ANONYMOUS blob that filler hides in the same run', () => {
      // The vendor pass cannot cover this one: the secret has no vendor prefix.
      // Under the old greedy-run judgement the whole 441-character run was one
      // candidate and was filler (underscores are 90.7% of it), so only an
      // interior `\b` — supplied here by the `=` — let the walk restart and
      // find the secret. The window finds it with or without the `=`; both
      // spellings are asserted so the fixture is not tuned to the survivor.
      const secret = drawFrom(B64, 40, 77);
      for (const [label, run] of [
        ['with the interior = that the old walk needed', '_'.repeat(400) + '=' + secret],
        ['without it', '_'.repeat(400) + secret],
      ] as Array<[string, string]>) {
        expect(isCredibleEntropyBlob(run), `precondition (${label}): the whole run is filler`).toBe(false);
        const hit = findCredentialFormatMatch(run);
        expect(hit, `a high-entropy secret must not be hidden by the filler around it (${label})`).toBeDefined();
        expect(hit!.value, `the reported match must carry the secret (${label})`).toContain(secret);
      }
    });
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

    it('reports a candidate for a vendor token glued to an identifier', () => {
      // Unanchored on purpose: under an anchored veto a token glued to a
      // preceding identifier matches nothing, the veto stops holding, and the
      // planted secret is suppressed.
      expect(hasAnyCredentialCandidate('"label":"MSGghp_AAAAAAAAAAAAAAAAAAAA"')).toBe(true);
    });
  });

  describe('form blanks in KEY-NAMED config values (SEM-CRED)', () => {
    // `isVisualFiller` is a SEPARATE test from `isCredibleEntropyBlob`, on
    // purpose. The AST fallback judges an anonymous 40+ character run where
    // structure is the only evidence; here a key name has already said "this is
    // a secret" and only the value's shape is in question. The structural rules
    // are far too blunt at 8 characters — they dropped these two real secrets.
    it('accepts weak-but-real secrets that the structural rules drop', () => {
      expect(isVisualFiller('Ab12'.repeat(6)), 'a weak 24-char password').toBe(false);
      expect(isVisualFiller('A'.repeat(43) + '='), 'base64 of an all-zero AES-256 key').toBe(false);
      // ...and the AST path still rejects both, because there they are anonymous.
      expect(isCredibleEntropyBlob('Ab12'.repeat(6))).toBe(false);
      expect(isCredibleEntropyBlob('A'.repeat(43) + '=')).toBe(false);
    });

    it('still rejects every drawn blank', () => {
      for (const [label, value] of [
        ["'_'x47, the reported blank", '_'.repeat(47)],
        ["'_'x46+'1'", '_'.repeat(46) + '1'],
        ["'_='x25 dot leader", '_='.repeat(25)],
        ["'-'x40 rule", '-'.repeat(40)],
        ["'.'x30 leader", '.'.repeat(30)],
        ['x-redaction bar', 'x'.repeat(32)],
        ['X-redaction bar', 'X'.repeat(32)],
        ['dotted leader with spaces', '. '.repeat(20)],
      ] as Array<[string, string]>) {
        expect(isVisualFiller(value), label).toBe(true);
      }
    });

    it('keeps a real secret with filler glued to it, at ANY filler length', () => {
      // The fourth adversarial pass, CRITICAL. `isVisualFiller` originally
      // judged the filler SHARE of the whole value — the same whole-value
      // judgement `findCredibleWindowOffset` exists to avoid, and it failed at
      // the identical threshold: `'_'x361 + secret` is 90.02% underscores, so
      // the value was called a blank and the secret dropped, while `'_'x360 +
      // secret` was reported. Losing the finding RAISED the score by 26 points.
      //
      // The AST path had this exact test ("finds a secret glued to a filler run
      // of ANY length") and the SEM path had nothing in that direction, which is
      // why the same defect survived one path over. Mutation guard: any
      // share-based rule turns this red.
      const secret = drawFrom(B64, 40, 77);
      for (const n of [1, 40, 300, 360, 361, 400, 1000]) {
        expect(isVisualFiller('_'.repeat(n) + secret), `'_'x${n} before the secret`).toBe(false);
        expect(isVisualFiller(secret + '_'.repeat(n)), `'_'x${n} after the secret`).toBe(false);
        expect(isVisualFiller('_'.repeat(n) + secret + '-'.repeat(n)), `filler both sides, ${n}`).toBe(false);
      }
    });

    it('keeps a secret followed by a dashed trailing comment', () => {
      // The YAML/env value is the rest of the line, so an ordinary trailing
      // comment counted as part of the "secret" and pushed a share-based rule
      // over its threshold. This made the CRITICAL reachable without an
      // attacker, on an ordinary config file.
      expect(isVisualFiller(`Zq7Wn2Rt9Yb4Kd6Mf8Hj3 # ${'-'.repeat(240)}`)).toBe(false);
      expect(isVisualFiller(`${drawFrom(B64, 32, 5)}   # ${'='.repeat(80)}`)).toBe(false);
    });

    it('keeps a short password whose only filler is a SEPARATOR', () => {
      // Adversarial review, HIGH, against the rule that replaced the share:
      // counting non-filler characters with no notion of a run is strictly
      // stricter than the caller's 8-character length floor, so every 8-char
      // password carrying one separator went silent and the CLI rose 27 points
      // on a lost CRITICAL. Separators are part of the value; only a drawn RUN
      // is not.
      //
      // Pins MIN_DRAWN_RUN_CHARS (4 -> 1 makes these filler) and the upper side
      // of MIN_SECRET_CORE_CHARS (8 -> 9 makes these filler).
      for (const value of [
        'dev_pass', 'prod_key', 'db_pass1', 'admin_pw',
        'api.key1', 'pass-123', 'pw#12345', 'x=abcdef',
      ]) {
        expect(isVisualFiller(value), `${value} is a weak password, not a blank`).toBe(false);
      }
    });

    it('still rejects a blank whose only non-filler stretch is too short', () => {
      // The other side of the core rule: a blank with a stray mark or a short
      // word in it is still a blank.
      for (const [label, value] of [
        ['stray digit', '_'.repeat(46) + '1'],
        ['short word', '_'.repeat(20) + 'TODO' + '_'.repeat(20)],
        // Exactly one character under the floor, which pins its lower side:
        // MIN_SECRET_CORE_CHARS 8 -> 7 makes this a credential.
        ['seven-character word', '_'.repeat(20) + 'ABCDEFG' + '_'.repeat(20)],
        ['alternating', '_-'.repeat(30)],
      ] as Array<[string, string]>) {
        expect(isVisualFiller(value), label).toBe(true);
      }
    });

    it('keeps real values that merely contain punctuation', () => {
      for (const [label, value] of [
        ['a hyphenated passphrase', 'super-secret-jwt-key-2024'],
        ['a dotted config value', 'my.service.account.key.v2'],
        ['a UUID', '123e4567-e89b-12d3-a456-426614174000'],
        ['an anthropic key', 'sk-ant-api03-' + drawFrom(B64, 24, 19)],
        ['base64 with padding', drawFrom(B64, 42, 21) + '=='],
        ['a hex digest', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'],
      ] as Array<[string, string]>) {
        expect(isVisualFiller(value), label).toBe(false);
      }
    });
  });
});
