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
  matchVendorPrefix,
} from '../../src/types/credential-format';

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
      ['GitHub PAT', GITHUB_PAT_FIXTURE],
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
      const key = GITHUB_PAT_FIXTURE;
      for (let i = 0; i < 5; i++) {
        expect(isAcceptedCredentialMatch(key), `call ${i + 1}`).toBe(true);
      }
    });

    it('does not let one candidate affect the next', () => {
      const vendor = GITHUB_PAT_FIXTURE;
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
      expect(isAcceptedCredentialMatch(drawFrom('ACGT', 64, 7)), '64 chars over 4 symbols = 128 bits').toBe(true);
      expect(isAcceptedCredentialMatch(drawFrom('ACGT', 40, 99)), '40 chars over 4 symbols = 80 bits').toBe(true);
      expect(isAcceptedCredentialMatch(drawFrom('01', 64, 5)), '64 chars over 2 symbols = 64 bits').toBe(true);
      expect(isAcceptedCredentialMatch(drawFrom('0123456789abcdef', 40, 11)), 'hex').toBe(true);
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

  describe('a vendor prefix must not be glued to an alphanumeric identifier', () => {
    // The vendor-list unification put `SG.` into the DETECTION path, unanchored,
    // and re-created the very false-positive class this unit exists to remove:
    // ordinary dotted identifiers were positively identified as credentials.
    it('does not fire on a message-bus constant whose namespace ends in SG', () => {
      expect(hasCredentialFormat('MSG.INCIDENT_ESCALATION_QUEUE')).toBe(false);
    });

    it('does not fire on a C# using directive for an SG namespace', () => {
      expect(hasCredentialFormat('using SG.Configuration_Providers_Internal;')).toBe(false);
    });

    it('still fires on a real SendGrid key, which carries BOTH dots', () => {
      // `SG.<key id>.<secret>`. The second segment is what makes it a key
      // rather than a namespace, and is what the tightened pattern requires.
      expect(hasCredentialFormat('SG.aBcDeFgHiJkLmNoPqRsTuv.wXyZ0123456789abcdefghijklmnopqrstu')).toBe(true);
    });

    it('does not fire on a vendor prefix continuing an identifier', () => {
      expect(hasCredentialFormat('MYghp_' + 'a'.repeat(20)), 'ghp_ glued to letters').toBe(false);
      expect(hasCredentialFormat('xAKIAIOSFODNN7EXAMPLE'), 'AKIA glued to a letter').toBe(false);
    });

    it('STILL fires on a credential glued to underscore filler', () => {
      // The anchor is `(?<![A-Za-z0-9])`, deliberately NOT `\b`. `\b` counts `_`
      // as a word character, so it would drop a real key glued to a form blank —
      // the exact document shape this unit is about. Mutation guard: swapping the
      // anchor for `\b` turns these red.
      expect(hasCredentialFormat('_'.repeat(38) + 'sk-ant-api03-R3alK3yV4lu3W1thEntropy0')).toBe(true);
      expect(hasCredentialFormat('_'.repeat(47) + 'AKIAIOSFODNN7EXAMPLE')).toBe(true);
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
        ['SG.aBcDeFgHiJkLmNoPqRsTuv.wXyZ0123456789abcdefghijklmnopqrstu', 'SG.'],
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
  });

  describe('the scan is bounded against adversarial filler', () => {
    // Continuing past a rejected candidate removed main's early exit and
    // exposed the JWT alternative's backtracking: the greedy segment class
    // contains `-`, so on `eyJ-eyJ-…` filler it ran to end-of-file at every one
    // of the O(n) `eyJ` offsets. Measured before the bound: 58 ms at 16 KB,
    // 808 ms at 64 KB, 13.5 s at 256 KB, ~215 s at the 1 MB scanner cap, while
    // `origin/main` was 0.0 ms at every size.
    it('scans a 1 MB dot-free JWT-filler file in well under a second', () => {
      const payload = '_'.repeat(47) + '-' + 'eyJ-'.repeat((1024 * 1024) / 4);
      const started = performance.now();
      expect(hasCredentialFormat(payload)).toBe(false);
      const elapsed = performance.now() - started;
      // Measured ~106 ms. The bound is what makes this linear; a regression
      // here is quadratic, so it blows past 2 s by orders of magnitude rather
      // than drifting past it.
      expect(elapsed, `1 MB adversarial scan took ${elapsed.toFixed(0)} ms`).toBeLessThan(2000);
    });

    it('scans a 1 MB file of OVERLAPPING large rejected candidates in well under a second', () => {
      // A second, worse quadratic than the JWT one, and reachable with no `eyJ`
      // in the file at all. `+` and `=` sit inside the blob class
      // `[A-Za-z0-9+=_]` but are NON-word characters, so every `=` is an
      // interior `\b` that starts a fresh candidate running to end-of-file.
      // With the walk resuming one character past each rejected candidate, the
      // engine re-scanned almost the whole file per `=`. Measured before the
      // budget: 135 ms at 16 KB, 2.0 s at 64 KB, 32 s at 256 KB.
      const payload = ('a'.repeat(40) + '=').repeat(Math.floor((1024 * 1024) / 41));
      const started = performance.now();
      expect(hasCredentialFormat(payload)).toBe(false);
      const elapsed = performance.now() - started;
      expect(elapsed, `1 MB overlapping-candidate scan took ${elapsed.toFixed(0)} ms`).toBeLessThan(2000);
    });

    it('finds a real key buried behind a megabyte of that same filler', () => {
      // The budget must not become a detection hole. The vendor pass runs to
      // completion before the bounded blob walk, so a real key stays findable
      // no matter how much filler precedes it.
      const filler = ('a'.repeat(40) + '=').repeat(Math.floor((1024 * 1024) / 41));
      const key = 'sk-ant-api03-R3alK3yV4lu3W1thEntropy0';
      expect(hasCredentialFormat(`${filler}\n${key}\n`), 'key after 1 MB of filler').toBe(true);
      expect(findCredentialFormatMatch(`${filler}\n${key}\n`)?.value).toBe(key);
    });

    it('scans a 1 MB file of rejected filler runs in well under a second', () => {
      const payload = ('_'.repeat(47) + '\n').repeat((1024 * 1024) / 48);
      const started = performance.now();
      expect(hasCredentialFormat(payload)).toBe(false);
      const elapsed = performance.now() - started;
      expect(elapsed, `1 MB filler-run scan took ${elapsed.toFixed(0)} ms`).toBeLessThan(2000);
    });

    it('still finds a real JWT, which the bounded segments must not break', () => {
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
      // Real SendGrid shape: `SG.<key id>.<secret>`. Written with one dot it
      // also matched any dotted identifier ending in `SG`, so the pattern now
      // requires the second segment.
      ['SendGrid', 'SG.' + 'a'.repeat(22) + '.' + 'b'.repeat(43)],
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
      // Guards the VENDOR pre-pass: the greedy blob absorbs `'_'x38 + 'sk'` into
      // one 40-character candidate, so a single-pass scan reports the filler run
      // (or, once the dominance rule rejects it, nothing at all). Mutation
      // guard: removing the vendor pre-pass turns this red.
      const key = 'sk-ant-api03-R3alK3yV4lu3W1thEntropy0';
      const hit = findCredentialFormatMatch('_'.repeat(38) + key);
      expect(hit?.value, 'the match must be the key itself').toBe(key);
      expect(hit?.index, 'and it must be reported at the key offset').toBe(38);
    });

    it('finds an ANONYMOUS blob that filler hides in the same run', () => {
      // The direct, non-vacuous guard on `blobRe.lastIndex = m.index + 1`.
      //
      // The vendor pre-pass cannot cover this one: the secret has no vendor
      // prefix. The case is reachable because `+` and `=` sit inside the blob
      // class `[A-Za-z0-9+=_]` but are NON-word characters, so they are
      // interior `\b` positions. Here the whole 441-character run is a single
      // candidate and is filler — underscores are 90.7% of it, just over the
      // dominance threshold — while the secret after the `=` is a second
      // candidate that only the resume reaches. Advancing to the end of the
      // rejected run instead loses it entirely.
      //
      // Under the earlier "distinct >= 2" floor this line was provably inert,
      // which is what the finding recorded. It is load-bearing now.
      const secret = drawFrom('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 40, 77);
      const run = '_'.repeat(400) + '=' + secret;
      expect(isCredibleEntropyBlob(run), 'precondition: the whole run must be filler').toBe(false);
      const hit = findCredentialFormatMatch(run);
      expect(hit, 'a high-entropy secret must not be hidden by the filler around it').toBeDefined();
      expect(hit!.value, 'the reported match must carry the secret').toContain(secret);
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
  });
});
