// Regression: every credential shape the scanner DETECTS is also REDACTED, and
// the legacy OpenAI shape is one of them.
//
// `opena2a scan` / `hackmyagent secure` returned 98/100 exit 0 on a source file
// holding a hardcoded legacy `sk-` key, while a byte-identical fixture using a
// `sk-proj-` key returned 69/100 exit 1. `scan` is the CI gate — the miss was
// shape-dependent silence on exactly what the command exists to catch.
//
// Root cause was list drift: `CANONICAL_CREDENTIAL_PATTERNS` (the verdict path)
// had fallen eight shapes behind `VENDOR_PREFIX_ALTERNATIVES`, the module that
// declares itself the single source of truth. Fixing only `sk-` would have left
// the other seven.
//
// Two properties are pinned, and they pull in opposite directions on purpose:
//   - DETECTION: each shape produces a credential hit (a false negative here is
//     a silent CI pass on a committed key).
//   - REDACTION: each shape is stripped before content reaches the NanoMind
//     daemon (a gap here means the scanner proves a secret is real and then
//     forwards it — strictly worse than not detecting it).
//
// Every value below is synthetic, generated from a fixed non-secret alphabet.
// None is or ever was a live credential.

import { describe, it, expect } from 'vitest';
import { redactSecretsForNanoMind } from '../../src/nanomind-core/security/defense-in-depth';
import {
  scanCanonicalCredentialFormatsForTest,
  canonicalCredentialLabelsForTest,
} from '../../src/nanomind-core/compiler/semantic-compiler';

/** Synthetic filler: alphanumeric, no placeholder markers the FP filters strip. */
const fill = (n: number) => 'Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4Yz5Ab6Cd7Ef8Gh9Ij0Kl1Mn2Op3'.repeat(3).slice(0, n);

const SHAPES: Array<{ label: string; value: string }> = [
  { label: 'OpenAI legacy key', value: `sk-${fill(48)}` },
  { label: 'OpenAI project key', value: `sk-proj-${fill(48)}` },
  { label: 'Anthropic API key', value: `sk-ant-api03-${fill(40)}` },
  // Composed, never written literally: an `AKIA` + 16 upper-alnum literal in a
  // committed file is the shape GitHub push protection blocks on, and this file
  // would be pushed to a public repo. Every other value here is composed for the
  // same reason. See reference_github_push_protection_secret_fixtures.
  { label: 'AWS access key', value: 'AKIA' + 'ABCDEFGHIJKLMNOP' },
  { label: 'GitHub personal access token', value: `ghp_${fill(36)}` },
  { label: 'GitHub OAuth token', value: `gho_${fill(36)}` },
  { label: 'GitHub app token', value: `ghs_${fill(36)}` },
  { label: 'GitHub user-to-server token', value: `ghu_${fill(36)}` },
  { label: 'GitHub fine-grained token', value: `github_pat_${fill(22)}_${fill(59)}` },
  { label: 'GitLab personal access token', value: `glpat-${fill(20)}` },
  { label: 'HuggingFace token', value: `hf_${fill(34)}` },
  { label: 'npm access token', value: `npm_${fill(36)}` },
  { label: 'Stripe live key', value: `sk_live_${fill(24)}` },
  { label: 'Stripe test key', value: `sk_test_${fill(24)}` },
  { label: 'SendGrid API key', value: `SG.${fill(22)}.${fill(43)}` },
  { label: 'Google API key', value: `AIza${fill(35)}` },
  { label: 'Slack bot token', value: `xoxb-${fill(12)}-${fill(12)}-${fill(24)}` },
];

/** Realistic carrier: a source line, which is the context `scan` reads. */
const asSource = (value: string) => `const client = new Client({ apiKey: "${value}" });\n`;

/**
 * Carrier with NO credential-ish variable name and no quotes.
 *
 * The redactor has a generic `(?:password|secret|token|key)\s*[=:]\s*"…"` rule
 * that fires on `apiKey: "…"` and rewrites the whole assignment. Testing
 * redaction through `asSource` therefore passes whether or not the shape rules
 * exist — the generic rule covers it either way. This carrier is the case the
 * generic rule CANNOT reach, so a failure here means the shape rule is missing.
 */
const asProse = (value: string) => `Deployment note: pass ${value} to the uploader before running it.\n`;

describe('credential shapes: detected and redacted, never one without the other', () => {
  describe('detection', () => {
    for (const { label, value } of SHAPES) {
      it(`${label} produces a credential hit`, () => {
        const hits = scanCanonicalCredentialFormatsForTest(asSource(value));
        expect(hits.length).toBeGreaterThan(0);
        expect(hits.map(h => h.label)).toContain(label);
      });
    }
  });

  describe('redaction', () => {
    for (const { label, value } of SHAPES) {
      it(`${label} never survives into daemon-bound content`, () => {
        // Both carriers: the assignment form AND the form the generic
        // name-based rule cannot see.
        expect(redactSecretsForNanoMind(asSource(value))).not.toContain(value);
        const redacted = redactSecretsForNanoMind(asProse(value));
        expect(redacted).not.toContain(value);
        // Replaced by a shape-specific marker, not merely deleted — and a
        // bare `[REDACTED]` from the generic rule does not satisfy this.
        expect(redacted).toMatch(/\[REDACTED_[A-Z]/);
      });
    }
  });

  it('the two lists agree: nothing is detectable but unredactable', () => {
    // The failure this catches is asymmetric drift — a shape added to the
    // detector alone, which makes the scanner forward a secret it has just
    // confirmed is real.
    const detectableButNotRedacted = SHAPES.filter(({ value }) => {
      const detected = scanCanonicalCredentialFormatsForTest(asSource(value)).length > 0;
      // Probe redaction through the carrier the generic rule cannot cover, so a
      // shape covered ONLY by the generic rule still counts as unredacted here.
      const survives = redactSecretsForNanoMind(asProse(value)).includes(value);
      return detected && survives;
    });
    expect(detectableButNotRedacted.map(s => s.label)).toEqual([]);
  });

  it('the legacy rule does not swallow its prefixed siblings', () => {
    // `sk-proj-` and `sk-ant-api` must keep their own labels. If the legacy
    // class ever gains `-` or `_`, this is what goes red — a project key
    // reported as a legacy key is a wrong finding, not a near-miss.
    const proj = scanCanonicalCredentialFormatsForTest(asSource(`sk-proj-${fill(48)}`));
    expect(proj.map(h => h.label)).toContain('OpenAI project key');
    expect(proj.map(h => h.label)).not.toContain('OpenAI legacy key');

    const ant = scanCanonicalCredentialFormatsForTest(asSource(`sk-ant-api03-${fill(40)}`));
    expect(ant.map(h => h.label)).toContain('Anthropic API key');
    expect(ant.map(h => h.label)).not.toContain('OpenAI legacy key');
  });

  it('short sk- identifiers are not credentials', () => {
    // FP guard on the widened rule. A hyphenated identifier that merely starts
    // with `sk-` must not become a finding.
    const benign = 'const skill = "sk-basic-tool";\nconst mode = "sk-fast";\n';
    const labels = scanCanonicalCredentialFormatsForTest(benign).map(h => h.label);
    expect(labels).not.toContain('OpenAI legacy key');
  });

  describe('a vendor prefix glued to an identifier tail is not that vendor key', () => {
    // The regression that shipped in the first draft of this change: the shapes
    // were copied from `credential-format.ts` WITHOUT its left anchor, so any
    // word ending `sk` + `-` + 48 alphanumerics matched. A sha256 is 64 hex
    // characters, which is how `disk-<hash>` in ordinary infrastructure code
    // became CRITICAL "Hardcoded Secret Detected" with exit 1.
    const SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const notCredentials: Array<[string, string]> = [
      ['disk id', `primary: "disk-${SHA256}",`],
      ['task id', `const id = "task-${SHA256}";`],
      ['mask id', `mask-${SHA256}`],
      ['risk id', `risk-${SHA256}`],
      // `MSG.` contains `SG.` — the exact string credential-format.ts records as
      // having been positively identified as a credential once already.
      ['dotted namespace', 'const topic = MSG.INCIDENT_ESCALATION_QU.HIGH_PRIORITY_ROUTE_FOR_ONCALL_TEAM_ALPHA_9;'],
      ['hyphenated glpat identifier', 'const runner = "glpat-internal-runner-config-name";'],
    ];
    for (const [name, content] of notCredentials) {
      it(`${name} produces no credential finding`, () => {
        expect(scanCanonicalCredentialFormatsForTest(content)).toEqual([]);
      });
    }

    it('the anchor does not drop a real key glued to underscore filler', () => {
      // The reason the anchor is `(?<![A-Za-z0-9])` and not `\b`: `\b` treats
      // `_` as a word character, so a key following form-blank filler would
      // have no boundary and be silently dropped.
      const content = `${'_'.repeat(38)}sk-${fill(48)}`;
      expect(scanCanonicalCredentialFormatsForTest(content).map(h => h.label))
        .toContain('OpenAI legacy key');
    });
  });

  it('every shape the detector knows is covered by this file', () => {
    // The drift this whole change exists to fix can recur silently if the test
    // keeps its own hand-maintained list. Deriving the expected set from the
    // detector means a newly added shape with no case here fails by
    // construction rather than passing unnoticed.
    const covered = new Set(SHAPES.map(s => s.label));
    const known = new Set(canonicalCredentialLabelsForTest());
    const uncovered = [...known].filter(l => !covered.has(l) && l !== 'PEM private key');
    expect(uncovered).toEqual([]);
  });
});
