// Regression: the legacy OpenAI key shape is detected, and every shape the
// detector can find is also redacted before content reaches the NanoMind daemon.
//
// `opena2a scan` / `hackmyagent secure` returned 98/100 exit 0 on a source file
// holding a hardcoded legacy `sk-` key, while a byte-identical fixture using a
// `sk-proj-` key returned 69/100 exit 1. `scan` is the CI gate — the miss was
// shape-dependent silence on exactly what the command exists to catch.
//
// SCOPE. This release adds ONE detector shape: `sk-[a-zA-Z0-9]{48,}`. A first
// draft added eight, on the theory that the defect was drift from
// `VENDOR_PREFIX_ALTERNATIVES`; two adversarial rounds showed the expansion was
// itself the problem — a false-positive class on ordinary identifiers, and a
// quadratic scan introduced while trying to bound it. The rest are being
// re-added one at a time on `fix/credential-fp-siblings` (#352/#353).
//
// The invariant between the two lists is COVERAGE, not equality: the redactor
// must strip everything the detector can find, and may strip more. A shape
// detected but not redacted means the scanner proves a secret is real and then
// forwards it — strictly worse than not detecting it. The reverse costs only a
// mangled token in an advisory prompt, so the redactor keeps the wider list.
//
// Every value below is synthetic, generated from a fixed non-secret alphabet.
// None is or ever was a live credential.

import { describe, it, expect } from 'vitest';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { redactSecretsForNanoMind } from '../../src/nanomind-core/security/defense-in-depth';
import {
  scanCanonicalCredentialFormatsForTest,
  canonicalCredentialLabelsForTest,
  analyzeCredentialKeywordContext,
} from '../../src/nanomind-core/compiler/semantic-compiler';
import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import { tempDir } from '../helpers/temp-dir';

/** Synthetic filler: alphanumeric, no placeholder markers the FP filters strip. */
const fill = (n: number) => 'Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4Yz5Ab6Cd7Ef8Gh9Ij0Kl1Mn2Op3'.repeat(3).slice(0, n);

/** Shapes the detector reports. Must ALSO be redacted. */
const SHAPES: Array<{ label: string; value: string }> = [
  { label: 'OpenAI legacy key', value: `sk-${fill(48)}` },
  { label: 'OpenAI project key', value: `sk-proj-${fill(48)}` },
  { label: 'Anthropic API key', value: `sk-ant-api03-${fill(40)}` },
  // Composed, never written literally: an `AKIA` + 16 upper-alnum literal in a
  // committed file is the shape GitHub push protection blocks on, and this file
  // would be pushed to a public repo. See
  // reference_github_push_protection_secret_fixtures.
  { label: 'AWS access key', value: 'AKIA' + 'ABCDEFGHIJKLMNOP' },
  { label: 'GitHub personal access token', value: `ghp_${fill(36)}` },
  { label: 'GitHub OAuth token', value: `gho_${fill(36)}` },
  { label: 'GitHub app token', value: `ghs_${fill(36)}` },
  { label: 'Stripe live key', value: `sk_live_${fill(24)}` },
  { label: 'Google API key', value: `AIza${fill(35)}` },
  { label: 'Slack bot token', value: `xoxb-${fill(12)}-${fill(12)}-${fill(24)}` },
  // Both were redact-only until #543. Each was invisible to `secure` unless a
  // credential noun sat within reach of the value; see the block at the end.
  { label: 'Hugging Face token', value: `hf_${fill(34)}` },
  { label: 'GitLab personal access token', value: `glpat-${fill(20)}` },
  // From NAME_GATED_CREDENTIAL_PATTERNS, the detector's SECOND list. It was
  // invisible to the coverage assertion below while that derived its expected
  // set from the canonical list alone — so this shape was detected, never
  // redacted, and rendered 33 of its 40 characters into user-facing output.
  // The name anchor is part of the shape: the value alone is just base64.
  { label: 'AWS secret access key', value: `aws_secret_access_key = ${fill(40)}` },
  // A complete block. The header-only case — detector fires on `-----BEGIN …
  // KEY-----` alone, redactor requires the closing marker — is a KNOWN GAP,
  // carved out of the coverage assertion below rather than papered over. See
  // that carve-out for why the obvious fix was reverted.
  {
    label: 'PEM private key',
    value: `-----BEGIN RSA PRIVATE KEY-----${fill(40)}-----END RSA PRIVATE KEY-----`,
  },
];

/**
 * Shapes the REDACTOR covers but the detector deliberately does not.
 *
 * Redaction is defence-in-depth on the daemon boundary and carries no verdict
 * risk, so it keeps the wider list while the detector is held to the one shape
 * this release fixes. These must never appear in the detector without a bounded
 * pattern and a ReDoS measurement — that is what #352/#353 are for.
 */
const REDACT_ONLY: Array<{ label: string; value: string }> = [
  { label: 'GitHub user-to-server token', value: `ghu_${fill(36)}` },
  { label: 'GitHub fine-grained token', value: `github_pat_${fill(22)}_${fill(59)}` },
  { label: 'npm access token', value: `npm_${fill(36)}` },
  { label: 'Stripe test key', value: `sk_test_${fill(24)}` },
  { label: 'SendGrid API key', value: `SG.${fill(22)}.${fill(43)}` },
];

/**
 * Shapes the detector reports and the redactor does NOT yet strip: a KNOWN GAP,
 * recorded here instead of hidden.
 *
 * #316 added the 32-47 character `sk-` band to the detector. The redactor's
 * `openai-key` rule still floors at 48, so on the daemon path a key in this
 * band is detected and forwarded verbatim. The finding itself never quotes the
 * key (`OpenAI-style sk- key: [REDACTED]`). The last test in the block below
 * pins the gap so that closing it goes red and moves this entry into `SHAPES`.
 */
const DETECTED_NOT_YET_REDACTED: Array<{ label: string; value: string }> = [
  { label: 'OpenAI-style sk- key', value: `sk-${fill(32)}` },
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
    for (const { label, value } of [...SHAPES, ...DETECTED_NOT_YET_REDACTED]) {
      it(`${label} produces a credential hit`, () => {
        const hits = scanCanonicalCredentialFormatsForTest(asSource(value));
        expect(hits.length).toBeGreaterThan(0);
        expect(hits.map(h => h.label)).toContain(label);
      });
    }
  });

  describe('redaction', () => {
    for (const { label, value } of [...SHAPES, ...REDACT_ONLY]) {
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

  it('two adjacent tokens are both redacted', () => {
    // The redactor is deliberately unanchored. Anchoring it made
    // `ghp_<36>ghp_<36>` redact the first and leave the SECOND verbatim in
    // daemon-bound content, because the replacement consumed the boundary the
    // next match needed. Concatenated tokens are narrow but the direction of
    // the failure is the one that leaks.
    for (const width36 of ['ghp_', 'gho_', 'ghs_', 'ghu_', 'npm_']) {
      const pair = `${width36}${fill(36)}${width36}${fill(36)}`;
      const redacted = redactSecretsForNanoMind(asProse(pair));
      expect(redacted, `${width36} pair leaked a token`).not.toMatch(
        new RegExp(`${width36}[A-Za-z0-9]{36}`),
      );
    }
  });

  it('the redactor covers everything the detector can find', () => {
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
    // `canonicalCredentialLabelsForTest` now returns BOTH detector lists —
    // the canonical one AND the name-gated one. Deriving the expected set from
    // a single list is what made the AWS secret access key invisible here
    // while it was detected and rendered into user-facing output.
    //
    // `PEM private key` stays carved out, and the carve-out is the honest
    // record of a real gap rather than a convenience: the detector fires on a
    // `-----BEGIN … KEY-----` header alone, the redactor needs the closing
    // marker, so a truncated block is detected and left verbatim. Redacting
    // from the header to end of line closes it and was reverted — it ate the
    // prose after the header, destroying the test/doc-context words the
    // credential analyzer reads and flipping a scan 98/exit-0 -> 69/exit-1.
    // A rule bounded to the key material would let this carve-out go.
    const covered = new Set([...SHAPES, ...DETECTED_NOT_YET_REDACTED].map(s => s.label));
    const known = new Set(canonicalCredentialLabelsForTest());
    const uncovered = [...known].filter(l => !covered.has(l) && l !== 'PEM private key');
    expect(uncovered).toEqual([]);
  });

  it('KNOWN GAP (#316): the detected-not-yet-redacted shapes are still exactly that', () => {
    // When the redactor learns a shape listed here, this goes red. Move the
    // entry into `SHAPES`, where the coverage invariant then holds it.
    for (const { label, value } of DETECTED_NOT_YET_REDACTED) {
      expect(scanCanonicalCredentialFormatsForTest(asSource(value)).map(h => h.label)).toContain(label);
      expect(redactSecretsForNanoMind(asProse(value)), `${label} is now redacted`).toContain(value);
    }
  });
});

// #543. A bare `hf_` or `glpat-` value scored 98/100 exit 0 under `secure`
// while a file of the same shape holding an AWS access key scored 69/100 exit 1.
// The two shapes were in the shared vocabulary but not in the canonical list,
// so they reached a finding only when a credential noun (`token`, `secret`, …)
// sat within reach of the value. The carrier below names no credential at all,
// which is the case that was silent.
describe('#543: hf_ and glpat- fire like the AWS access key control, with no credential noun nearby', () => {
  /** One assignment, no credential noun anywhere in the file. */
  const alone = (value: string) => `VALUE_A = "${value}"\n`;

  /** Failing finding IDs with severities from the real semantic pipeline. */
  async function failingFindings(content: string): Promise<string[]> {
    const dir = tempDir('hma-543-');
    await writeFile(join(dir, 'app.py'), content, 'utf-8');
    const result = await runNanoMindScan(dir, []);
    return result.mergedFindings
      .filter(f => !f.passed)
      .map(f => `${f.checkId}:${f.severity}`)
      .sort();
  }

  const AWS_CONTROL = 'AKIA' + 'ABCDEFGHIJKLMNOP';

  for (const { label, value } of [
    { label: 'Hugging Face token', value: `hf_${fill(34)}` },
    { label: 'GitLab personal access token', value: `glpat-${fill(20)}` },
  ]) {
    it(`${label} alone gets the same check IDs and severities as the AWS access key`, async () => {
      const control = await failingFindings(alone(AWS_CONTROL));
      // Without this, two empty lists would compare equal and prove nothing.
      expect(control, 'the AWS control produced no credential finding').toContain('AST-CRED-003:critical');

      expect(scanCanonicalCredentialFormatsForTest(alone(value)).map(h => h.label)).toEqual([label]);
      expect(await failingFindings(alone(value))).toEqual(control);
    }, 120_000);
  }

  describe('identifiers that share the prefix are not credentials', () => {
    const notCredentials: Array<[string, string]> = [
      [
        'the hf_hub_download helper',
        'from huggingface_hub import hf_hub_download\n'
          + 'path = hf_hub_download(repo_id="org/model", filename="config.json")\n',
      ],
      ['hf_ plus 33 alphanumerics', alone(`hf_${fill(33)}`)],
      ['a hyphenated GitLab runner slug', alone('glpat-' + 'shared-linux-docker-runner-1')],
      ['glpat- plus 20 lower-case x', alone('glpat-' + 'x'.repeat(20))],
      ['glpat- plus 20 upper-case X', alone('glpat-' + 'X'.repeat(20))],
    ];
    for (const [name, content] of notCredentials) {
      it(`${name} produces no finding`, async () => {
        expect(scanCanonicalCredentialFormatsForTest(content)).toEqual([]);
        expect(await failingFindings(content)).toEqual([]);
      }, 120_000);
    }
  });

  it('the case-mix check does not let a rejected match hide a real token after it', () => {
    const content = alone('glpat-' + 'shared-linux-docker-runner-1') + alone(`glpat-${fill(20)}`);
    expect(scanCanonicalCredentialFormatsForTest(content).map(h => h.label))
      .toEqual(['GitLab personal access token']);
    // The keyword-context path reads the same list through its own loop.
    expect(analyzeCredentialKeywordContext(`{"token": null}\n${content}`)).toBe('value-present');
    expect(analyzeCredentialKeywordContext(`{"token": null}\n${alone('glpat-' + 'x'.repeat(20))}`))
      .toBe('schema-only');
  });

  it('480 KB of hostile glpat- and hyphen input scans in under one second', () => {
    // The lookahead this shape was once held out with re-read the run from every
    // start position: 1 ms -> 40 s at 480 KB. Each input below is a single run the
    // body class admits, which is the input that made it quadratic.
    const size = 480 * 1000;
    const hostile = [
      'glpat-'.repeat(size / 6),
      'glpat-' + '-'.repeat(size - 6),
      'glpat--'.repeat(Math.ceil(size / 7)).slice(0, size),
    ];
    for (const content of hostile) {
      expect(content.length).toBe(size);
      const started = performance.now();
      const hits = scanCanonicalCredentialFormatsForTest(content);
      analyzeCredentialKeywordContext(content);
      const elapsed = performance.now() - started;
      expect(hits).toEqual([]);
      expect(elapsed, `scan took ${Math.round(elapsed)} ms`).toBeLessThan(1000);
    }
  });
});
