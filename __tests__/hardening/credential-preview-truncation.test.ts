/**
 * The detector must not hand the boundary a value it has already truncated.
 *
 * The redaction boundary (`emitFinding` -> `redactSecretsForReportReporting`) matches
 * FULL-LENGTH credential shapes. A producer that renders a shortened preview of a secret
 * — `matched.slice(0, 16)`, `value.slice(0, 8)`, `value.slice(0, 5) + '****'` — emits a
 * string the boundary's patterns cannot match. The fragment therefore crosses untouched
 * AND is stamped `redactionStatus: 'clean'`, `redactedShapes: []`, which is a false
 * certificate of cleanliness rather than a missing one.
 *
 * Measured 2026-08-19 on `1dac1e1`, before this file existed: `secure --json` carried 16
 * body characters at 4 JSON paths, `check --json` at 2, and a 5-character preview reached
 * `findings[].description` — all three unchanged from 0.31.0, all three required to be 0
 * by `todo/roadmap/hma-unit1-credential-boundary.md:227-236`.
 *
 * WHY THIS TEST IS SHAPED THIS WAY. `pinned-credential-shapes.test.ts` already pins that
 * the detector and the redactor know the same SHAPES. That invariant was green throughout,
 * because it compares two lists of patterns and never asks what string the producer
 * actually emits. The distinction this file adds is between "the redactor could redact
 * this secret" and "the redactor was handed something it can redact". Only the second one
 * keeps body bytes out of the JSON.
 *
 * The secrets below are synthetic, high-entropy and contain no dictionary word, so a
 * >= 5-character match against output cannot be ordinary English in remediation text. They
 * deliberately avoid the `FAKE`/`EXAMPLE`/`TEST`/`XXX` markers, because those are exactly
 * what the detector's fixture filter suppresses — a canary carrying one measures nothing.
 */

import { describe, it, expect } from 'vitest';
import {
  scanCanonicalCredentialFormatsForTest,
  canonicalCredentialLabelsForTest,
} from '../../src/nanomind-core/compiler/semantic-compiler.js';
import { CredentialContextAnalyzer } from '../../src/semantic/structural/credential-context.js';
import type { AnalysisFile } from '../../src/semantic/types.js';

/** Longest contiguous run of `secret` that appears anywhere in `haystack`. */
function longestRun(haystack: string, secret: string, min = 5): string {
  let best = '';
  for (let i = 0; i < secret.length; i++) {
    for (let n = secret.length - i; n >= min; n--) {
      const frag = secret.substr(i, n);
      if (frag.length <= best.length) break;
      if (haystack.includes(frag)) {
        best = frag;
        break;
      }
    }
  }
  return best;
}

/** Every string leaf of a value, so a new field cannot quietly become a leak path. */
function stringLeaves(node: unknown, path = '$', out: Array<[string, string]> = []): Array<[string, string]> {
  if (typeof node === 'string') out.push([path, node]);
  else if (Array.isArray(node)) node.forEach((v, i) => stringLeaves(v, `${path}[${i}]`, out));
  else if (node && typeof node === 'object') {
    for (const k of Object.keys(node as Record<string, unknown>)) {
      stringLeaves((node as Record<string, unknown>)[k], `${path}.${k}`, out);
    }
  }
  return out;
}

function assertNoBodyBytes(subject: unknown, secret: string, what: string): void {
  for (const [path, leaf] of stringLeaves(subject)) {
    const run = longestRun(leaf, secret);
    expect(
      run,
      `${what}: ${path} carries ${run.length} body characters of the secret (${JSON.stringify(run)})`,
    ).toBe('');
  }
}

// High-entropy, dictionary-free, no fixture marker.
const CORE = 'Zq7Xv2Kp9Wm4Rt6Yn8Bd3Fh5Jl1Gs0Cx7Vz4Nq2Mw6Tr8Kp3Xy9Ld5Hb2Jn';
const SECRETS = {
  anthropic: `sk-ant-api03-${CORE}`,
  openai: `sk-proj-${CORE}`,
  // Exactly 36 alphanumerics after the prefix — `ghp_[a-zA-Z0-9]{36}`. A 35-character
  // canary is not detected, and its leak assertion then passes vacuously; the positive
  // control above is what caught that while this file was being written.
  github: 'ghp_' + 'Qz8Wn3Kv6Rt1Yp9Bd4Fh7Jl2Gs5Cx0Vz6NqP',
  aws: 'AKIA' + 'QZ8WN3KV6RT1YP9B',
  urlPassword: 'Wm4Rt6Yn8BdZq7Xv2Kp9',
  jwt: 'Xv2Kp9Wm4Rt6Yn8Bd3Fh5Jl1Gs0Cx7Vz',
};

describe('canonical credential detector: evidence carries classification, never body bytes', () => {
  const cases: Array<[string, string]> = [
    ['anthropic', SECRETS.anthropic],
    ['openai', SECRETS.openai],
    ['github', SECRETS.github],
    ['aws', SECRETS.aws],
  ];

  for (const [name, secret] of cases) {
    it(`${name}: detects the secret at all (positive control)`, () => {
      const hits = scanCanonicalCredentialFormatsForTest(`const k = "${secret}";`);
      // Without this, the body-byte assertion below would pass on a detector that
      // simply stopped detecting, which is the failure mode a redaction test invites.
      expect(hits.length, 'detector produced no hit; the leak assertion would be vacuous').toBeGreaterThan(0);
    });

    it(`${name}: emits zero body bytes into evidence`, () => {
      const hits = scanCanonicalCredentialFormatsForTest(`const k = "${secret}";`);
      assertNoBodyBytes(hits, secret, `canonical detector (${name})`);
    });

    it(`${name}: still names the credential type, so the user keeps the classification`, () => {
      const hits = scanCanonicalCredentialFormatsForTest(`const k = "${secret}";`);
      const labels = canonicalCredentialLabelsForTest();
      for (const hit of hits) {
        expect(labels).toContain(hit.label);
        expect(hit.evidence, 'evidence dropped its label along with the body').toContain(hit.label);
      }
    });
  }

  it('name-gated patterns (the slice(0, 8) path) emit zero body bytes', () => {
    // The name-gated arm is a SEPARATE producer with its own truncation. A test that
    // only exercised the canonical arm would leave it uncovered, which is the exact
    // shape of the drift `canonicalCredentialLabelsForTest` was widened to prevent.
    const content = [
      `aws_secret_access_key = "${SECRETS.urlPassword}Kp9Wm4Rt6Yn8Bd3Fh5Jl1Gs0"`,
      `jwt_secret = "${SECRETS.jwt}"`,
    ].join('\n');
    const hits = scanCanonicalCredentialFormatsForTest(content);
    for (const secret of [SECRETS.jwt, SECRETS.urlPassword]) {
      assertNoBodyBytes(hits, secret, 'name-gated detector');
    }
  });
});

describe('maskCredentialValue: a constant prefix is classification, a slice of the value is not', () => {
  // This distinction is the whole point and it is easy to get backwards. `sk-ant-api0` is
  // IDENTICAL for every Anthropic key, so emitting it reveals the vendor and nothing about
  // this secret — PC-6' permits classification, and `benign-fp-regression.test.ts` pins it
  // ("evidence must preserve the recognizable prefix"). `value.slice(0, 8)` on an
  // UNRECOGNISED secret has no such property: those 8 characters are the secret itself.

  it('a vendor-shaped credential keeps its constant prefix and nothing after it', async () => {
    const { analyzeCredentials } = await import('../../src/nanomind-core/analyzers/credential-analyzer.js');
    const { SemanticCompiler } = await import('../../src/nanomind-core/compiler/semantic-compiler.js');
    const yaml = `name: agent-config\ndescription: stores credentials for the bot\nservice:\n  apiToken: ${SECRETS.anthropic}\n`;
    const compiler = new SemanticCompiler({ useNanoMind: false });
    const result = await compiler.compile(yaml, 'agent-config.yaml');
    const findings = analyzeCredentials(result.ast, ast => compiler.verifyAST(ast), undefined, yaml);

    const withEvidence = findings.filter(f => typeof f.evidence === 'string' && f.evidence.length > 0);
    expect(withEvidence.length, 'detection precondition').toBeGreaterThan(0);
    for (const f of withEvidence) {
      // Nothing of the BODY — the characters after the constant vendor prefix.
      assertNoBodyBytes(f.evidence, SECRETS.anthropic.slice('sk-ant-api0'.length), 'vendor-shaped mask');
    }
  });

  it('an UNRECOGNISED secret is masked entirely — no 8-character prefix of the value', async () => {
    const { analyzeCredentials } = await import('../../src/nanomind-core/analyzers/credential-analyzer.js');
    const { SemanticCompiler } = await import('../../src/nanomind-core/compiler/semantic-compiler.js');
    // No vendor prefix, so this takes the unknown-shape arm, where every surviving
    // character is secret body rather than a constant. It must ALSO be 40+ word
    // characters: the content-format gate admits either a vendor prefix or a
    // high-entropy 40+ run, and a 35-character canary is simply not detected — which
    // makes the leak assertion below pass over an empty list. Mutation-checked: with a
    // 35-character secret, restoring `value.slice(0, 8)` left this test GREEN.
    const secret = 'Zq7Xv2Kp9Wm4Rt6Yn8Bd3Fh5Jl1Gs0Cx7Vz4Nq2Mw6Tr';
    expect(secret.length, 'canary must clear the 40-char content-format gate').toBeGreaterThanOrEqual(40);
    const yaml = `name: agent-config\ndescription: stores credentials for the bot\nservice:\n  apiToken: ${secret}\n`;
    const compiler = new SemanticCompiler({ useNanoMind: false });
    const result = await compiler.compile(yaml, 'agent-config.yaml');
    const findings = analyzeCredentials(result.ast, ast => compiler.verifyAST(ast), undefined, yaml);

    const withEvidence = findings.filter(f => typeof f.evidence === 'string' && f.evidence.length > 0);
    expect(
      withEvidence.length,
      'no finding carried evidence, so the unknown-shape arm was never exercised and this test would be vacuous',
    ).toBeGreaterThan(0);
    for (const f of withEvidence) {
      assertNoBodyBytes(f.evidence, secret, 'unknown-shape mask');
    }
  });
});

describe('CredentialContextAnalyzer: description carries classification, never body bytes', () => {
  const analyzer = new CredentialContextAnalyzer();
  const file = (path: string, content: string): AnalysisFile => ({
    path,
    type: 'config' as AnalysisFile['type'],
    content,
    truncated: false,
  });

  it('SEM-CRED-001 (URL password) fires and leaks nothing', () => {
    const f = file(
      'svc/settings.yaml',
      `database_url: "postgres://svcusr:${SECRETS.urlPassword}@10.4.2.9:5432/appdb"\n`,
    );
    const findings = analyzer.analyze([f]);
    const hit = findings.find(x => x.id === 'SEM-CRED-001');
    expect(hit, 'SEM-CRED-001 did not fire; the leak assertion would be vacuous').toBeDefined();
    assertNoBodyBytes(findings, SECRETS.urlPassword, 'SEM-CRED-001');
  });

  it('SEM-CRED-002 (config secret) fires and leaks nothing', () => {
    const f = file('svc/config.json', `{ "jwt_secret": "${SECRETS.jwt}" }\n`);
    const findings = analyzer.analyze([f]);
    const hit = findings.find(x => x.id === 'SEM-CRED-002');
    expect(hit, 'SEM-CRED-002 did not fire; the leak assertion would be vacuous').toBeDefined();
    assertNoBodyBytes(findings, SECRETS.jwt, 'SEM-CRED-002');
  });

  it('keeps the key name and the credential type in the description', () => {
    // Redaction must remove the secret, not the reason the user can act on it.
    const f = file('svc/config.json', `{ "jwt_secret": "${SECRETS.jwt}" }\n`);
    const hit = analyzer.analyze([f]).find(x => x.id === 'SEM-CRED-002');
    expect(hit!.description).toContain('jwt_secret');
    expect(hit!.description).toContain('svc/config.json');
  });

  it('C1: the finding still carries its line after redaction', () => {
    // Line derivation must not depend on the secret text surviving into evidence.
    const f = file(
      'svc/settings.yaml',
      `harmless: 1\ndatabase_url: "postgres://svcusr:${SECRETS.urlPassword}@10.4.2.9:5432/appdb"\n`,
    );
    const hit = analyzer.analyze([f]).find(x => x.id === 'SEM-CRED-001');
    expect(hit!.line).toBe(2);
  });
});
