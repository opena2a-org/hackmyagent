/**
 * The credential redactor became a RULE TABLE so that each match can report the
 * registry shape it proves (C9 — `redactedShapes` may carry only ids resolved
 * FROM THE VALUE, and the marker vocabulary cannot supply them because it is
 * many-to-one).
 *
 * That refactor is only safe if it changed nothing about WHAT is removed. This
 * file is the proof.
 *
 * The oracle is a hand-written sequential `.replace()` chain — the pre-table
 * form — kept HERE and not in `src/`, deliberately, for two reasons:
 *   1. `credential-vocabulary-enumeration.test.ts` (E4) freezes the number of
 *      credential shape literals in `src/` + `scripts/`. A second copy in `src/`
 *      is exactly the vocabulary duplication that guard exists to stop, and it
 *      caught this: the count went 301 -> 324.
 *   2. An oracle that lives beside the implementation drifts with it. This one
 *      has to be edited by hand, in a different shape, to stay in agreement.
 */

import { describe, it, expect } from 'vitest';
import {
  redactCredentialShapes,
  redactCredentialShapesReporting,
  redactSecretsForReport,
  redactSecretsForReportReporting,
} from '../../src/nanomind-core/security/defense-in-depth';

/**
 * THE ORACLE. A sequential chain, in the original order, written out longhand.
 *
 * Do not refactor this into a loop or a table — being a different FORM from the
 * implementation is the whole point. If both sides were tables, a mistake in the
 * shared shape would pass.
 */
function oracleChain(content: string): string {
  let r = content;
  r = r.replace(/sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/g, '[REDACTED_ANTHROPIC_KEY]');
  r = r.replace(/sk-proj-[a-zA-Z0-9_-]{20,}/g, '[REDACTED_OPENAI_KEY]');
  r = r.replace(/sk-[a-zA-Z0-9]{48,}/g, '[REDACTED_OPENAI_KEY]');
  r = r.replace(/AKIA[0-9A-Z]{16}/g, '[REDACTED_AWS_KEY]');
  r = r.replace(/ghp_[a-zA-Z0-9]{36}/g, '[REDACTED_GITHUB_TOKEN]');
  r = r.replace(/gho_[a-zA-Z0-9]{36}/g, '[REDACTED_GITHUB_TOKEN]');
  r = r.replace(/ghs_[a-zA-Z0-9]{36}/g, '[REDACTED_GITHUB_TOKEN]');
  r = r.replace(/ghu_[a-zA-Z0-9]{36}/g, '[REDACTED_GITHUB_TOKEN]');
  r = r.replace(/github_pat_[a-zA-Z0-9_]{60,}/g, '[REDACTED_GITHUB_TOKEN]');
  r = r.replace(/glpat-[a-zA-Z0-9_-]{20,}/g, '[REDACTED_GITLAB_TOKEN]');
  r = r.replace(/hf_[a-zA-Z0-9]{34,}/g, '[REDACTED_HUGGINGFACE_TOKEN]');
  r = r.replace(/npm_[a-zA-Z0-9]{36}/g, '[REDACTED_NPM_TOKEN]');
  r = r.replace(/sk_live_[0-9a-zA-Z]{24,}/g, '[REDACTED_STRIPE_KEY]');
  r = r.replace(/sk_test_[0-9a-zA-Z]{24,}/g, '[REDACTED_STRIPE_KEY]');
  r = r.replace(/SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, '[REDACTED_SENDGRID_KEY]');
  r = r.replace(/AIza[0-9A-Za-z_-]{35}/g, '[REDACTED_GOOGLE_KEY]');
  r = r.replace(/xox[baprs]-[a-zA-Z0-9-]{10,}/g, '[REDACTED_SLACK_TOKEN]');
  r = r.replace(
    /((?:aws.{0,16}?(?:secret|private).{0,16}?key|secret[_\s.-]?access[_\s.-]?key)["'\s]*[:=]+>?\s*["']?)([A-Za-z0-9/+=]{40,})/gi,
    '$1[REDACTED_AWS_SECRET]',
  );
  r = r.replace(/-----BEGIN [A-Z ]+ KEY-----(?:(?!-----BEGIN)[\s\S]){0,32768}?-----END [A-Z ]+ KEY-----/g, '[REDACTED_PRIVATE_KEY]');
  r = r.replace(/(?:postgres|mysql|mongodb|redis):\/\/[^\s'"]+/gi, '[REDACTED_CONNECTION_STRING]');
  return r;
}

/**
 * Every value below is SYNTHETIC and carries `FAKE` in its body. They match the
 * shape patterns and nothing else; none is or ever was a live credential.
 */
const F4 = 'FAKE';
const fakeOf = (n: number) => F4.repeat(Math.ceil(n / 4)).slice(0, n);

const SAMPLES: ReadonlyArray<{ label: string; text: string; shapes: string[] }> = [
  { label: 'anthropic', text: `key=sk-ant-api03-${fakeOf(20)}`, shapes: ['anthropic-key'] },
  { label: 'openai-project', text: `sk-proj-${fakeOf(20)}`, shapes: ['openai-project-key'] },
  { label: 'openai-legacy', text: `sk-${fakeOf(48)}`, shapes: ['openai-key'] },
  { label: 'aws-akia', text: `AKIA${fakeOf(16).toUpperCase()}`, shapes: ['aws-access-key-id'] },
  { label: 'github-pat', text: `ghp_${fakeOf(36)}`, shapes: ['github-pat'] },
  { label: 'github-oauth', text: `gho_${fakeOf(36)}`, shapes: ['github-oauth'] },
  { label: 'github-server', text: `ghs_${fakeOf(36)}`, shapes: ['github-server'] },
  { label: 'github-user', text: `ghu_${fakeOf(36)}`, shapes: ['github-user'] },
  { label: 'github-fg', text: `github_pat_${fakeOf(60)}`, shapes: ['github-fine-grained'] },
  { label: 'gitlab', text: `glpat-${fakeOf(20)}`, shapes: ['gitlab-pat'] },
  { label: 'huggingface', text: `hf_${fakeOf(34)}`, shapes: ['huggingface-token'] },
  { label: 'npm', text: `npm_${fakeOf(36)}`, shapes: ['npm-token'] },
  { label: 'stripe-live', text: `sk_live_${fakeOf(24)}`, shapes: ['stripe-live'] },
  { label: 'stripe-test', text: `sk_test_${fakeOf(24)}`, shapes: ['stripe-test'] },
  { label: 'sendgrid', text: `SG.${fakeOf(22)}.${fakeOf(43)}`, shapes: ['sendgrid-key'] },
  { label: 'google', text: `AIza${fakeOf(35)}`, shapes: ['google-api-key'] },
  // Every member of the `xox[baprs]-` alternation, not just `xoxb-`.
  //
  // The first draft of this file carried `xoxb-` alone and a red-proof caught it:
  // narrowing the rule to `xoxb-` left all 60 assertions GREEN, because no
  // fixture exercised the other four. A pattern with an alternation needs a
  // sample per branch or the branch is untested.
  { label: 'slack-b', text: `xoxb-${fakeOf(12)}`, shapes: ['slack-token'] },
  { label: 'slack-a', text: `xoxa-${fakeOf(12)}`, shapes: ['slack-token'] },
  { label: 'slack-p', text: `xoxp-${fakeOf(12)}`, shapes: ['slack-token'] },
  { label: 'slack-r', text: `xoxr-${fakeOf(12)}`, shapes: ['slack-token'] },
  { label: 'slack-s', text: `xoxs-${fakeOf(12)}`, shapes: ['slack-token'] },
  {
    label: 'aws-secret',
    text: `aws_secret_access_key = "${fakeOf(40)}"`,
    shapes: ['aws-secret-access-key'],
  },
  {
    label: 'pem',
    text: '-----BEGIN RSA PRIVATE KEY-----\nFAKEFAKE\n-----END RSA PRIVATE KEY-----',
    shapes: ['pem-private-key'],
  },
  {
    label: 'connection-string',
    text: 'postgres://fakeuser:fakepass@localhost:5432/db',
    shapes: ['connection-string'],
  },
  // Ordering hazard: the generic `sk-` rule must not claim the project key.
  {
    label: 'openai-project-before-generic',
    text: `sk-proj-${fakeOf(60)}`,
    shapes: ['openai-project-key'],
  },
  // Adjacency: the non-anchored patterns must catch BOTH, not just the first.
  {
    label: 'adjacent-github',
    text: `ghp_${fakeOf(36)}ghp_${fakeOf(36)}`,
    shapes: ['github-pat'],
  },
  // Two different shapes in one string.
  {
    label: 'multi-shape',
    text: `AKIA${fakeOf(16).toUpperCase()} and glpat-${fakeOf(20)}`,
    shapes: ['aws-access-key-id', 'gitlab-pat'],
  },
  // Prose that must survive untouched.
  { label: 'benign-prose', text: 'The API key rotates every 90 days.', shapes: [] },
  { label: 'empty', text: '', shapes: [] },
];

describe('redaction rule table — parity with the pre-table chain', () => {
  it.each(SAMPLES.map(s => [s.label, s.text] as const))(
    'produces byte-identical output to the oracle chain: %s',
    (_label, text) => {
      expect(redactCredentialShapes(text)).toBe(oracleChain(text));
    },
  );

  it('is byte-identical on every sample concatenated into one document', () => {
    const doc = SAMPLES.map(s => s.text).join('\n---\n');
    expect(redactCredentialShapes(doc)).toBe(oracleChain(doc));
  });

  it('the oracle is not vacuous — it really does change these inputs', () => {
    // Without this, a broken oracle that returned its input unchanged would make
    // every parity assertion above pass against an equally broken implementation.
    const changed = SAMPLES.filter(s => s.shapes.length > 0);
    expect(changed.length).toBeGreaterThan(15);
    for (const s of changed) {
      expect(oracleChain(s.text), `oracle left ${s.label} unchanged`).not.toBe(s.text);
    }
  });
});

describe('redaction rule table — shapes are resolved FROM THE VALUE (C9)', () => {
  it.each(SAMPLES.map(s => [s.label, s.text, s.shapes] as const))(
    'reports exactly the shapes that matched: %s',
    (_label, text, shapes) => {
      expect(redactCredentialShapesReporting(text).shapes).toEqual([...shapes].sort());
    },
  );

  it('reported shapes are sorted and deduped', () => {
    const multi = `AKIA${fakeOf(16).toUpperCase()} glpat-${fakeOf(20)} AKIA${fakeOf(16).toUpperCase()}`;
    const { shapes } = redactCredentialShapesReporting(multi);
    expect(shapes).toEqual(['aws-access-key-id', 'gitlab-pat']);
    expect([...shapes].sort()).toEqual(shapes);
  });

  it('the five GitHub shapes report DISTINCT ids despite sharing one marker', () => {
    // This is the reason the table exists. Recovering ids from the redacted
    // text would yield five candidates for any one of them.
    const ids = (['ghp_', 'gho_', 'ghs_', 'ghu_'] as const).map(
      p => redactCredentialShapesReporting(`${p}${fakeOf(36)}`).shapes[0],
    );
    expect(new Set(ids).size).toBe(4);
    expect(ids).toEqual(['github-pat', 'github-oauth', 'github-server', 'github-user']);
    // …and all four really do render the same marker.
    for (const p of ['ghp_', 'gho_', 'ghs_', 'ghu_']) {
      expect(redactCredentialShapes(`${p}${fakeOf(36)}`)).toBe('[REDACTED_GITHUB_TOKEN]');
    }
  });

  it('stripe live and test are distinguished, because their rotations differ', () => {
    expect(redactCredentialShapesReporting(`sk_live_${fakeOf(24)}`).shapes).toEqual(['stripe-live']);
    expect(redactCredentialShapesReporting(`sk_test_${fakeOf(24)}`).shapes).toEqual(['stripe-test']);
  });
});

describe('the report boundary — a key-name heuristic resolves NO shape (C9)', () => {
  it('redacts a name-gated value but reports no shape id', () => {
    const text = 'password = "hunter2xyzabc"';
    const out = redactSecretsForReportReporting(text);
    expect(out.text).not.toContain('hunter2xyzabc');
    // Applied, but nothing was resolved from the VALUE — the rule fired on the
    // identifier and never inspected what it removed.
    expect(out.shapes).toEqual([]);
  });

  it('still reports the shape when the value itself is shape-anchored', () => {
    const out = redactSecretsForReportReporting(`token = "ghp_${fakeOf(36)}"`);
    expect(out.shapes).toEqual(['github-pat']);
  });

  it('leaves prose the name-gate would otherwise destroy', () => {
    // The measured regression that separates the report boundary from the
    // daemon one: whitespace in the value means it is not a secret.
    const prose = 'key = "example fixture value for tests only"';
    expect(redactSecretsForReport(prose)).toBe(prose);
  });
});

describe('the two shapes held out of this release stay held out (GAP-8 / S4)', () => {
  it('does not redact a git SHA-40, a sha512- integrity value, or a contentHash', () => {
    // Porting the entropy-blob class into the redactor is the measured S4 stop
    // condition. HMA's own reports carry `contentHash` values, so this is a
    // self-inflicted-FP guard, not a hypothetical.
    const sha40 = 'a'.repeat(40);
    const integrity = `sha512-${'A'.repeat(60)}==`;
    for (const s of [sha40, integrity]) {
      expect(redactCredentialShapes(s)).toBe(s);
      expect(redactCredentialShapesReporting(s).shapes).toEqual([]);
    }
  });

  it('does not redact a JWT', () => {
    const jwt = `eyJ${fakeOf(20)}.eyJ${fakeOf(20)}.${fakeOf(20)}`;
    expect(redactCredentialShapesReporting(jwt).shapes).toEqual([]);
  });
});
