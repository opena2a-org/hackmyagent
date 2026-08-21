/**
 * Hand-written literal fixtures, one per credential shape id.
 *
 * EVERY VALUE IN THIS FILE IS WRITTEN BY HAND AND NOTHING HERE IMPORTS THE
 * IMPLEMENTATION. That is the entire point, and it is a measured requirement
 * rather than a style preference.
 *
 * The prior-art branch (`3d0d44c`) built its corpus the other way: the
 * generator derived its samples by mapping over `VENDOR_PREFIX_ALTERNATIVES`
 * and its oracle called `matchVendorPrefix` — the same function the redactor
 * uses to decide what to keep. Two consequences, both measured:
 *
 *   - deleting a shape from the detector deleted its own test case, so the
 *     suite stayed green over the deletion;
 *   - a `matchVendorPrefix` that over-claimed shrank the expected `body` by
 *     exactly the bytes that then leaked, so the suite stayed green over the
 *     leak too. 197 assertions, fully green, while a 43-character JWT
 *     signature and a 20-character `glpat-` body were leaking.
 *
 * So: the id set here is compared against the registry's id set in both
 * directions, and every expectation below is a literal a human typed. Adding a
 * shape without a fixture fails; deleting a shape leaves an orphan fixture that
 * also fails.
 *
 * The sample values are synthetic. They are shaped like real credentials
 * because a fixture that cannot match its own shape proves nothing, but none of
 * them is a live secret.
 */

export interface ShapeFixture {
  /** The expected alternation source, written out in full, by hand. */
  readonly alternation: string;
  /** The expected redaction marker, written out by hand. */
  readonly marker: string;
  /**
   * A literal value of this shape. Must match the shape's own composed regex.
   * Empty only for `jwt`, which is matched by a linear scan and has no source.
   */
  readonly sample: string;
  /**
   * A value one step BELOW the shape's floor, or otherwise just outside it.
   * Must NOT match. This is what proves the floor is live rather than
   * decorative: without it, a shape narrowed to nothing would still pass.
   */
  readonly nearMiss: string;
  /** For a name-gated shape, a line carrying the gate as well as the value. */
  readonly gatedContext?: string;
}

export const SHAPE_FIXTURES: Readonly<Record<string, ShapeFixture>> = {
  'anthropic-key': {
    alternation: 'sk-ant-api[0-9][a-zA-Z0-9_-]{16,}',
    marker: '[REDACTED_ANTHROPIC_KEY]',
    sample: 'sk-ant-api' + '03-Ab3xY7Qw9Lm2Kd5Rt8Nv1Zc4',
    // 15 body characters after `sk-ant-api0`, one below the 16 floor.
    nearMiss: 'sk-ant' + '-api03-Ab3xY7Qw9Lm2K',
  },
  'openai-project-key': {
    alternation: 'sk-proj-[a-zA-Z0-9_-]{16,}',
    marker: '[REDACTED_OPENAI_KEY]',
    sample: 'sk-proj-' + 'Ab3xY7Qw9Lm2Kd5Rt8Nv',
    nearMiss: 'sk-pro' + 'j-Ab3xY7Qw9Lm2Kd5',
  },
  'openai-key': {
    alternation: 'sk-[a-zA-Z0-9_-]{20,}',
    marker: '[REDACTED_OPENAI_KEY]',
    sample: 'sk-Ab3' + 'xY7Qw9Lm2Kd5Rt8Nv1Zc4Ef6Gh',
    // 19 body characters, one below the 20 floor.
    nearMiss: 'sk-Ab3' + 'xY7Qw9Lm2Kd5Rt',
  },
  'stripe-live': {
    alternation: 'sk_live_[a-zA-Z0-9]{20,}',
    marker: '[REDACTED_STRIPE_KEY]',
    sample: 'sk_liv' + 'e_4eC39HqLyjWDarjtT1zdp7dc',
    nearMiss: 'sk_liv' + 'e_4eC39HqLyjWD',
  },
  'stripe-test': {
    alternation: 'sk_test_[a-zA-Z0-9]{20,}',
    marker: '[REDACTED_STRIPE_KEY]',
    sample: 'sk_tes' + 't_4eC39HqLyjWDarjtT1zdp7dc',
    nearMiss: 'sk_tes' + 't_4eC39HqLyjWD',
  },
  'github-pat': {
    alternation: 'ghp_[a-zA-Z0-9]{20,}',
    marker: '[REDACTED_GITHUB_TOKEN]',
    sample: 'ghp_' + '16C7e42F292c6912E7710c838347Ae178B4a',
    nearMiss: 'ghp_16' + 'C7e42F292c6912E77',
  },
  'github-oauth': {
    alternation: 'gho_[a-zA-Z0-9]{20,}',
    marker: '[REDACTED_GITHUB_TOKEN]',
    sample: 'gho_' + '16C7e42F292c6912E7710c838347Ae178B4a',
    nearMiss: 'gho_16' + 'C7e42F292c6912E77',
  },
  'github-server': {
    alternation: 'ghs_[a-zA-Z0-9]{20,}',
    marker: '[REDACTED_GITHUB_TOKEN]',
    sample: 'ghs_' + '16C7e42F292c6912E7710c838347Ae178B4a',
    nearMiss: 'ghs_16' + 'C7e42F292c6912E77',
  },
  'github-user': {
    alternation: 'ghu_[a-zA-Z0-9]{20,}',
    marker: '[REDACTED_GITHUB_TOKEN]',
    sample: 'ghu_' + '16C7e42F292c6912E7710c838347Ae178B4a',
    nearMiss: 'ghu_16' + 'C7e42F292c6912E77',
  },
  'github-fine-grained': {
    alternation: 'github_pat_[a-zA-Z0-9_]{20,}',
    marker: '[REDACTED_GITHUB_TOKEN]',
    sample: 'github' + '_pat_11ABCDEFG0abcdefghij_KLMNOPQRSTUVWXYZ0123456789abcdef',
    nearMiss: 'github' + '_pat_11ABCDEFG0abcdefghi',
  },
  'huggingface-token': {
    alternation: 'hf_[a-zA-Z0-9]{20,}',
    marker: '[REDACTED_HUGGINGFACE_TOKEN]',
    sample: 'hf_' + 'QwErTyUiOpAsDfGhJkLzXcVbNm123456',
    nearMiss: 'hf_QwE' + 'rTyUiOpAsDfGhJ',
  },
  'gitlab-pat': {
    alternation: 'glpat-[a-zA-Z0-9_-]{20,}',
    marker: '[REDACTED_GITLAB_TOKEN]',
    sample: 'glpat-' + 'Ab3xY7Qw9Lm2Kd5Rt8Nv',
    nearMiss: 'glpat-' + 'Ab3xY7Qw9Lm2Kd5Rt',
  },
  'npm-token': {
    alternation: 'npm_[a-zA-Z0-9]{20,}',
    marker: '[REDACTED_NPM_TOKEN]',
    sample: 'npm_ab' + 'cdefghijklmnopqrstuvwxyz0123456789',
    nearMiss: 'npm_ab' + 'cdefghijklmnopqrs',
  },
  'aws-access-key-id': {
    alternation: 'AKIA[0-9A-Z]{16}',
    marker: '[REDACTED_AWS_KEY]',
    sample: 'AKIA' + '3QZ7MPLV2XKDNW4R',
    // 15 body characters: the width here is EXACT, not a floor.
    nearMiss: 'AKIA3Q' + 'Z7MPLV2XKDN',
  },
  'google-api-key': {
    alternation: 'AIza[0-9A-Za-z_-]{35}',
    marker: '[REDACTED_GOOGLE_KEY]',
    sample: 'AIza' + 'SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY',
    nearMiss: 'AIzaSy' + 'D-9tSrke72PouQMnMX-a7eZSW0jkFMB',
  },
  'slack-token': {
    // The five token types share one label. If this expectation is ever
    // narrowed to `xoxb-`, the registry test must go red — that is precisely
    // what a label-set assertion cannot see.
    alternation: 'xox[abprs]-[0-9A-Za-z-]{10,}',
    marker: '[REDACTED_SLACK_TOKEN]',
    sample: 'xoxb-' + '123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx',
    nearMiss: 'xoxb-1' + '2345678',
  },
  'sendgrid-key': {
    alternation: 'SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}',
    marker: '[REDACTED_SENDGRID_KEY]',
    sample:
      'SG.abc' + 'defghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG',
    // The dotted-namespace false positive the fixed widths exist to reject.
    nearMiss: 'MSG.IN' + 'CIDENT_ESCALATION_QUEUE.HIGH_PRIORITY_ROUTE',
  },
  jwt: {
    alternation: '',
    marker: '[REDACTED_JWT]',
    sample:
      'eyJhbG' + 'ciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
    nearMiss: 'eyJhbG' + 'ciOiJIUzI1NiJ9',
  },
  'entropy-blob': {
    alternation: '\\b[A-Za-z0-9+=_]{40,}\\b',
    marker: '[REDACTED_SECRET]',
    // 44 characters.
    sample: 'Zx8Kq2' + 'Wm5Bn7Vc4Lp9Rt6Yu3Ij1Oe0Ad8Sf5Gh2Jk7Lq',
    // 39 characters, one below the 40 floor.
    nearMiss: 'Zx8Kq2' + 'Wm5Bn7Vc4Lp9Rt6Yu3Ij1Oe0Ad8Sf5Gh',
  },
  'pem-private-key': {
    alternation: '-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PRIVATE)[A-Z ]*KEY-----',
    marker: '[REDACTED_PRIVATE_KEY]',
    sample: '-----B' + 'EGIN RSA PRIVATE KEY-----',
    nearMiss: '-----B' + 'EGIN CERTIFICATE-----',
  },
  'aws-secret-access-key': {
    alternation: '[A-Za-z0-9/+=]{40,}',
    marker: '[REDACTED_AWS_SECRET]',
    // Exactly 40 characters.
    sample: 'wJalrX' + 'UtnFEMI/K7MDENG/bPxRfiCYz1a2B3c4D5',
    // 39.
    nearMiss: 'wJalrX' + 'UtnFEMI/K7MDENG/bPxRfiCYz1a2B3c4D',
    gatedContext: 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYz1a2B3c4D5"',
  },
  'connection-string': {
    alternation: "(?:postgres|mysql|mongodb|redis)://[^\\s'\"]+",
    marker: '[REDACTED_CONNECTION_STRING]',
    sample: 'postgr' + 'es://appuser:s3cr3t-p4ssw0rd@db.internal:5432/app',
    // A scheme the redactor does not carry — six of them are located by
    // credential-context.ts and redacted by nothing.
    nearMiss: 'amqp:/' + '/appuser:s3cr3t-p4ssw0rd@broker.internal:5672/vhost',
  },
};

/**
 * The enumeration guard literals each shape declares, written out by hand.
 *
 * Pinned separately from the shapes because the guard set is what the E4
 * enumeration test scans `src/` for. Narrowing a shape's guards would quietly
 * shrink what that test can see — a copy of the shape could then be added to
 * another file and stay invisible — and the guard test itself cannot notice,
 * because it derives its vocabulary from the registry on purpose. This literal
 * is what notices.
 */
export const EXPECTED_GUARDS: Readonly<Record<string, readonly string[]>> = {
  'anthropic-key': ['sk-ant'],
  'openai-project-key': ['sk-proj'],
  'openai-key': ['sk-[', 'sk-|'],
  'stripe-live': ['sk_live_'],
  'stripe-test': ['sk_test_'],
  'github-pat': ['ghp_'],
  'github-oauth': ['gho_'],
  'github-server': ['ghs_'],
  'github-user': ['ghu_'],
  'github-fine-grained': ['github_pat_'],
  'huggingface-token': ['hf_'],
  'gitlab-pat': ['glpat-'],
  'npm-token': ['npm_'],
  'aws-access-key-id': ['AKIA'],
  'google-api-key': ['AIza'],
  'slack-token': ['xox'],
  'sendgrid-key': ['SG.', 'SG\\.'],
  jwt: ['eyJ'],
  'entropy-blob': ['[A-Za-z0-9+=_]{40,}'],
  'pem-private-key': ['-----BEGIN'],
  'aws-secret-access-key': ['secret_access_key', 'secret[_\\s.-]?access'],
  'connection-string': ['postgres://', 'mongodb://'],
};

/**
 * The 17 vendor alternatives, written out by hand in the order the alternation
 * resolves them.
 *
 * This is the pin that makes the registry derivation safe: `credential-format`
 * used to declare this list as a literal and now composes it from
 * `CREDENTIAL_SHAPES`. If the composition ever produces anything other than
 * these exact strings in this exact order, every consumer of the alternation
 * changes behaviour, and this list is what notices.
 *
 * Order is load-bearing: `sk-ant-api…` and `sk-proj-…` before the generic
 * `sk-…`, or a project key is reported under the legacy label.
 */
export const EXPECTED_VENDOR_ALTERNATIVES: readonly string[] = [
  'sk-ant-api[0-9][a-zA-Z0-9_-]{16,}',
  'sk-proj-[a-zA-Z0-9_-]{16,}',
  'sk-[a-zA-Z0-9_-]{20,}',
  'sk_live_[a-zA-Z0-9]{20,}',
  'sk_test_[a-zA-Z0-9]{20,}',
  'ghp_[a-zA-Z0-9]{20,}',
  'gho_[a-zA-Z0-9]{20,}',
  'ghs_[a-zA-Z0-9]{20,}',
  'ghu_[a-zA-Z0-9]{20,}',
  'github_pat_[a-zA-Z0-9_]{20,}',
  'hf_[a-zA-Z0-9]{20,}',
  'glpat-[a-zA-Z0-9_-]{20,}',
  'npm_[a-zA-Z0-9]{20,}',
  'AKIA[0-9A-Z]{16}',
  'AIza[0-9A-Za-z_-]{35}',
  'xox[abprs]-[0-9A-Za-z-]{10,}',
  'SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}',
];
