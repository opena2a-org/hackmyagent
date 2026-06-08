/**
 * Name-gated AWS secret access key detection.
 *
 * AWS secret access keys are 40-char `[A-Za-z0-9/+]` values with no
 * distinctive prefix, so they cannot join the prefix-anchored
 * CANONICAL_CREDENTIAL_PATTERNS without mass false positives. They are flagged
 * only when the assignment target names them (`aws … secret … = <40>`).
 *
 * Surfaced by the opena2a-cli 0.10.8 fresh-user release test: ai-trust (which
 * delegates scanning to HMA) did not flag a hardcoded AWS secret key. This
 * test exercises the real compiler path that produces the risk surface.
 */
import { describe, it, expect } from 'vitest';
import { SemanticCompiler } from '../../../src/nanomind-core/compiler/semantic-compiler';

const compiler = new SemanticCompiler({ useNanoMind: false }); // heuristic mode

const SURFACE = 'Hardcoded AWS secret access key';
// 40-char base64-shaped value with NO placeholder marker in the bytes.
const REAL = 'abcdEFGH1234ijklMNOP5678qrstUVWX90ABcdef';

function hasAwsSecretSurface(riskSurface: Array<{ surface: string }>): boolean {
  return riskSurface.some((r) => r.surface === SURFACE);
}

describe('name-gated AWS secret access key', () => {
  it('flags `aws_secret_access_key = "<40>"` in source', async () => {
    const { ast } = await compiler.compile(`aws_secret_access_key = "${REAL}"\n`, 'creds.py');
    expect(hasAwsSecretSurface(ast.inferredRiskSurface)).toBe(true);
  });

  it('flags `AWS_SECRET_ACCESS_KEY=<40>` env-style (unquoted)', async () => {
    const { ast } = await compiler.compile(`AWS_SECRET_ACCESS_KEY=${REAL}\n`, 'config.js');
    expect(hasAwsSecretSurface(ast.inferredRiskSurface)).toBe(true);
  });

  it('flags camelCase `awsSecretKey`', async () => {
    const { ast } = await compiler.compile(`const awsSecretKey = "${REAL}";\n`, 'app.js');
    expect(hasAwsSecretSurface(ast.inferredRiskSurface)).toBe(true);
  });

  it('flags JS-SDK `secretAccessKey: "<40>"` with NO nearby "aws" token', async () => {
    // The AWS SDK for JS v2 convention: new AWS.S3({ accessKeyId, secretAccessKey }).
    // The full phrase "secretAccessKey" is AWS-specific enough to flag on its own.
    const { ast } = await compiler.compile(
      `const s3 = new AWS.S3({ accessKeyId: id, secretAccessKey: "${REAL}" });\n`,
      'client.js',
    );
    expect(hasAwsSecretSurface(ast.inferredRiskSurface)).toBe(true);
  });

  it('flags Terraform-style `secret_access_key = "<40>"` (aws on the provider line)', async () => {
    const { ast } = await compiler.compile(
      `provider "aws" {\n  region = "us-east-1"\n  secret_access_key = "${REAL}"\n}\n`,
      'main.tf.js', // .tf isn't source_code yet; use a source ext to exercise the rule
    );
    expect(hasAwsSecretSurface(ast.inferredRiskSurface)).toBe(true);
  });

  // ── False-positive guards ───────────────────────────────────────────────

  it('does NOT flag the AWS docs example secret (contains EXAMPLE)', async () => {
    const { ast } = await compiler.compile(
      'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n',
      'docs.js',
    );
    expect(hasAwsSecretSurface(ast.inferredRiskSurface)).toBe(false);
  });

  it('does NOT flag a bare 40-char base64 blob with no credential name', async () => {
    const { ast } = await compiler.compile(`const blob = "${REAL}";\n`, 'data.js');
    expect(hasAwsSecretSurface(ast.inferredRiskSurface)).toBe(false);
  });

  it('does NOT flag a generic `session_secret` (no "aws" anchor)', async () => {
    const { ast } = await compiler.compile(`session_secret = "${REAL}"\n`, 'sess.py');
    expect(hasAwsSecretSurface(ast.inferredRiskSurface)).toBe(false);
  });

  it('does NOT flag a 40-char value named like a non-secret (aws_region nearby)', async () => {
    const { ast } = await compiler.compile(
      `aws_region = "us-east-1"\nbuild_hash = "${REAL}"\n`,
      'cfg.py',
    );
    expect(hasAwsSecretSurface(ast.inferredRiskSurface)).toBe(false);
  });

  it('does NOT flag a scanner\'s own regex rule definition', async () => {
    // A security tool quoting the AWS-secret pattern in its own source must
    // not self-flag (regexContextMarker guard).
    const { ast } = await compiler.compile(
      String.raw`const awsSecretRule = /aws.{0,20}secret.{0,20}[A-Za-z0-9]{40}/;` + '\n',
      'patterns.js',
    );
    expect(hasAwsSecretSurface(ast.inferredRiskSurface)).toBe(false);
  });

  it('does NOT flag `aws secretsmanager arn:` + a 40-char id (no "key" token)', async () => {
    const { ast } = await compiler.compile(
      `log.info("aws secretsmanager arn: ${REAL}")\n`,
      'log.py',
    );
    expect(hasAwsSecretSurface(ast.inferredRiskSurface)).toBe(false);
  });

  it('does NOT flag `aws secret bucket etag = <40 hex>` (no "key" token)', async () => {
    const { ast } = await compiler.compile(
      'aws_secret_bucket_etag = "0123456789abcdef0123456789abcdef01234567"\n',
      'etag.py',
    );
    expect(hasAwsSecretSurface(ast.inferredRiskSurface)).toBe(false);
  });

  it('does NOT flag low-entropy sentinel values (40 x\'s / 40 zeros)', async () => {
    const xs = await compiler.compile(`aws_secret_access_key = "${'x'.repeat(40)}"\n`, 'a.py');
    expect(hasAwsSecretSurface(xs.ast.inferredRiskSurface)).toBe(false);
    const zeros = await compiler.compile(`aws_secret_access_key = "${'0'.repeat(40)}"\n`, 'b.py');
    expect(hasAwsSecretSurface(zeros.ast.inferredRiskSurface)).toBe(false);
  });

  it('JSON form `"awsSecretAccessKey":"<40>"` is flagged', async () => {
    const { ast } = await compiler.compile(`{"awsSecretAccessKey":"${REAL}"}\n`, 'cfg.js');
    expect(hasAwsSecretSurface(ast.inferredRiskSurface)).toBe(true);
  });

  it('cache does not leak a source_code AWS finding onto same-content non-source artifact', async () => {
    // Regression: the compiler cache was keyed on content hash alone, so a
    // byte-identical file parsed as a different (non-source_code) type could
    // serve the cached source_code AST — and inherit its AWS finding. Cache is
    // now keyed on type+hash. Compile as source first (flags), then as a
    // non-source extension with identical bytes (must NOT inherit the finding).
    const c = new SemanticCompiler({ useNanoMind: false });
    const body = `aws_secret_access_key = "${REAL}"\n`;
    const src = await c.compile(body, 'creds.py');
    expect(hasAwsSecretSurface(src.ast.inferredRiskSurface)).toBe(true);
    const doc = await c.compile(body, 'notes.md'); // same bytes, different type
    expect(hasAwsSecretSurface(doc.ast.inferredRiskSurface)).toBe(false);
  });
});
