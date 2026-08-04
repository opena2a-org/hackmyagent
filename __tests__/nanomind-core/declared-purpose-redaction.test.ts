/**
 * `declaredPurpose` must never carry a live credential into user-visible output.
 *
 * `extractDeclaredPurpose` returns the first non-comment line of a source file
 * (sliced to 200 chars). For a file whose first real line assigns an API key,
 * that line IS the credential — and `declaredPurpose` is then interpolated
 * verbatim into at least nine user-visible strings, among them
 * `fix-generator.ts`'s CRED-EXPOSURE fix text:
 *
 *     Credentials in this source_code ("<first 60 chars>") are exposed in ...
 *
 * which reached stdout, `--json`, and the `-f html` "shareable compliance
 * report". Measured on 0.25.2 before this fix: 46 of a 49-character key.
 * Published 0.25.1 emitted zero characters of it, so this was a regression.
 *
 * The fix redacts at the single construction site in `semantic-compiler.ts`
 * rather than at the nine presentation sites: a normalizer applied at one
 * consumer leaves the other eight leaking, and new consumers get it for free.
 *
 * These tests assert on the COMPILED AST, not on rendered text, so they stay
 * red if any future renderer starts interpolating `declaredPurpose` again.
 */

import { describe, it, expect } from 'vitest';
import { SemanticCompiler } from '../../src/nanomind-core/compiler/semantic-compiler';

/**
 * Build a source file whose FIRST non-comment line is a credential assignment,
 * so `extractDeclaredPurpose` selects it. The line must exceed 20 characters
 * to be chosen at all.
 *
 * Credential values are assembled at runtime from parts so that no committed
 * line in this repository is itself a credential-shaped literal (GitHub push
 * protection scans every commit, including squashes).
 */
function sourceWithLeadingSecret(secret: string): string {
  // The identifier deliberately avoids the words key/token/secret/password.
  // `redactSecretsForNanoMind` has a generic `key = "..."` rule that runs
  // AFTER the shape-specific ones and would overwrite their labelled marker
  // with a bare `[REDACTED]`. A neutral name keeps the shape-specific rule
  // observable, so these cases prove the per-shape patterns actually fire
  // rather than passing on the generic backstop alone.
  return `const clientHandle = "${secret}";\nexport default clientHandle;\n`;
}

// Heuristic mode (no NanoMind daemon), matching the other compiler tests.
const compiler = new SemanticCompiler({ useNanoMind: false });

async function compilePurpose(content: string): Promise<string> {
  const result = await compiler.compile(content, 'client.js');
  return result.ast.declaredPurpose;
}

describe('declaredPurpose credential redaction', () => {
  // Each case is a shape the semantic compiler's own credential detector
  // reports. `redactSecretsForNanoMind` documents a COVERAGE invariant against
  // that detector, so every shape it can detect must also be redacted here.
  const cases: Array<{ name: string; secret: string; marker: string }> = [
    {
      name: 'OpenAI project key',
      secret: 'sk-proj-' + 'A'.repeat(41),
      marker: '[REDACTED_OPENAI_KEY]',
    },
    {
      name: 'legacy OpenAI key',
      secret: 'sk-' + 'B'.repeat(48),
      marker: '[REDACTED_OPENAI_KEY]',
    },
    {
      name: 'GitHub token',
      secret: 'ghp_' + 'C'.repeat(36),
      marker: '[REDACTED_GITHUB_TOKEN]',
    },
    {
      name: 'AWS access key id',
      secret: 'AKIA' + 'D'.repeat(16),
      marker: '[REDACTED_AWS_KEY]',
    },
    {
      name: 'Anthropic key',
      secret: 'sk-ant-api03-' + 'E'.repeat(40),
      marker: '[REDACTED_ANTHROPIC_KEY]',
    },
  ];

  for (const { name, secret, marker } of cases) {
    it(`${name}: declaredPurpose carries no fragment of the secret`, async () => {
      const purpose = await compilePurpose(sourceWithLeadingSecret(secret));

      // The whole value must be gone.
      expect(purpose).not.toContain(secret);

      // ...and so must any usable fragment of its body. A truncating renderer
      // is what leaked 46 of 49 characters, so assert on substrings, not just
      // on the full value: every window of the body longer than the shared
      // prefix must be absent.
      const body = secret.slice(secret.indexOf('-') + 1);
      for (let len = 12; len <= body.length; len += 8) {
        expect(purpose).not.toContain(body.slice(0, len));
      }

      // The redaction must be visible, not a silent drop — a caller that
      // prints `declaredPurpose` should show that something was removed.
      expect(purpose).toContain(marker);
    });
  }

  it('does not eat prose after a mentioned PEM header', async () => {
    // A file may legitimately MENTION a PEM header — validation code, docs, a
    // scanner's own source. A redaction rule anchored on the header and
    // running to end of line consumes whatever follows, which is where the
    // test/doc-context words live. That rule was written to close the
    // truncated-block gap, and reverted: on this exact shape it destroyed
    // `example`, `fixture`, `tests` and `demo` and flipped the scan from
    // 98/exit-0 to 69/exit-1.
    //
    // This guards the revert. If someone reintroduces a header-to-EOL rule,
    // this goes red instead of the regression reaching users again.
    const purpose = await compilePurpose(
      'const NOTE = "reject uploads starting with -----BEGIN PRIVATE KEY----- ; example fixture for tests and demo only";\n',
    );
    for (const word of ['example', 'fixture', 'tests', 'demo']) {
      expect(purpose.toLowerCase()).toContain(word);
    }
  });

  it('does not collapse the word count checkScopeMismatch gates on', async () => {
    // `capability-analyzer.ts` only raises AST-SCOPE-001 when
    // `purposeWords.size > 3`, where purposeWords are the >3-character words
    // of declaredPurpose. The daemon redactor rewrote a whole quoted value to
    // `token=[REDACTED]`, taking the count from 6 to 1 and silently dropping
    // a check whose stated job is catching malicious capabilities hidden
    // behind a benign-sounding purpose. Guard the input to that gate.
    const purpose = await compilePurpose(
      'const token = "finance reporting analytics pipeline summaries";\n',
    );
    const words = new Set(
      purpose.toLowerCase().split(/\s+/).filter(w => w.length > 3),
    );
    expect(words.size).toBeGreaterThan(3);
  });

  it('leaves a genuine non-credential purpose untouched', async () => {
    // Guards the opposite direction: redaction must not eat real purpose text,
    // or every downstream "declared purpose" string becomes useless. Without
    // this, redacting everything would pass the assertions above vacuously.
    const purpose = await compilePurpose(
      'export const handler = "summarizes analytics reports for the finance team";\n',
    );
    expect(purpose).toContain('summarizes analytics reports');
    expect(purpose).not.toContain('[REDACTED');
  });

  it('preserves test/doc-context words INSIDE a key-named quoted value', async () => {
    // `credential-analyzer.ts` suppresses credential findings when
    // declaredPurpose contains test/example/documentation/fixture/demo.
    //
    // The words must sit INSIDE the quoted value of a key/token/secret/
    // password identifier — that is the only position the name-gated rule
    // can reach. An earlier version of this test put them in a trailing
    // comment, outside the value, where no rule could touch them: it passed
    // by construction and could not see the regression below.
    //
    // Applying the daemon-boundary redactor here rewrote the whole value to
    // `apiKey=[REDACTED]`, destroying all three keywords and flipping a scan
    // of this shape from 98/exit-0 to 69/exit-1.
    const purpose = await compilePurpose(
      'const apiKey = "example fixture value for tests only";\n',
    );

    expect(purpose.toLowerCase()).toContain('example');
    expect(purpose.toLowerCase()).toContain('fixture');
    expect(purpose.toLowerCase()).toContain('tests');
    expect(purpose).not.toContain('[REDACTED');
  });

  it('still redacts a secret-shaped value under a key-named identifier', async () => {
    // The complement of the test above, and the reason the whitespace
    // condition is the discriminator rather than dropping the rule outright:
    // a value with no spaces under a `key`-ish name is still redacted.
    const purpose = await compilePurpose('const apiKey = "hunter2xyzhunter2xyz";\n');
    expect(purpose).not.toContain('hunter2xyzhunter2xyz');
    expect(purpose).toContain('[REDACTED');
  });

  describe('name-gated AWS secret access key', () => {
    // Reported by the compiler's SECOND detector list, which the shape list
    // originally did not mirror — detected, but rendered 33 of 40 characters
    // into text, JSON, HTML and SARIF.
    //
    // Every identifier spelling the DETECTOR's anchor accepts must be covered,
    // in BOTH the quoted and bare forms. A first version of this test checked
    // only `aws_secret_access_key`, and passed against a redactor whose anchor
    // matched nothing else: `secretAccessKey`, `awsSecretKey` and
    // `secret_access_key` each leaked the full 40 characters when unquoted.
    // One spelling is not a matrix.
    //
    // The bare form is the load-bearing half: the generic name-gated rule
    // requires quotes, so a quoted-only fixture passes even with the
    // shape rule deleted entirely.
    // Composed, never written as one literal. A 40-character AWS-shaped run in
    // a committed file is what GitHub push protection blocks on, and this repo
    // is public — it scans every commit, including squashes. Same reason the
    // `AKIA` fixture in pinned-credential-shapes.test.ts is built from parts.
    const secret = 'wJalrXUtnFEMI' + 'bK7MDENGbPxRf' + 'iCYzWPFdQpTr9K';
    const spellings = [
      'aws_secret_access_key',
      'AWS_SECRET_ACCESS_KEY',
      'secretAccessKey',
      'awsSecretKey',
      'secret_access_key',
    ];

    for (const name of spellings) {
      for (const [form, line] of [
        ['bare', `${name} = ${secret}\n`],
        ['quoted', `${name} = "${secret}"\n`],
        ['json', `{"${name}":"${secret}"}\n`],
      ] as const) {
        it(`${name} (${form}) leaves no fragment`, async () => {
          const purpose = await compilePurpose(line);
          expect(purpose).not.toContain(secret);
          // No usable fragment either — the original defect was a truncation
          // that kept 33 of the 40 characters.
          expect(purpose).not.toContain(secret.slice(0, 16));
          expect(purpose).toContain('[REDACTED');
        });
      }
    }
  });

  it('redacts a secret that straddles the 200-character slice boundary', async () => {
    // Redaction must run BEFORE the slice. Slicing first cuts a straddling
    // secret below the pattern's minimum length, so the redactor stops
    // matching while the detector, reading full content, still reports it.
    const secret = 'sk-' + 'K'.repeat(50);
    const padding = 'const handle = "' + 'p'.repeat(180) + '"; const q = "';
    const purpose = await compilePurpose(`${padding}${secret}";\n`);

    expect(purpose).not.toContain(secret);
    // No usable fragment of the body may survive either.
    expect(purpose).not.toContain('K'.repeat(20));
  });
});
