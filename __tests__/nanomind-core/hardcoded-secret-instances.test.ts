/**
 * HMA-01.AC1 / HMA-01.AC3 — the CRITICAL hardcoded-secret finding is locatable,
 * and several secrets in one file are countable (#368, #478).
 *
 * ONE DEFECT, TWO SYMPTOMS, ONE CAUSE. `scanCanonicalCredentialFormats` knew
 * the exact offset of every key it matched and threw it away, emitting only a
 * classification (`OpenAI legacy key: [REDACTED]`) that nothing downstream
 * could search for — `extractEvidenceSpans` looks evidence up with `indexOf`,
 * and a classification is not a quotation. So:
 *
 *   - the CRITICAL rendered as `app/config.ts` with no `:N` and therefore no
 *     `Verify:`, directly above a HIGH on the same file that printed both. A
 *     CRITICAL vaguer than the HIGH beneath it inverts the severity signal
 *     (#368, second carry);
 *   - four keys in one file collapsed to a single finding naming the first, and
 *     because scoring counts findings, removing three of four moved the score
 *     by exactly zero — which reads as "my fix did not work" (#478).
 *
 * The offset is now recorded where the match is made and carried on the risk
 * surface. NO DETECTION VOCABULARY MOVES: the same shapes are found on the same
 * files, and a file holding ONE secret still produces exactly one finding at the
 * same severity, which the last block below pins.
 *
 * WHY THE KEYS ARE SYNTHESIZED AT RUN TIME rather than committed, and why the
 * bodies are hex: the detector skips any value whose own bytes carry
 * FAKE / EXAMPLE / PLACEHOLDER / DUMMY / YOUR_KEY / YOUR_TOKEN / REPLACE_ME /
 * INSERT_HERE, so a fixture using the house marker would be vacuously green,
 * and committing a credential-shaped literal to a public repo is worse. A hex
 * body is a subset of every vendor's character class and cannot spell any of
 * those markers, so the generator cannot accidentally suppress its own fixture.
 */

import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import { calculateSecurityScore } from '../../src/hardening/scanner';
import { generateVerifyCommand } from '../../src/ui/verify-command';

/** Uppercase hex, which every vendor character class below admits. */
function body(chars: number): string {
  return randomBytes(chars).toString('hex').slice(0, chars).toUpperCase();
}

/**
 * Four DIFFERENT vendor shapes, because #478's measurement was that each type
 * is detected in isolation — the defect is aggregation, not pattern coverage.
 * A four-of-one-shape fixture could not tell those apart.
 */
function secretLines(): string[] {
  return [
    `  anthropicKey: "sk-ant-api03-${body(40)}",`,
    `  awsAccessKeyId: "AKIA${body(16)}",`,
    `  githubToken: "ghp_${body(36)}",`,
    `  googleApiKey: "AIza${body(35)}",`,
  ];
}

/**
 * `count` secrets in one source file, otherwise byte-identical. The removed
 * lines are replaced by inert ones so the two trees differ only in how many
 * credentials they hold, not in how long the file is.
 */
function sourceWithSecrets(count: number): string {
  const secrets = secretLines();
  const rows = secrets.map((line, i) =>
    i < count ? line : `  setting${i}: "us-east-1",`,
  );
  return [
    '// Runtime configuration for the billing worker.',
    "import { createClient } from './client';",
    '',
    'export const settings = {',
    ...rows,
    "  endpoint: 'https://api.openai.com/v1',",
    '};',
    '',
    'export const client = createClient(settings);',
    '',
  ].join('\n');
}

const ARTIFACT = join('app', 'config.ts');

describe('HMA-01.AC1 / HMA-01.AC3: hardcoded secrets are locatable and countable', () => {
  /** Write the fixture into a fresh tree and run the real semantic pipeline. */
  async function scanWith(count: number) {
    const dir = await mkdtemp(join(tmpdir(), 'hma-01-cred-tree-'));
    await mkdir(join(dir, 'app'), { recursive: true });
    await writeFile(join(dir, ARTIFACT), sourceWithSecrets(count), 'utf-8');
    const result = await runNanoMindScan(dir, []);
    return { dir, result };
  }

  it('HMA-01.AC1 the CRITICAL hardcoded-secret finding carries a line and a runnable Verify', async () => {
    const { dir, result } = await scanWith(1);
    try {
      const cred = result.mergedFindings.filter(
        (f) => !f.passed && f.checkId === 'AST-CRED-003',
      );
      expect(
        cred.length,
        'AST-CRED-003 must fire on the planted key, or nothing below measures anything',
      ).toBeGreaterThan(0);

      for (const f of cred) {
        expect(
          f.line,
          `AST-CRED-003 reported no line on ${f.file}, so the renderer prints no ":N" and no Verify`,
        ).toBeGreaterThanOrEqual(1);
        // The renderer's own two conditions, evaluated here: `f.line` gates the
        // `<file>:<line>` line and `generateVerifyCommand` gates the `Verify:`
        // line (src/cli.ts, both finding-render sites).
        expect(generateVerifyCommand(f, dir)).toMatch(/^sed -n '\d+p' /);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('HMA-01.AC1 no CRITICAL is less locatable than a HIGH rendered beside it', async () => {
    const { dir, result } = await scanWith(1);
    try {
      const onArtifact = result.mergedFindings.filter(
        (f) => !f.passed && f.file === ARTIFACT,
      );
      const criticals = onArtifact.filter((f) => f.severity === 'critical');

      // Two non-vacuity floors. Without a CRITICAL the assertion below is free,
      // and without a located finding of any severity the artifact simply has
      // no citations to be less specific than.
      expect(
        criticals.length,
        'no CRITICAL on the artifact — the fixture stopped reaching the credential checks',
      ).toBeGreaterThan(0);
      expect(
        onArtifact.filter((f) => Number.isInteger(f.line)).length,
        `nothing on ${ARTIFACT} carried a line — there is no citation to compare against`,
      ).toBeGreaterThan(0);

      // The property #368 is about, stated without assuming which severity the
      // sibling finding lands on: whatever else the report locates on this file,
      // the CRITICAL is located too. A CRITICAL a reader cannot open, printed
      // above a finding they can, inverts the severity signal.
      expect(
        criticals.filter((f) => !Number.isInteger(f.line)).map((f) => f.checkId),
        'a CRITICAL with no line renders vaguer than the findings beside it',
      ).toEqual([]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('HMA-01.AC3 four secrets in one file are four countable findings, at four lines', async () => {
    const { dir, result } = await scanWith(4);
    try {
      const cred = result.mergedFindings.filter(
        (f) => !f.passed && f.checkId === 'AST-CRED-003' && f.file === ARTIFACT,
      );
      expect(
        cred.length,
        `four keys must be countable in the output, one per instance. Got ${cred.length}`,
      ).toBe(4);

      const lines = cred.map((f) => f.line);
      expect(new Set(lines).size, `four instances must carry four distinct lines: ${lines.join(', ')}`)
        .toBe(4);

      // The alternative the criterion allows — one finding carrying a count —
      // must never be reported as null when instances were measured.
      for (const f of cred) {
        const details = (f as { details?: { instanceCount?: unknown } }).details;
        expect(details?.instanceCount ?? null, 'instanceCount must not be null').not.toBeNull();
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('HMA-01.AC3 removing three of the four secrets moves the score up', async () => {
    const four = await scanWith(4);
    const one = await scanWith(1);
    try {
      const credCount = (r: Awaited<ReturnType<typeof scanWith>>['result']) =>
        r.mergedFindings.filter((f) => !f.passed && f.checkId === 'AST-CRED-003').length;

      // Non-vacuity floor: the score comparison below is only meaningful while
      // the two trees genuinely differ in how many credentials were found.
      expect(credCount(four.result)).toBe(4);
      expect(credCount(one.result)).toBe(1);

      const scoreFour = calculateSecurityScore(four.result.mergedFindings).score;
      const scoreOne = calculateSecurityScore(one.result.mergedFindings).score;

      expect(
        scoreOne,
        `removing three of four secrets must move the score. four=${scoreFour} one=${scoreOne}`,
      ).toBeGreaterThan(scoreFour);
    } finally {
      await rm(four.dir, { recursive: true, force: true });
      await rm(one.dir, { recursive: true, force: true });
    }
  });

  it('HMA-01.AC3 a file holding one secret still produces exactly one finding', async () => {
    // The rollup this widens exists for a real reason. A "fix" that simply
    // stopped grouping would pass the two assertions above and flood every
    // report that fires a check repeatedly inside one artifact.
    const { dir, result } = await scanWith(1);
    try {
      const cred = result.mergedFindings.filter(
        (f) => !f.passed && f.checkId === 'AST-CRED-003' && f.file === ARTIFACT,
      );
      expect(cred).toHaveLength(1);
      expect(cred[0].severity).toBe('critical');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
