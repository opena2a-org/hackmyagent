/**
 * The post-fix verify scan runs at the depth of the run it verifies, `deep`
 * included, and never transmits the archive to the LLM.
 *
 * Layer 3 sends file CONTENT to the Anthropic API. While `--fix` wrote its
 * archive into the scanned tree, the verify scan — a deliberately context-free
 * `new HardeningScanner()`, which has no backup context and so no archive
 * exclusion — walked Layer 3 into it and transmitted the only remaining
 * PLAINTEXT copies of the credentials the same run had just redacted. Measured
 * when it was briefly threaded: 2 LLM payloads before, 4 after, the two extra
 * ones carrying the token bytes. So the verify scan was capped at `standard`,
 * and `secure --fix --deep` confirmed its fixes with checks the user's next
 * `--deep` scan does not stop at (#386).
 *
 * The archive is in the backup store outside the tree now (#376), so the cap
 * is gone. These tests hold both halves of that bargain:
 *
 *   - the verify scan DOES reach Layer 3 on a `--fix --deep` run, so it sees
 *     what the next `--deep` scan sees, and the announced score equals that
 *     scan's;
 *   - no pass hands the analyzer a file of the archive, or any content that
 *     carries the plaintext the fix moved into it.
 *
 * Guards the property behaviourally — by counting what would go on the wire —
 * rather than by asserting the shape of the options object, so a refactor that
 * reaches Layer 3 by some other route is still caught.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { latestStoreRun } from '../helpers/backup-store';
import { tempDir } from '../helpers/temp-dir';

interface SentFile { path: string; content: string }

/** Every batch of files handed to the LLM, across every scan in the process. */
const transmitted: SentFile[][] = [];

/**
 * When set, the spy answers one high finding per file it is handed, so Layer 3
 * contributes to the score and the score comparison below measures something.
 */
let reportEveryFile = false;

vi.mock('../../src/semantic', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/semantic')>();
  class SpyLLMAnalyzer {
    constructor(_opts: unknown) {}
    // Reads `path` and `content` and NOTHING ELSE. An earlier version fell back
    // through `?? f.filePath ?? String(f)`, which is a vacuity sink: rename
    // `AnalysisFile.path` and every entry silently becomes "[object Object]",
    // the archive filter matches nothing, and this security test goes green
    // while measuring nothing. Throwing here instead means the shape changing
    // is a loud failure.
    async analyze(files: { path: string; content: string }[]) {
      const batch = (files ?? []).map((f) => {
        if (typeof f?.path !== 'string' || typeof f?.content !== 'string') {
          throw new Error(
            `AnalysisFile.path or .content is not a string (got ${typeof f?.path}, ${typeof f?.content}). `
            + 'The spy can no longer see what is transmitted, so this test cannot prove the archive is excluded.',
          );
        }
        return { path: f.path, content: f.content };
      });
      transmitted.push(batch);
      const findings = reportEveryFile
        ? batch.map((f, i) => ({
          id: `SEM-LLM-${String(i + 1).padStart(3, '0')}`,
          title: 'Layer 3 test finding',
          description: 'Reported by the test analyzer for every file it is handed.',
          rationale: 'test',
          category: 'credential' as const,
          severity: 'high' as const,
          file: f.path,
          line: 1,
          recommendation: 'test',
          layer: 3 as const,
          autoFixable: false,
        }))
        : [];
      return { findings, cost: 0, cachedResults: 0, unanalyzed: [], withheld: [] };
    }
  }
  return { ...actual, LLMAnalyzer: SpyLLMAnalyzer };
});

const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;

/** A tree with a credential in a file Layer 3 sends and one it withholds. */
async function writeFixture(dir: string): Promise<void> {
  await mkdir(path.join(dir, '.claude'), { recursive: true });
  await writeFile(path.join(dir, 'package.json'), '{"name":"f","version":"1.0.0"}\n');
  await writeFile(
    path.join(dir, '.claude', 'settings.json'),
    JSON.stringify({ githubToken: FAKE_GH_TOKEN }) + '\n',
  );
  await writeFile(path.join(dir, 'config.json'), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');
}

function isWithin(child: string, parent: string): boolean {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

describe('the --fix verify scan runs at deep and never transmits the archive to the LLM', () => {
  let prevKey: string | undefined;
  beforeEach(() => {
    transmitted.length = 0;
    reportEveryFile = false;
    prevKey = process.env.ANTHROPIC_API_KEY;
    // Layer 3 is gated on this being set. The analyzer is mocked, so no request
    // leaves the machine — the value is never used as a credential.
    process.env.ANTHROPIC_API_KEY = ['sk', '-ant-test-not-a-real-key'].join('');
  });
  afterEach(() => {
    if (prevKey === undefined) delete process.env.ANTHROPIC_API_KEY;
    else process.env.ANTHROPIC_API_KEY = prevKey;
  });

  it('runs Layer 3 in the verify scan too, over the live tree only, on a --fix --deep run', async () => {
    const { HardeningScanner } = await import('../../src/hardening/scanner');
    const dir = await mkdtemp(path.join(tmpdir(), 'hma-deep-archive-'));
    try {
      await writeFixture(dir);

      const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true, deep: true });

      // ── Non-vacuity: there is an archive, and it holds the plaintext ──
      expect(result.findings.some((f) => f.fixed), 'the run fixed nothing, so nothing was verified').toBe(true);
      expect(result.backupPath, 'the run made no backup, so there is no archive to leak').toBeDefined();
      const archive = await realpath(await latestStoreRun(dir));
      expect(
        await readFile(path.join(archive, '.claude', 'settings.json'), 'utf-8'),
        'the archive holds no plaintext copy of the credential the fix redacted',
      ).toContain(FAKE_GH_TOKEN);
      expect(
        isWithin(archive, await realpath(dir)),
        `the archive ${archive} sits inside the scanned tree`,
      ).toBe(false);

      // ── Non-vacuity: Layer 3 ran at all ──
      expect(transmitted.flat().length, 'Layer 3 was handed no files; the fixture is not reaching the analyzer')
        .toBeGreaterThan(0);

      // ── The verify scan ran at the run's depth ──
      // One pass for the run itself and one for the verify scan. A single pass
      // is the verify scan capped below `deep` again.
      expect(
        transmitted.length,
        `Layer 3 ran ${transmitted.length} time(s) on one --fix --deep; the verify scan did not run it`,
      ).toBe(2);
      expect(
        transmitted[1].map((f) => f.path).sort(),
        'the verify scan sent different files than the run it verifies',
      ).toEqual(transmitted[0].map((f) => f.path).sort());

      // ── Nothing of the archive, by any pass ──
      for (const f of transmitted.flat()) {
        expect(path.isAbsolute(f.path), `${f.path} is not a path inside the scanned tree`).toBe(false);
        expect(f.path.split(/[\\/]/), `${f.path} lies in a backup directory`).not.toContain('.hackmyagent-backup');
        expect(
          isWithin(path.resolve(dir, f.path), dir),
          `${f.path} resolves outside the scanned tree`,
        ).toBe(true);
        expect(f.content, `${f.path} was sent carrying the plaintext the fix moved into the archive`)
          .not.toContain(FAKE_GH_TOKEN);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('announces the score the next --deep scan reports', async () => {
    const { HardeningScanner } = await import('../../src/hardening/scanner');
    const dir = tempDir('hma-deep-score-');
    await writeFixture(dir);
    reportEveryFile = true;

    const fixed = await new HardeningScanner().scan({ targetDir: dir, autoFix: true, deep: true });
    const passesInFixRun = transmitted.length;
    const next = await new HardeningScanner().scan({ targetDir: dir, autoFix: false, deep: true });

    // ── Non-vacuity ──
    expect(fixed.findings.some((f) => f.fixed), 'the run fixed nothing; nothing is being measured').toBe(true);
    expect(passesInFixRun, 'the verify scan of the --fix run did not reach Layer 3').toBe(2);
    expect(transmitted.length, 'the next --deep scan did not reach Layer 3').toBe(3);
    expect(
      next.findings.some((f) => f.checkId.startsWith('SEM-LLM-') && !f.passed),
      'Layer 3 contributed no finding to the next --deep scan, so the score comparison measures nothing',
    ).toBe(true);
    expect(fixed.rawScore, 'rawScore is unset, so the comparison would be undefined to undefined').toBeDefined();
    expect(next.rawScore).toBeDefined();

    // ── The property, on the unclamped number ──
    expect(
      fixed.rawScore,
      `--fix --deep announced rawScore ${fixed.rawScore} and the next --deep scan said ${next.rawScore}`,
    ).toBe(next.rawScore);
    expect(fixed.score, 'the displayed scores disagree as well').toBe(next.score);

    // And the archive stayed off the wire in all three passes.
    for (const f of transmitted.flat()) {
      expect(f.path.split(/[\\/]/)).not.toContain('.hackmyagent-backup');
      expect(f.content).not.toContain(FAKE_GH_TOKEN);
    }
  });
});
