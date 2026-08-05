/**
 * The post-fix verify scan must never run Layer 3.
 *
 * Layer 3 sends file CONTENT to the Anthropic API. It excludes the run's own
 * archive via `isOwnBackupDir`, which returns `false` whenever there is no
 * `backupContext` (`scanner.ts:3699`) — and the verify scan is a deliberately
 * context-free `new HardeningScanner()`, because being context-free is the whole
 * point: it has to see the tree the way the user's next scan will.
 *
 * So threading `deep` into it walked Layer 3 into the archive that run had just
 * written, and transmitted the only remaining PLAINTEXT copies of the credentials
 * the same run had just redacted out of the live files. Measured when it was
 * briefly threaded: 2 LLM payloads before, 4 after, the two extra ones carrying
 * the token bytes.
 *
 * The scan a `--fix` performs must not send the secret it just removed to a third
 * party. That is worth an incomplete announced number (#386), and the cap is not
 * an optimisation that a later change may trade away for accuracy.
 *
 * Guards the property behaviourally — by counting what would go on the wire —
 * rather than by asserting the shape of the options object, so a refactor that
 * reaches Layer 3 by some other route is still caught.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

/** Every batch of files handed to the LLM, across every scan in the process. */
const transmitted: string[][] = [];

vi.mock('../../src/semantic', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/semantic')>();
  class SpyLLMAnalyzer {
    constructor(_opts: unknown) {}
    async analyze(files: { path?: string; filePath?: string }[]) {
      transmitted.push((files ?? []).map((f) => f.path ?? f.filePath ?? String(f)));
      return { findings: [], cost: 0, cachedResults: 0 };
    }
  }
  return { ...actual, LLMAnalyzer: SpyLLMAnalyzer };
});

const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;

describe('the --fix verify scan never transmits the archive to the LLM', () => {
  let prevKey: string | undefined;
  beforeEach(() => {
    transmitted.length = 0;
    prevKey = process.env.ANTHROPIC_API_KEY;
    // Layer 3 is gated on this being set. The analyzer is mocked, so no request
    // leaves the machine — the value is never used as a credential.
    process.env.ANTHROPIC_API_KEY = 'sk-ant-test-not-a-real-key';
  });
  afterEach(() => {
    if (prevKey === undefined) delete process.env.ANTHROPIC_API_KEY;
    else process.env.ANTHROPIC_API_KEY = prevKey;
  });

  it('runs Layer 3 once, over the live tree only, on a --fix --deep run', async () => {
    const { HardeningScanner } = await import('../../src/hardening/scanner');
    const dir = await mkdtemp(path.join(tmpdir(), 'hma-deep-archive-'));
    try {
      await mkdir(path.join(dir, '.claude'), { recursive: true });
      await writeFile(path.join(dir, 'package.json'), '{"name":"f","version":"1.0.0"}\n');
      await writeFile(
        path.join(dir, '.claude', 'settings.json'),
        JSON.stringify({ githubToken: FAKE_GH_TOKEN }) + '\n',
      );
      await writeFile(path.join(dir, 'config.json'), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');

      await new HardeningScanner().scan({ targetDir: dir, autoFix: true, deep: true });

      // ── Non-vacuity: Layer 3 must have run at all ──
      // Without this, "nothing was transmitted" is trivially true whenever the
      // gate, the mock or the fixture stops working, and the test would keep
      // passing while measuring nothing.
      expect(
        transmitted.length,
        'Layer 3 never ran, so this test proves nothing about what it transmits',
      ).toBeGreaterThan(0);
      expect(
        transmitted.flat().length,
        'Layer 3 ran but was handed no files; the fixture is not reaching the analyzer',
      ).toBeGreaterThan(0);

      // ── The property ──
      // Exactly one pass: the main scan's. A second is the verify scan having
      // reached Layer 3, which is the defect.
      expect(
        transmitted.length,
        `Layer 3 ran ${transmitted.length} times on one --fix --deep. The second pass is the `
        + `context-free verify scan, whose archive exclusion does not hold`,
      ).toBe(1);

      // And nothing from inside the archive was ever handed over, by any pass.
      const archived = transmitted.flat().filter((p) => p.includes('.hackmyagent-backup'));
      expect(
        archived,
        'the pre-fix plaintext copies of the redacted credentials were sent to the LLM',
      ).toEqual([]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
