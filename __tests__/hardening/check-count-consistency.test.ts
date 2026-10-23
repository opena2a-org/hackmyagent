import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'fs';
import { join } from 'path';
import { getCheckCounts, getNotCountedCheckIds, getTaxonomyMap, isDeclaredExcludedCheckId } from '../../src/hardening/taxonomy';
import { CHECK_METHOD_PREFIXES } from '../../src/hardening/coverage-ledger';

/**
 * Guards the single source of truth for HMA's check/category counts.
 *
 * Regression context: `secure` scan output hardcoded `HMA_STATIC_CHECK_COUNT = 209`
 * (and README/docs said 209/44 and 187/39) while `--help` and `check-metadata`
 * derived 323/74 from the taxonomy — a self-contradiction a user running the CLI
 * could see. getCheckCounts() is now the one source every surface reads.
 *
 * The source-scan test below FAILS on the pre-fix code (which contained the
 * hardcoded literal), which is what gives this suite teeth.
 */
describe('check-count single source of truth', () => {
  const counts = getCheckCounts();

  // #970: the map minus the keys no command can report, which are declared
  // with their reason rather than counted.
  it('total equals the taxonomy map size less the declared not-counted keys', () => {
    const notCounted = getNotCountedCheckIds().flatMap(e => e.ids);
    expect(notCounted.length).toBeGreaterThan(0);
    expect(counts.total).toBe(Object.keys(getTaxonomyMap()).length - notCounted.length);
  });

  it('static + semantic partition the total exactly', () => {
    expect(counts.static + counts.semantic).toBe(counts.total);
  });

  it('static categories are a subset of total categories', () => {
    expect(counts.staticCategories).toBeLessThanOrEqual(counts.totalCategories);
    expect(counts.staticCategories).toBeGreaterThan(0);
  });

  // Golden values. Update these together with README.md and docs/SECURITY_CHECKS.md
  // whenever the taxonomy changes — this test fails on drift by design, forcing
  // the public-facing numbers to be updated in the same change.
  it('matches the published golden counts (update docs when this changes)', () => {
    // Raised from 324/311/13/75/70: the 24 semantic (AST) and 6 SOUL
    // narrative ids the scanner emitted without inventory entries are
    // TAXONOMY_MAP keys now, as are the 8 SEM-MCP structural checks
    // (354/37/87 → 362/45/88), which are emitted as `id:` rather than
    // `checkId:` and so were missed by a literal-only census.
    //
    // 363 → 365, and one new category: TEXT-001 and TEXT-002, the two rules
    // `scan-text` emits over a free text. They are static, they are the whole
    // of the new `text` category, and they are inventory keys rather than
    // declared exclusions because they are stable rules — which is what makes
    // `check-metadata` list them and `explain <id>` answer for them.
    //
    // 365/320/89/74 → 362/317/86/71 (#395): CODEINJ-001, TMPPATH-001 and
    // ENVLEAK-001 were counted with no caller, overlapped NEMO-005, -006 and
    // -007 (which do not match every form they did), and are deleted. Each
    // was the only id in its prefix, so the three `codeinj`, `tmppath` and
    // `envleak` categories go with them.
    //
    // 362/317/86/71 → 306/261/82/67 (#970): 56 counted ids could not be
    // reported by any command. PARSE-001..010, FAKETOOL-001..010,
    // PERSIST-004..010 and ASKILL-002 had no emitter, and the 28 HMA-NMC ids
    // are emitted only by NemoClawScanner, which no command constructs. They
    // stay taxonomy keys, declared in getNotCountedCheckIds(), and the reverse
    // census (counted-check-emitters.test.ts) holds every counted id to an
    // emitter a command reaches. The parse, faketool, askill and hma-nmc
    // categories held only those ids.
    expect(counts.total).toBe(306);
    expect(counts.static).toBe(261);
    expect(counts.semantic).toBe(45);
    expect(counts.totalCategories).toBe(82);
    expect(counts.staticCategories).toBe(67);
  });

  const staticFigures = (text: string): number[] =>
    [...text.matchAll(/\b(\d+) static (?:checks|declared)\b/g)].map(m => Number(m[1]));

  // A recording's text capture is what the published build its sidecar names
  // printed, and that build states its own count, which the tree can be ahead
  // of until the next release. Such a capture is not rewritten by hand: it
  // would then disagree with its frames. Each one is named here, and an entry
  // holds only while its sidecar records that published build at the version
  // in package.json (a release fails recording-sidecars.test.ts until it is
  // re-rendered) and while the capture states a count other than the derived
  // one. Once a re-render prints the derived count, drop the entry.
  // docs/vhs/secure-capture.txt left at the 0.34.0 cut: re-rendered from the
  // tarball packed at that checkout, it states the derived count.
  const RECORDED_FROM_PUBLISHED_BUILD: { capture: string; sidecar: string }[] = [];

  // #970: README and docs carried the static count in eight more places than
  // the two sentences pinned below, sample captures of the scan Observations
  // line among them, and each was a literal. Every "N static checks" and
  // "N static declared" in README.md and docs/ states the derived count.
  it('every static-check count in README.md and docs/ is the derived count', () => {
    const root = join(__dirname, '../..');
    const recorded = new Set(RECORDED_FROM_PUBLISHED_BUILD.map(e => e.capture));
    const files = ['README.md'];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(join(root, dir), { withFileTypes: true })) {
        const rel = `${dir}/${entry.name}`;
        if (entry.isDirectory()) walk(rel);
        else if (/\.(md|txt)$/.test(entry.name) && !recorded.has(rel)) files.push(rel);
      }
    };
    walk('docs');
    const stated: string[] = [];
    for (const file of files) {
      for (const n of staticFigures(readFileSync(join(root, file), 'utf8'))) {
        stated.push(`${file}: ${n}`);
      }
    }
    // README (3), SECURITY_CHECKS, quick-start-capture, USE-CASES,
    // scan-my-agent (3), openclaw-security (2), red-team-mcp.
    expect(stated.length).toBeGreaterThanOrEqual(12);
    expect(stated.filter(s => !s.endsWith(`: ${counts.static}`))).toEqual([]);
  });

  it('a capture left out of that census records the published build at the version in package.json', () => {
    const root = join(__dirname, '../..');
    const read = (rel: string): string => readFileSync(join(root, rel), 'utf8');
    const version = (JSON.parse(read('package.json')) as { version: string }).version;
    for (const entry of RECORDED_FROM_PUBLISHED_BUILD) {
      const sidecar = JSON.parse(read(entry.sidecar)) as {
        version: string; npmIntegrity?: string; outputs: { capture: string };
      };
      expect(sidecar.outputs.capture).toBe(entry.capture);
      expect(sidecar.version, `${entry.sidecar} records another version: re-render it`).toBe(version);
      expect(sidecar.npmIntegrity, `${entry.sidecar} records no published build`).toMatch(/^sha512-/);
      const figures = staticFigures(read(entry.capture));
      expect(figures.length).toBeGreaterThan(0);
      expect(figures.every(n => n === counts.static), `${entry.capture} states the derived count: drop its entry`).toBe(false);
    }
  });

  it('the --help and MCP tool descriptions read the derived counts', () => {
    const root = join(__dirname, '../..');
    const cliSource = readFileSync(join(root, 'src/cli.ts'), 'utf8');
    const mcpSource = readFileSync(join(root, 'src/mcp-server.ts'), 'utf8');
    expect(cliSource).toMatch(/const CHECK_COUNTS = getCheckCounts\(\);/);
    expect(mcpSource).toMatch(/const MCP_CHECK_COUNTS = getCheckCounts\(\);/);
    expect(mcpSource).toMatch(/Runs \$\{MCP_CHECK_COUNTS\.total\} security checks across \$\{MCP_CHECK_COUNTS\.totalCategories\} categories/);
    for (const source of [cliSource, mcpSource]) {
      expect(source).not.toMatch(/\b\d{3} (?:static |security )?checks across \d+ categories/);
    }
  });

  // #482: the golden values above are pinned to the taxonomy, but the README
  // and docs/SECURITY_CHECKS.md were only asked to follow them, and the README
  // explained its semantic figure against the scan `Checks` line but not
  // against `check-metadata`. Two numbers, two sources: the README's 29 is the
  // distinct check ids the seven analyzers emit (the published definition),
  // `check-metadata`'s semanticChecks is every AST-/SEM- taxonomy id. Hold each
  // published sentence to the source it names.
  // When the README was cut to its reading-load limits, these sentences moved
  // to docs/SECURITY_CHECKS.md (What the counts mean); the README keeps one
  // count per category, and its semantic count is held to the same source.
  it('README and docs/SECURITY_CHECKS.md state the counts their sources produce', () => {
    const root = join(__dirname, '../..');
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    const checksDoc = readFileSync(join(root, 'docs/SECURITY_CHECKS.md'), 'utf8');
    const figures = (text: string, pattern: RegExp): number[] => {
      const m = pattern.exec(text);
      expect(m, `expected ${pattern} to match`).not.toBeNull();
      return m!.slice(1).map(Number);
    };

    const analyzerDir = join(root, 'src/nanomind-core/analyzers');
    const emitted = new Set<string>();
    for (const file of readdirSync(analyzerDir).filter(f => f.endsWith('-analyzer.ts'))) {
      for (const m of readFileSync(join(analyzerDir, file), 'utf8').matchAll(/checkId:\s*['"`]([A-Z][A-Z0-9-]*-\d+)['"`]/g)) {
        emitted.add(m[1]);
      }
    }
    const ids = Object.keys(getTaxonomyMap());
    const sem = ids.filter(id => id.startsWith('SEM-'));
    const sharedWithStatic = [...emitted].filter(id => !id.startsWith('AST-'));

    expect(figures(checksDoc, /\*\*(\d+) static checks across (\d+) categories\*\* \((\d+) checks across (\d+) categories including the NanoMind semantic layer\)/))
      .toEqual([counts.static, counts.staticCategories, counts.total, counts.totalCategories]);
    expect(figures(checksDoc, /\*\*(\d+) NanoMind semantic checks\.\*\*/)).toEqual([emitted.size]);
    expect(figures(checksDoc, /\(This (\d+) is the fixed catalog of check ids the seven analyzers emit\./)).toEqual([emitted.size]);
    expect(figures(checksDoc, /reports `semanticChecks: (\d+)`/)).toEqual([counts.semantic]);
    expect(figures(checksDoc, /the structural layer's (\d+) `SEM-` checks/)).toEqual([sem.length]);
    expect(figures(checksDoc, /leaves out the (\d+) `UNICODE-STEGO` ids/)).toEqual([sharedWithStatic.length]);
    expect(figures(readme, /: (\d+) semantic checks over /)).toEqual([emitted.size]);
    expect(sharedWithStatic.every(id => id.startsWith('UNICODE-STEGO-') && ids.includes(id))).toBe(true);
    expect(emitted.size - sharedWithStatic.length + sem.length).toBe(counts.semantic);

    expect(figures(checksDoc, /performs (\d+) security checks across (\d+) categories \((\d+) static checks/))
      .toEqual([counts.total, counts.totalCategories, counts.static]);
  });

  // #980: the OpenClaw guide and its USE-CASES.md row said 34 and
  // docs/SECURITY_CHECKS.md said 47, and no code defined either set. The set
  // is the check ids the scanner's `checkOpenclaw*` methods emit (the methods
  // the coverage ledger registers), read from their bodies and the helpers
  // they call; every one is an inventory key in a family those methods own.
  it('every OpenClaw count and table in the docs matches the ids the OpenClaw checks emit', () => {
    const root = join(__dirname, '../..');
    const scannerSource = readFileSync(join(root, 'src/hardening/scanner.ts'), 'utf8');
    // Imported helpers that emit findings for these methods, keyed by the call.
    const importedEmitters: Record<string, string> = {
      'validateCapabilities(': 'src/hardening/skill-capability-validator.ts',
    };
    const literalIds = (text: string): string[] =>
      [...text.matchAll(/checkId:\s*['"`]([A-Z][A-Z0-9-]*)['"`]/g)].map(m => m[1]);
    const methodBody = (name: string): string => {
      const start = scannerSource.search(new RegExp(`\\n  (?:private |public |protected )?(?:async )?${name}\\(`));
      expect(start, `scanner.ts defines ${name}`).toBeGreaterThan(-1);
      const end = scannerSource.indexOf('\n  }\n', start + 1);
      expect(end, `${name} has a closing brace`).toBeGreaterThan(start);
      return scannerSource.slice(start, end);
    };

    const methods = Object.keys(CHECK_METHOD_PREFIXES).filter(m => m.startsWith('checkOpenclaw'));
    expect(methods.length).toBeGreaterThan(0);
    const emitted = new Set<string>();
    const visited = new Set<string>();
    const pending = [...methods];
    while (pending.length > 0) {
      const name = pending.pop()!;
      if (visited.has(name)) continue;
      visited.add(name);
      const body = methodBody(name);
      literalIds(body).forEach(id => emitted.add(id));
      for (const m of body.matchAll(/this\.(\w+)\(/g)) {
        if (new RegExp(`\\n  (?:private |public |protected )?(?:async )?${m[1]}\\(`).test(scannerSource)) pending.push(m[1]);
      }
      for (const [call, file] of Object.entries(importedEmitters)) {
        if (body.includes(call)) literalIds(readFileSync(join(root, file), 'utf8')).forEach(id => emitted.add(id));
      }
    }

    const taxonomyIds = Object.keys(getTaxonomyMap());
    const checks = [...emitted].filter(id => taxonomyIds.includes(id)).sort();
    // What is left out is a status record (a read failure, a fix summary),
    // each declared excluded from the inventory, never an undeclared check.
    expect([...emitted].filter(id => !taxonomyIds.includes(id)).every(isDeclaredExcludedCheckId)).toBe(true);
    const families = new Set(methods.flatMap(m => CHECK_METHOD_PREFIXES[m]));
    const familyIds = taxonomyIds
      .filter(id => families.has(id.replace(/-\d+$/, '')) && /-\d+$/.test(id))
      .sort();
    expect(checks).toEqual(familyIds);

    const figure = (text: string, pattern: RegExp): number => {
      const m = pattern.exec(text);
      expect(m, `expected ${pattern} to match`).not.toBeNull();
      return Number(m![1]);
    };
    const checksDoc = readFileSync(join(root, 'docs/SECURITY_CHECKS.md'), 'utf8');
    const useCases = readFileSync(join(root, 'docs/USE-CASES.md'), 'utf8');
    const guide = readFileSync(join(root, 'docs/use-cases/openclaw-security.md'), 'utf8');
    expect(figure(checksDoc, /HackMyAgent includes (\d+) specialized security checks targeting OpenClaw/)).toBe(checks.length);
    expect(figure(useCases, /Run (\d+) OpenClaw-specific checks/)).toBe(checks.length);
    expect(figure(guide, /HMA includes (\d+) checks specifically for \[OpenClaw\]/)).toBe(checks.length);
    expect(figure(guide, /All (\d+) OpenClaw checks run automatically/)).toBe(checks.length);

    // The section's tables list exactly that set, so the number and the rows
    // under it cannot disagree either.
    const section = checksDoc.slice(
      checksDoc.indexOf('## OpenClaw Security Checks'),
      checksDoc.indexOf('### Auto-Fix Capabilities'),
    );
    const rows = [...section.matchAll(/^\| ([A-Z]+-\d+) \|/gm)].map(m => m[1]);
    expect(new Set(rows).size).toBe(rows.length);
    expect([...rows].sort()).toEqual(checks);
  });

  it('the scan display no longer hardcodes a static-check count (teeth)', () => {
    const cliSource = readFileSync(join(__dirname, '../../src/cli.ts'), 'utf8');
    // The pre-fix bug: `const HMA_STATIC_CHECK_COUNT = 209;`. Any hardcoded
    // static-count literal reintroduces the drift this suite exists to prevent.
    expect(cliSource).not.toMatch(/HMA_STATIC_CHECK_COUNT\s*=\s*\d+/);
    // And the display must derive from the single source.
    expect(cliSource).toMatch(/getCheckCounts\(\)\.static/);
  });
});
